#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import abc
import collections
import functools
import itertools
import re
import uuid
import wsgiref.util

import flask
from flask import blueprints
import flask_restful
import flask_restful.utils
from oslo_log import log
from oslo_serialization import jsonutils
from pycadf import cadftaxonomy as taxonomy
from pycadf import host
from pycadf import resource
import six
from six.moves import http_client

from keystone.common import authorization
from keystone.common import context
from keystone.common import driver_hints
from keystone.common import json_home
from keystone.common.rbac_enforcer import enforcer
from keystone.common import utils
import keystone.conf
from keystone import exception


# NOTE(morgan): Capture the relevant part of the flask url route rule for
# substitution. In flask arguments (e.g. url elements to be passed to the
# "resource" method, e.g. user_id, are specified like `<string:user_id>`
# we use this regex to replace the <> with {} for JSON Home purposes and
# remove the argument type. Use of this is done like
# _URL_SUBST.sub('{\\1}', entity_path), which replaces the whole match
# match rule bit with the capture group (this is a greedy sub).
_URL_SUBST = re.compile(r'<[^\s:]+:([^>]+)>')
CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
ResourceMap = collections.namedtuple(
    'resource_map', 'resource, url, alternate_urls, kwargs, json_home_data')
JsonHomeData = collections.namedtuple(
    'json_home_data', 'rel, status, path_vars')

_v3_resource_relation = json_home.build_v3_resource_relation


def construct_resource_map(resource, url, resource_kwargs, alternate_urls=None,
                           rel=None, status=json_home.Status.STABLE,
                           path_vars=None,
                           resource_relation_func=_v3_resource_relation):
    """Construct the ResourceMap Named Tuple.

    :param resource: The flask-RESTful resource class implementing the methods
                     for the API.
    :type resource: :class:`ResourceMap`
    :param url: Flask-standard url route, all flask url routing rules apply.
                url variables will be passed to the Resource methods as
                arguments.
    :type url: str
    :param resource_kwargs: a dict of optional value(s) that can further modify
                            the handling of the routing.

                            * endpoint: endpoint name (defaults to
                                        :meth:`Resource.__name__.lower`
                                        Can be used to reference this route in
                                        :class:`fields.Url` fields (str)

                            * resource_class_args: args to be forwarded to the
                                                   constructor of the resource.
                                                   (tuple)

                            * resource_class_kwargs: kwargs to be forwarded to
                                                     the constructor of the
                                                     resource. (dict)

                            Additional keyword arguments not specified above
                            will be passed as-is to
                            :meth:`flask.Flask.add_url_rule`.
    :param alternate_urls: An iterable (list) of urls that also map to the
                           resource. These are used to ensure API compat when
                           a "new" path is more correct for the API but old
                           paths must continue to work. Example:
                           `/auth/domains` being the new path for
                           `/OS-FEDERATION/domains`. The `OS-FEDERATION` part
                           would be listed as an alternate url. These are not
                           added to the JSON Home Document.
    :type: any iterable or None
    :param rel:
    :type rel: str or None
    :param status: JSON Home API Status, e.g. "STABLE"
    :type status: str
    :param path_vars: JSON Home Path Var Data (arguments)
    :type path_vars: dict or None
    :param resource_relation_func: function to build expected resource rel data
    :type resource_relation_func: callable
    :return:
    """
    if rel is not None:
        jh_data = construct_json_home_data(
            rel=rel, status=status, path_vars=path_vars,
            resource_relation_func=resource_relation_func)
    else:
        jh_data = None
    if not url.startswith('/'):
        url = '/%s' % url
    return ResourceMap(
        resource=resource, url=url, alternate_urls=alternate_urls,
        kwargs=resource_kwargs, json_home_data=jh_data)


def construct_json_home_data(rel, status=json_home.Status.STABLE,
                             path_vars=None,
                             resource_relation_func=_v3_resource_relation):
    rel = resource_relation_func(resource_name=rel)
    return JsonHomeData(rel=rel, status=status, path_vars=(path_vars or {}))


def _initialize_rbac_enforcement_check():
    setattr(flask.g, enforcer._ENFORCEMENT_CHECK_ATTR, False)


def _assert_rbac_enforcement_called(resp):
    # assert is intended to be used to ensure code during development works
    # as expected, it is fine to be optimized out with `python -O`
    msg = ('PROGRAMMING ERROR: enforcement (`keystone.common.rbac_enforcer.'
           'enforcer.RBACKEnforcer.enforce_call()`) has not been called; API '
           'is unenforced.')
    g = flask.g
    assert getattr(g, enforcer._ENFORCEMENT_CHECK_ATTR, False), msg  # nosec
    return resp


def _remove_content_type_on_204(resp):
    # Remove content-type if the resp is 204.
    if resp.status_code == http_client.NO_CONTENT:
        resp.headers.pop('content-type', None)
    return resp


def build_audit_initiator():
    """A pyCADF initiator describing the current authenticated context."""
    pycadf_host = host.Host(address=flask.request.remote_addr,
                            agent=str(flask.request.user_agent))
    initiator = resource.Resource(typeURI=taxonomy.ACCOUNT_USER,
                                  host=pycadf_host)
    oslo_context = flask.request.environ.get(context.REQUEST_CONTEXT_ENV)
    if oslo_context.user_id:
        initiator.id = utils.resource_uuid(oslo_context.user_id)
        initiator.user_id = oslo_context.user_id

    if oslo_context.project_id:
        initiator.project_id = oslo_context.project_id

    if oslo_context.domain_id:
        initiator.domain_id = oslo_context.domain_id

    return initiator


@six.add_metaclass(abc.ABCMeta)
class APIBase(object):

    @property
    @abc.abstractmethod
    def _name(self):
        """Override with an attr consisting of the API Name, e.g 'users'."""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def _import_name(self):
        """Override with an attr consisting of the value of `__name__`."""
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def resource_mapping(self):
        """An attr containing of an iterable of :class:`ResourceMap`.

        Each :class:`ResourceMap` is a NamedTuple with the following elements:

            * resource: a :class:`flask_restful.Resource` class or subclass

            * url: a url route to match for the resource, standard flask
                   routing rules apply. Any url variables will be passed
                   to the resource method as args. (str)

            * alternate_urls: an iterable of url routes to match for the
                              resource, standard flask routing rules apply.
                              These rules are in addition (for API compat) to
                              the primary url. Any url variables will be
                              passed to the resource method as args. (iterable)

            * json_home_data: :class:`JsonHomeData` populated with relevant
                              info for populated JSON Home Documents or None.

            * kwargs: a dict of optional value(s) that can further modify the
                      handling of the routing.

                      * endpoint: endpoint name (defaults to
                                  :meth:`Resource.__name__.lower`
                                  Can be used to reference this route in
                                  :class:`fields.Url` fields (str)

                      * resource_class_args: args to be forwarded to the
                                             constructor of the resource.
                                             (tuple)

                      * resource_class_kwargs: kwargs to be forwarded to the
                                               constructor of the resource.
                                               (dict)

                      Additional keyword arguments not specified above will be
                      passed as-is to :meth:`flask.Flask.add_url_rule`.
        """
        raise NotImplementedError()

    @property
    def resources(self):
        return []

    @staticmethod
    def _build_bp_url_prefix(prefix):
        # NOTE(morgan): Keystone only has a V3 API, this is here for future
        # proofing and exceptional cases such as root discovery API object(s)
        parts = ['/v3']
        if prefix:
            parts.append(prefix.lstrip('/'))
        return '/'.join(parts).rstrip('/')

    @property
    def api(self):
        # The API may be directly accessed via this property
        return self.__api

    @property
    def blueprint(self):
        # The API Blueprint may be directly accessed via this property
        return self.__blueprint

    def __init__(self, blueprint_url_prefix='', api_url_prefix='',
                 default_mediatype='application/json', decorators=None,
                 errors=None):
        self.__before_request_functions_added = False
        self.__after_request_functions_added = False

        self._default_mediatype = default_mediatype
        blueprint_url_prefix = blueprint_url_prefix.rstrip('/')
        api_url_prefix = api_url_prefix.rstrip('/')

        if api_url_prefix and not api_url_prefix.startswith('/'):
            self._api_url_prefix = '/%s' % api_url_prefix
        else:
            # NOTE(morgan): If the api_url_prefix is empty fall back on the
            # class-level defined `_api_url_prefix` if it is set.
            self._api_url_prefix = (api_url_prefix or
                                    getattr(self, '_api_url_prefix', ''))

        if blueprint_url_prefix and not blueprint_url_prefix.startswith('/'):
            self._blueprint_url_prefix = self._build_bp_url_prefix(
                '/%s' % blueprint_url_prefix)
        else:
            self._blueprint_url_prefix = self._build_bp_url_prefix(
                blueprint_url_prefix)

        self.__blueprint = blueprints.Blueprint(
            name=self._name, import_name=self._import_name,
            url_prefix=self._blueprint_url_prefix)
        self.__api = flask_restful.Api(
            app=self.__blueprint, prefix=self._api_url_prefix,
            default_mediatype=self._default_mediatype,
            decorators=decorators, errors=errors)

        # NOTE(morgan): Make sure we're using oslo_serialization.jsonutils
        # instead of the default json serializer. Keystone has data types that
        # the default serializer cannot handle, representation is a decorator
        # but since we instantiate the API in-line we need to do some magic
        # and call it as a normal method.
        self.__api.representation('application/json')(self._output_json)

        self._add_resources()
        self._add_mapped_resources()

        # Apply Before and After request functions
        self._register_before_request_functions()
        self._register_after_request_functions()
        # Assert is intended to ensure code works as expected in development,
        # it is fine to optimize out with python -O
        msg = '%s_request functions not registered'
        assert self.__before_request_functions_added, msg % 'before'  # nosec
        assert self.__after_request_functions_added, msg % 'after'  # nosec

    def _add_resources(self):
        # Add resources that are standardized. Each resource implements a
        # base set of handling for a collection of entities such as
        # `users`. Resources are sourced from self.resources. Each resource
        # should have an attribute/property containing the `collection_key`
        # which is typically the "plural" form of the entity, e.g. `users` and
        # `member_key` which is typically the "singular" of the entity, e.g.
        # `user`. Resources are sourced from self.resources, each element is
        # simply a :class:`flask_restful.Resource`.
        for r in self.resources:
            c_key = getattr(r, 'collection_key', None)
            m_key = getattr(r, 'member_key', None)
            r_pfx = getattr(r, 'api_prefix', None)
            if not c_key or not m_key:
                LOG.debug('Unable to add resource %(resource)s to API '
                          '%(name)s, both `member_key` and `collection_key` '
                          'must be implemented. [collection_key(%(col_key)s) '
                          'member_key(%(m_key)s)]',
                          {'resource': r.__name__,
                           'name': self._name, 'col_key': c_key,
                           'm_key': m_key})
                continue
            if r_pfx != self._api_url_prefix:
                LOG.debug('Unable to add resource %(resource)s to API as the '
                          'API Prefixes do not match: %(apfx)r != %(rpfx)r',
                          {'resource': r.__name__,
                           'rpfx': r_pfx, 'apfx': self._api_url_prefix})
                continue

            # NOTE(morgan): The Prefix is automatically added by the API, so
            # we do not add it to the paths here.
            collection_path = '/%s' % c_key
            entity_path = '/%(collection)s/<string:%(member)s_id>' % {
                'collection': c_key, 'member': m_key}
            # NOTE(morgan): The json-home form of the entity path is different
            # from the flask-url routing form. Must also include the prefix
            jh_e_path = '%(pfx)s/%(e_path)s' % {
                'pfx': self._api_url_prefix,
                'e_path': _URL_SUBST.sub('{\\1}', entity_path).lstrip('/')}

            LOG.debug(
                'Adding standard routes to API %(name)s for `%(resource)s` '
                '(API Prefix: %(prefix)s) [%(collection_path)s, '
                '%(entity_path)s]', {
                    'name': self._name, 'resource': r.__class__.__name__,
                    'collection_path': collection_path,
                    'entity_path': entity_path,
                    'prefix': self._api_url_prefix})
            self.api.add_resource(r, collection_path, entity_path)

            # Add JSON Home data
            resource_rel_func = getattr(
                r, 'json_home_resource_rel_func',
                json_home.build_v3_resource_relation)
            resource_rel_status = getattr(
                r, 'json_home_resource_status', None)
            collection_rel = resource_rel_func(resource_name=c_key)
            # NOTE(morgan): Add the prefix explicitly for JSON Home documents
            # to the collection path.
            rel_data = {'href': '%(pfx)s%(collection_path)s' % {
                'pfx': self._api_url_prefix,
                'collection_path': collection_path}
            }

            entity_rel = resource_rel_func(resource_name=m_key)
            id_str = '%s_id' % m_key

            parameter_rel_func = getattr(
                r, 'json_home_parameter_rel_func',
                json_home.build_v3_parameter_relation)
            id_param_rel = parameter_rel_func(parameter_name=id_str)
            entity_rel_data = {'href-template': jh_e_path,
                               'href-vars': {id_str: id_param_rel}}

            if resource_rel_status is not None:
                json_home.Status.update_resource_data(
                    rel_data, resource_rel_status)
                json_home.Status.update_resource_data(
                    entity_rel_data, resource_rel_status)

            json_home.JsonHomeResources.append_resource(
                collection_rel, rel_data)
            json_home.JsonHomeResources.append_resource(
                entity_rel, entity_rel_data)

    def _add_mapped_resources(self):
        # Add resource mappings, non-standard resource connections
        for r in self.resource_mapping:
            LOG.debug(
                'Adding resource routes to API %(name)s: '
                '[%(url)r %(kwargs)r]',
                {'name': self._name, 'url': r.url, 'kwargs': r.kwargs})
            self.api.add_resource(r.resource, r.url, **r.kwargs)
            if r.alternate_urls is not None:
                LOG.debug(
                    'Adding additional resource routes (alternate) to API'
                    '%(name)s: [%(urls)r %(kwargs)r]',
                    {'name': self._name, 'urls': r.alternate_urls,
                     'kwargs': r.kwargs})
                self.api.add_resource(r.resource, *r.alternate_urls,
                                      **r.kwargs)

            # Build the JSON Home data and add it to the relevant JSON Home
            # Documents for explicit JSON Home data.
            if r.json_home_data:
                resource_data = {}
                # NOTE(morgan): JSON Home form of the URL is different
                # from FLASK, do the conversion here.
                conv_url = '%(pfx)s/%(url)s' % {
                    'url': _URL_SUBST.sub('{\\1}', r.url).lstrip('/'),
                    'pfx': self._api_url_prefix}

                if r.json_home_data.path_vars:
                    resource_data['href-template'] = conv_url
                    resource_data['href-vars'] = r.json_home_data.path_vars
                else:
                    resource_data['href'] = conv_url
                json_home.Status.update_resource_data(
                    resource_data, r.json_home_data.status)
                json_home.JsonHomeResources.append_resource(
                    r.json_home_data.rel,
                    resource_data)

    def _register_before_request_functions(self, functions=None):
        """Register functions to be executed in the `before request` phase.

        Override this method and pass in via "super" any additional functions
        that should be registered. It is assumed that any override will also
        accept a "functions" list and append the passed in values to it's
        list prior to calling super.

        Each function will be called with no arguments and expects a NoneType
        return. If the function returns a value, that value will be returned
        as the response to the entire request, no further processing will
        happen.

        :param functions: list of functions that will be run in the
                          `before_request` phase.
        :type functions: list
        """
        functions = functions or []
        # Assert is intended to ensure code works as expected in development,
        # it is fine to optimize out with python -O
        msg = 'before_request functions already registered'
        assert not self.__before_request_functions_added, msg  # nosec
        # register global before request functions
        # e.g. self.__blueprint.before_request(function)
        self.__blueprint.before_request(_initialize_rbac_enforcement_check)

        # Add passed-in functions
        for f in functions:
            self.__blueprint.before_request(f)
        self.__before_request_functions_added = True

    def _register_after_request_functions(self, functions=None):
        """Register functions to be executed in the `after request` phase.

        Override this method and pass in via "super" any additional functions
        that should be registered. It is assumed that any override will also
        accept a "functions" list and append the passed in values to it's
        list prior to calling super.

        Each function will be called with a single argument of the Response
        class type. The function must return either the passed in Response or
        a new Response. NOTE: As of flask 0.7, these functions may not be
        executed in the case of an unhandled exception.

        :param functions: list of functions that will be run in the
                          `after_request` phase.
        :type functions: list
        """
        functions = functions or []
        # Assert is intended to ensure code works as expected in development,
        # it is fine to optimize out with python -O
        msg = 'after_request functions already registered'
        assert not self.__after_request_functions_added, msg  # nosec
        # register global after request functions
        # e.g. self.__blueprint.after_request(function)
        self.__blueprint.after_request(_assert_rbac_enforcement_called)
        self.__blueprint.after_request(_remove_content_type_on_204)

        # Add Passed-In Functions
        for f in functions:
            self.__blueprint.after_request(f)
        self.__after_request_functions_added = True

    @staticmethod
    def _output_json(data, code, headers=None):
        """Make a Flask response with a JSON encoded body.

        This is a replacement of the default that is shipped with flask-RESTful
        as we need oslo_serialization for the wider datatypes in our objects
        that are serialized to json.
        """
        settings = flask.current_app.config.get('RESTFUL_JSON', {})

        # If we're in debug mode, and the indent is not set, we set it to
        # a reasonable value here. Note that this won't override any existing
        # value that was set. We also set the "sort_keys" value.
        if flask.current_app.debug:
            settings.setdefault('indent', 4)
            settings.setdefault('sort_keys', not flask_restful.utils.PY3)

        # always end the json dumps with a new line
        # see https://github.com/mitsuhiko/flask/pull/1262
        dumped = jsonutils.dumps(data, **settings) + "\n"

        resp = flask.make_response(dumped, code)
        resp.headers.extend(headers or {})
        return resp

    @classmethod
    def instantiate_and_register_to_app(cls, flask_app):
        """Build the API object and register to the passed in flask_app.

        This is a simplistic loader that makes assumptions about how the
        blueprint is loaded. Anything beyond defaults should be done
        explicitly via normal instantiation where more values may be passed
        via :meth:`__init__`.

        :returns: :class:`keystone.server.flask.common.APIBase`
        """
        inst = cls()
        flask_app.register_blueprint(inst.blueprint)
        return inst


class ResourceBase(flask_restful.Resource):

    collection_key = None
    member_key = None
    # NOTE(morgan): This must match the string on the API the resource is
    # registered to.
    api_prefix = ''

    method_decorators = []

    def __init__(self):
        super(ResourceBase, self).__init__()
        if self.collection_key is None:
            raise ValueError('PROGRAMMING ERROR: `self.collection_key` '
                             'cannot be `None`.')
        if self.member_key is None:
            raise ValueError('PROGRAMMING ERROR: `self.member_key` cannot '
                             'be `None`.')

    @staticmethod
    def _assign_unique_id(ref):
        ref = ref.copy()
        ref['id'] = uuid.uuid4().hex
        return ref

    @classmethod
    def _require_matching_id(cls, ref):
        """Ensure the value matches the reference's ID, if any."""
        id_arg = None
        if cls.member_key is not None:
            id_arg = flask.request.view_args.get('%s_id' % cls.member_key)
        if ref.get('id') is not None and id_arg != ref['id']:
            raise exception.ValidationError('Cannot change ID')

    @classmethod
    def wrap_collection(cls, refs, hints=None):
        """Wrap a collection, checking for filtering and pagination.

        Returns the wrapped collection, which includes:
        - Executing any filtering not already carried out
        - Truncate to a set limit if necessary
        - Adds 'self' links in every member
        - Adds 'next', 'self' and 'prev' links for the whole collection.

        :param refs: the list of members of the collection
        :param hints: list hints, containing any relevant filters and limit.
                      Any filters already satisfied by managers will have been
                      removed
        """
        # Check if there are any filters in hints that were not handled by
        # the drivers. The driver will not have paginated or limited the
        # output if it found there were filters it was unable to handle

        if hints:
            refs = cls.filter_by_attributes(refs, hints)

        list_limited, refs = cls.limit(refs, hints)

        for ref in refs:
            cls._add_self_referential_link(ref)

        container = {cls.collection_key: refs}
        pfx = getattr(cls, 'api_prefix', '').lstrip('/')
        parts = [p for p in (full_url(), 'v3', pfx, cls.collection_key) if p]
        self_url = '/'.join(parts)
        container['links'] = {
            'next': None,
            'self': self_url,
            'previous': None
        }
        if list_limited:
            container['truncated'] = True

        return container

    @classmethod
    def wrap_member(cls, ref):
        cls._add_self_referential_link(ref)
        return {cls.member_key: ref}

    @classmethod
    def _add_self_referential_link(cls, ref):
        collection_element = cls.collection_key
        if cls.api_prefix:
            api_prefix = cls.api_prefix.lstrip('/').rstrip('/')
            collection_element = '/'.join([api_prefix, cls.collection_key])
        self_link = '/'.join([base_url(), 'v3', collection_element, ref['id']])
        ref.setdefault('links', {})['self'] = self_link

    @classmethod
    def filter_by_attributes(cls, refs, hints):
        """Filter a list of references by filter values."""
        def _attr_match(ref_attr, val_attr):
            """Matche attributes allowing for booleans as strings.

            We test explicitly for a value that defines it as 'False',
            which also means that the existence of the attribute with
            no value implies 'True'

            """
            if type(ref_attr) is bool:
                return ref_attr == utils.attr_as_boolean(val_attr)
            else:
                return ref_attr == val_attr

        def _inexact_attr_match(inexact_filter, ref):
            """Apply an inexact filter to a result dict.

            :param inexact_filter: the filter in question
            :param ref: the dict to check

            :returns: True if there is a match

            """
            comparator = inexact_filter['comparator']
            key = inexact_filter['name']

            if key in ref:
                filter_value = inexact_filter['value']
                target_value = ref[key]
                if not inexact_filter['case_sensitive']:
                    # We only support inexact filters on strings so
                    # it's OK to use lower()
                    filter_value = filter_value.lower()
                    target_value = target_value.lower()

                if comparator == 'contains':
                    return (filter_value in target_value)
                elif comparator == 'startswith':
                    return target_value.startswith(filter_value)
                elif comparator == 'endswith':
                    return target_value.endswith(filter_value)
                else:
                    # We silently ignore unsupported filters
                    return True

            return False

        for f in hints.filters:
            if f['comparator'] == 'equals':
                attr = f['name']
                value = f['value']
                refs = [r for r in refs if _attr_match(
                    utils.flatten_dict(r).get(attr), value)]
            else:
                # It might be an inexact filter
                refs = [r for r in refs if _inexact_attr_match(f, r)]

        return refs

    @property
    def auth_context(self):
        return flask.request.environ.get(authorization.AUTH_CONTEXT_ENV, None)

    @property
    def oslo_context(self):
        return flask.request.environ.get(context.REQUEST_CONTEXT_ENV, None)

    @property
    def audit_initiator(self):
        """A pyCADF initiator describing the current authenticated context.

        As a property.
        """
        return build_audit_initiator()

    @staticmethod
    def build_driver_hints(supported_filters):
        """Build list hints based on the context query string.

        :param supported_filters: list of filters supported, so ignore any
                                  keys in query_dict that are not in this list.

        """
        hints = driver_hints.Hints()

        if not flask.request.args:
            return hints

        for key, value in flask.request.args.items():
            # Check if this is an exact filter
            if supported_filters is None or key in supported_filters:
                hints.add_filter(key, value)
                continue

            # Check if it is an inexact filter
            for valid_key in supported_filters:
                # See if this entry in query_dict matches a known key with an
                # inexact suffix added.  If it doesn't match, then that just
                # means that there is no inexact filter for that key in this
                # query.
                if not key.startswith(valid_key + '__'):
                    continue

                base_key, comparator = key.split('__', 1)

                # We map the query-style inexact of, for example:
                #
                # {'email__contains', 'myISP'}
                #
                # into a list directive add filter call parameters of:
                #
                # name = 'email'
                # value = 'myISP'
                # comparator = 'contains'
                # case_sensitive = True

                case_sensitive = True
                if comparator.startswith('i'):
                    case_sensitive = False
                    comparator = comparator[1:]
                hints.add_filter(base_key, value,
                                 comparator=comparator,
                                 case_sensitive=case_sensitive)

        # NOTE(henry-nash): If we were to support pagination, we would pull any
        # pagination directives out of the query_dict here, and add them into
        # the hints list.
        return hints

    @classmethod
    def limit(cls, refs, hints):
        """Limit a list of entities.

        The underlying driver layer may have already truncated the collection
        for us, but in case it was unable to handle truncation we check here.

        :param refs: the list of members of the collection
        :param hints: hints, containing, among other things, the limit
                      requested

        :returns: boolean indicating whether the list was truncated, as well
                  as the list of (truncated if necessary) entities.

        """
        NOT_LIMITED = False
        LIMITED = True

        if hints is None or hints.limit is None:
            # No truncation was requested
            return NOT_LIMITED, refs

        if hints.limit.get('truncated', False):
            # The driver did truncate the list
            return LIMITED, refs

        if len(refs) > hints.limit['limit']:
            # The driver layer wasn't able to truncate it for us, so we must
            # do it here
            return LIMITED, refs[:hints.limit['limit']]

        return NOT_LIMITED, refs

    @classmethod
    def _normalize_dict(cls, d):
        return {cls._normalize_arg(k): v for (k, v) in d.items()}

    @staticmethod
    def _normalize_arg(arg):
        return arg.replace(':', '_').replace('-', '_')


def base_url():
    url = CONF['public_endpoint']

    if url:
        substitutions = dict(
            itertools.chain(CONF.items(), CONF.eventlet_server.items()))

        url = url % substitutions
    elif flask.request.environ:
        url = wsgiref.util.application_uri(flask.request.environ)
        # remove version from the URL as it may be part of SCRIPT_NAME but
        # it should not be part of base URL
        url = re.sub(r'/v(3|(2\.0))/*$', '', url)

        # now remove the standard port
        url = utils.remove_standard_port(url)
    else:
        # if we don't have enough information to come up with a base URL,
        # then fall back to localhost. This should never happen in
        # production environment.
        url = 'http://localhost:%d' % CONF.eventlet_server.public_port

    return url.rstrip('/')


def full_url():
    subs = {'url': base_url(), 'query_string': ''}
    qs = flask.request.environ.get('QUERY_STRING')
    if qs:
        subs['query_string'] = '?%s' % qs
    return '%(url)s%(query_string)s' % subs


def unenforced_api(f):
    """Decorate a resource method to mark is as an unenforced API.

    Explicitly exempts an API from receiving the enforced API check,
    specifically for cases such as user self-service password changes (or
    other APIs that must work without already having a token).

    This decorator may also be used if the API has extended enforcement
    logic/varying enforcement logic (such as some of the AUTH paths) where
    the full enforcement will be implemented directly within the methods.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        setattr(flask.g, enforcer._ENFORCEMENT_CHECK_ATTR, True)
        return f(*args, **kwargs)
    return wrapper
