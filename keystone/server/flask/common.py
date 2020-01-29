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
import http.client
from oslo_log import log
from oslo_log import versionutils
from oslo_serialization import jsonutils

from keystone.common import authorization
from keystone.common import context
from keystone.common import driver_hints
from keystone.common import json_home
from keystone.common.rbac_enforcer import enforcer
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone import notifications


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
    :param alternate_urls: An iterable (list) of dictionaries containing urls
                           and associated json home REL data. Each element is
                           expected to be a dictionary with a 'url' key and an
                           optional 'json_home' key for a 'JsonHomeData' named
                           tuple  These urls will also map to the resource.
                           These are used to ensure API compatibility when a
                           "new" path is more correct for the API but old paths
                           must continue to work. Example:
                           `/auth/domains` being the new path for
                           `/OS-FEDERATION/domains`. The `OS-FEDERATION` part
                           would be listed as an alternate url. If a
                           'json_home' key is provided, the original path
                           with the new json_home data will be added to the
                           JSON Home Document.
    :type: iterable or None
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
           'enforcer.RBACEnforcer.enforce_call()`) has not been called; API '
           'is unenforced.')
    g = flask.g
    # NOTE(morgan): OPTIONS is a special case and is handled by flask
    # internally. We should never be enforcing on OPTIONS calls.
    if flask.request.method != 'OPTIONS':
        assert getattr(  # nosec
            g, enforcer._ENFORCEMENT_CHECK_ATTR, False), msg  # nosec
    return resp


def _remove_content_type_on_204(resp):
    # Remove content-type if the resp is 204.
    if resp.status_code == http.client.NO_CONTENT:
        resp.headers.pop('content-type', None)
    return resp


class APIBase(object, metaclass=abc.ABCMeta):

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
            if getattr(r, '_id_path_param_name_override', None):
                # The member_key doesn't match the "id" key in the url, make
                # sure to use the correct path-key for ID.
                member_id_key = getattr(r, '_id_path_param_name_override')
            else:
                member_id_key = '%(member_key)s_id' % {'member_key': m_key}

            entity_path = '/%(collection)s/<string:%(member)s>' % {
                'collection': c_key, 'member': member_id_key}
            # NOTE(morgan): The json-home form of the entity path is different
            # from the flask-url routing form. Must also include the prefix
            jh_e_path = _URL_SUBST.sub('{\\1}', '%(pfx)s/%(e_path)s' % {
                'pfx': self._api_url_prefix,
                'e_path': entity_path.lstrip('/')})

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
            collection_rel_resource_name = getattr(
                r, 'json_home_collection_resource_name_override', c_key)
            collection_rel = resource_rel_func(
                resource_name=collection_rel_resource_name)
            # NOTE(morgan): Add the prefix explicitly for JSON Home documents
            # to the collection path.
            href_val = '%(pfx)s%(collection_path)s' % {
                'pfx': self._api_url_prefix,
                'collection_path': collection_path}

            # If additional parameters exist in the URL, add them to the
            # href-vars dict.
            additional_params = getattr(
                r, 'json_home_additional_parameters', {})

            if additional_params:
                # NOTE(morgan): Special case, we have 'additional params' which
                # means we know the params are in the "prefix". This guarantees
                # the correct data in the json_home document with href-template
                # and href-vars even on the "collection" entry
                rel_data = dict()
                rel_data['href-template'] = _URL_SUBST.sub('{\\1}', href_val)
                rel_data['href-vars'] = additional_params
            else:
                rel_data = {'href': href_val}
            member_rel_resource_name = getattr(
                r, 'json_home_member_resource_name_override', m_key)

            entity_rel = resource_rel_func(
                resource_name=member_rel_resource_name)
            id_str = member_id_key

            parameter_rel_func = getattr(
                r, 'json_home_parameter_rel_func',
                json_home.build_v3_parameter_relation)
            id_param_rel = parameter_rel_func(parameter_name=id_str)
            entity_rel_data = {'href-template': jh_e_path,
                               'href-vars': {id_str: id_param_rel}}

            if additional_params:
                entity_rel_data.setdefault('href-vars', {}).update(
                    additional_params)

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
            alt_url_json_home_data = []
            LOG.debug(
                'Adding resource routes to API %(name)s: '
                '[%(url)r %(kwargs)r]',
                {'name': self._name, 'url': r.url, 'kwargs': r.kwargs})
            urls = [r.url]
            if r.alternate_urls is not None:
                for element in r.alternate_urls:
                    if self._api_url_prefix:
                        LOG.debug(
                            'Unable to add additional resource route '
                            '`%(route)s` to API %(name)s because API has a '
                            'URL prefix. Only APIs without explicit prefixes '
                            'can have alternate URL routes added.',
                            {'route': element['url'], 'name': self._name}
                        )
                        continue
                    LOG.debug(
                        'Adding additional resource route (alternate) to API '
                        '%(name)s: [%(url)r %(kwargs)r]',
                        {'name': self._name, 'url': element['url'],
                         'kwargs': r.kwargs})
                    urls.append(element['url'])
                    if element.get('json_home'):
                        alt_url_json_home_data.append(element['json_home'])
            # Add all URL routes at once.
            self.api.add_resource(r.resource, *urls, **r.kwargs)

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

                for element in alt_url_json_home_data:
                    # Append the "new" path (resource) data with the old rel
                    # reference.
                    json_home.JsonHomeResources.append_resource(
                        element.rel, resource_data)

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


class _AttributeRaisesError(object):
    # NOTE(morgan): This is a special case class that exists to effectively
    # create a @classproperty style function. We use __get__ to raise the
    # exception.

    def __init__(self, name):
        self.__msg = 'PROGRAMMING ERROR: `self.{name}` is not set.'.format(
            name=name)

    def __get__(self, instance, owner):
        raise ValueError(self.__msg)


class ResourceBase(flask_restful.Resource):
    collection_key = _AttributeRaisesError(name='collection_key')
    member_key = _AttributeRaisesError(name='member_key')
    _public_parameters = frozenset([])
    # NOTE(morgan): This must match the string on the API the resource is
    # registered to.
    api_prefix = ''
    _id_path_param_name_override = None

    method_decorators = []

    @staticmethod
    def _assign_unique_id(ref):
        ref = ref.copy()
        ref['id'] = uuid.uuid4().hex
        return ref

    @staticmethod
    def _validate_id_format(id):
        uval = uuid.UUID(id).hex
        if uval != id:
            raise ValueError('badly formed hexadecimal UUID value')

    @classmethod
    def _require_matching_id(cls, ref):
        """Ensure the value matches the reference's ID, if any."""
        id_arg = None
        if cls.member_key is not None:
            id_arg = flask.request.view_args.get('%s_id' % cls.member_key)
        if ref.get('id') is not None and id_arg != ref['id']:
            raise exception.ValidationError('Cannot change ID')

    @classmethod
    def filter_params(cls, ref):
        """Remove unspecified parameters from the dictionary.

        This function removes unspecified parameters from the dictionary.
        This method checks only root-level keys from a ref dictionary.

        :param ref: a dictionary representing deserialized response to be
                    serialized
        """
        # NOTE(morgan): if _public_parameters is empty, do nothing. We do not
        # filter if we do not have an explicit white-list to work from.
        if cls._public_parameters:
            ref_keys = set(ref.keys())
            blocked_keys = ref_keys - cls._public_parameters
            for blocked_param in blocked_keys:
                del ref[blocked_param]
        return ref

    @classmethod
    def wrap_collection(cls, refs, hints=None, collection_name=None):
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
        :param collection_name: optional override for the 'collection key'
                                class attribute. This is to be used when
                                wrapping a collection for a different api,
                                e.g. 'roles' from the 'trust' api.
        """
        # Check if there are any filters in hints that were not handled by
        # the drivers. The driver will not have paginated or limited the
        # output if it found there were filters it was unable to handle

        if hints:
            refs = cls.filter_by_attributes(refs, hints)

        list_limited, refs = cls.limit(refs, hints)

        collection = collection_name or cls.collection_key

        for ref in refs:
            cls._add_self_referential_link(ref, collection_name=collection)

        container = {collection: refs}
        self_url = full_url(flask.request.environ['PATH_INFO'])
        container['links'] = {
            'next': None,
            'self': self_url,
            'previous': None
        }
        if list_limited:
            container['truncated'] = True

        return container

    @classmethod
    def wrap_member(cls, ref, collection_name=None, member_name=None):
        cls._add_self_referential_link(ref, collection_name)
        return {member_name or cls.member_key: ref}

    @classmethod
    def _add_self_referential_link(cls, ref, collection_name=None):
        collection_element = collection_name or cls.collection_key
        if cls.api_prefix:
            api_prefix = cls.api_prefix.lstrip('/').rstrip('/')
            # ensure we have substituted the flask-arg specification
            # to the "keystone" mechanism, then format the string
            api_prefix = _URL_SUBST.sub('{\\1}', api_prefix)
            if flask.request.view_args:
                # if a prefix has substitutions it is *required* that the
                # values are passed as view_args to the HTTP action method
                # (e.g. head/get/post/...).
                api_prefix = api_prefix.format(**flask.request.view_args)
            collection_element = '/'.join(
                [api_prefix, collection_name or cls.collection_key])
        self_link = base_url(path='/'.join([collection_element, ref['id']]))
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
        return notifications.build_audit_initiator()

    @staticmethod
    def query_filter_is_true(filter_name):
        """Determine if bool query param is 'True'.

        We treat this the same way as we do for policy
        enforcement:

        {bool_param}=0 is treated as False

        Any other value is considered to be equivalent to
        True, including the absence of a value (but existence
        as a parameter).

        False Examples for param named `p`:

           * http://host/url
           * http://host/url?p=0

        All other forms of the param 'p' would be result in a True value
        including: `http://host/url?param`.
        """
        val = False
        if filter_name in flask.request.args:
            filter_value = flask.request.args.get(filter_name)
            if (isinstance(filter_value, str) and
                    filter_value == '0'):
                val = False
            else:
                val = True
        return val

    @property
    def request_body_json(self):
        return flask.request.get_json(silent=True, force=True) or {}

    @staticmethod
    def build_driver_hints(supported_filters):
        """Build list hints based on the context query string.

        :param supported_filters: list of filters supported, so ignore any
                                  keys in query_dict that are not in this list.

        """
        hints = driver_hints.Hints()

        if not flask.request.args:
            return hints

        for key, value in flask.request.args.items(multi=True):
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

    @classmethod
    def _get_domain_id_for_list_request(cls):
        """Get the domain_id for a v3 list call.

        If we running with multiple domain drivers, then the caller must
        specify a domain_id either as a filter or as part of the token scope.

        """
        if not CONF.identity.domain_specific_drivers_enabled:
            # We don't need to specify a domain ID in this case
            return

        domain_id = flask.request.args.get('domain_id')
        if domain_id:
            return domain_id

        token_ref = cls.get_token_ref()

        if token_ref.domain_scoped:
            return token_ref.domain_id
        elif token_ref.project_scoped:
            return token_ref.project_domain['id']
        elif token_ref.system_scoped:
            return
        else:
            msg = 'No domain information specified as part of list request'
            tr_msg = _('No domain information specified as part of list '
                       'request')
            LOG.warning(msg)
            raise exception.Unauthorized(tr_msg)

    @classmethod
    def get_token_ref(cls):
        """Retrieve KeystoneToken object from the auth context and returns it.

        :raises keystone.exception.Unauthorized: If auth context cannot be
                                                 found.
        :returns: The KeystoneToken object.
        """
        try:
            # Retrieve the auth context that was prepared by
            # AuthContextMiddleware.

            auth_context = flask.request.environ.get(
                authorization.AUTH_CONTEXT_ENV, {})
            return auth_context['token']
        except KeyError:
            LOG.warning("Couldn't find the auth context.")
            raise exception.Unauthorized()

    @classmethod
    def _normalize_domain_id(cls, ref):
        """Fill in domain_id if not specified in a v3 call."""
        if not ref.get('domain_id'):
            oslo_ctx = flask.request.environ.get(
                context.REQUEST_CONTEXT_ENV, None)
            if oslo_ctx and oslo_ctx.domain_id:
                # Domain Scoped Token Scenario.
                ref['domain_id'] = oslo_ctx.domain_id
            elif oslo_ctx.is_admin:
                # Legacy "shared" admin token Scenario
                raise exception.ValidationError(
                    _('You have tried to create a resource using the admin '
                      'token. As this token is not within a domain you must '
                      'explicitly include a domain for this resource to '
                      'belong to.'))
            else:
                # TODO(henry-nash): We should issue an exception here since if
                # a v3 call does not explicitly specify the domain_id in the
                # entity, it should be using a domain scoped token.  However,
                # the current tempest heat tests issue a v3 call without this.
                # This is raised as bug #1283539.  Once this is fixed, we
                # should remove the line below and replace it with an error.
                #
                # Ahead of actually changing the code to raise an exception, we
                # issue a deprecation warning.
                versionutils.report_deprecated_feature(
                    LOG,
                    'Not specifying a domain during a create user, group or '
                    'project call, and relying on falling back to the '
                    'default domain, is deprecated as of Liberty. There is no '
                    'plan to remove this compatibility, however, future API '
                    'versions may remove this, so please specify the domain '
                    'explicitly or use a domain-scoped token.')
                ref['domain_id'] = CONF.identity.default_domain_id
        return ref


def base_url(path=''):
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

    if path:
        # Cleanup leading /v3 if needed.
        path = path.rstrip('/').lstrip('/')
        if path.startswith('v3'):
            path = path[2:].lstrip('/')

    url = url.rstrip('/')
    url = '/'.join([p for p in (url, 'v3', path) if p])
    return url


def full_url(path=''):
    subs = {'url': base_url(path), 'query_string': ''}
    qs = flask.request.environ.get('QUERY_STRING')
    if qs:
        subs['query_string'] = '?%s' % qs
    return '%(url)s%(query_string)s' % subs


def set_unenforced_ok():
    # Does the work for unenforced_api. This must be used outside of a
    # decorator in some limited, such as when a ValidationError is raised up
    # from a "before_request" function (body_json checker is a prime example)
    setattr(flask.g, enforcer._ENFORCEMENT_CHECK_ATTR, True)


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
        set_unenforced_ok()
        return f(*args, **kwargs)
    return wrapper
