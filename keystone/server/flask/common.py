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

from flask import blueprints
from flask import g
import flask_restful
from oslo_log import log
import six

from keystone.common.rbac_enforcer import enforcer


LOG = log.getLogger(__name__)
ResourceMap = collections.namedtuple('resource_map', 'resource, urls, kwargs')


def _initialize_rbac_enforcement_check():
    setattr(g, enforcer._ENFORCEMENT_CHECK_ATTR, False)


def _assert_rbac_enforcement_called():
    # assert is intended to be used to ensure code during development works
    # as expected, it is fine to be optimized out with `python -O`
    msg = ('PROGRAMMING ERROR: enforcement (`keystone.common.rbac_enforcer.'
           'enforcer.RBACKEnforcer.enforce_call()`) has not been called; API '
           'is unenforced.')
    assert getattr(g, enforcer._ENFORCEMENT_CHECK_ATTR, False), msg  # nosec


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

            * urls: a url route or iterable of url routes to match for the
                    resource, standard flask routing rules apply. Any url
                    variables will be passed to the resource method as args.
                    (str)

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

    @staticmethod
    def _build_bp_url_prefix(prefix):
        # NOTE(morgan): Keystone only has a V3 API, this is here for future
        # proofing and exceptional cases such as root discovery API object(s)
        parts = ['/v3']
        if prefix:
            parts.append(prefix)
        return '/'.join(parts)

    @property
    def blueprint(self):
        # The API Blueprint may be directly accessed via this property
        return self.__api_bp

    def __init__(self, blueprint_url_prefix='', api_url_prefix='',
                 default_mediatype='application/json', decorators=None,
                 errors=None):
        self.__before_request_functions_added = False
        self.__after_request_functions_added = False
        self._blueprint_url_prefix = blueprint_url_prefix
        self._default_mediatype = default_mediatype
        self._api_url_prefix = api_url_prefix
        self.__blueprint = blueprints.Blueprint(
            name=self._name, import_name=self._import_name,
            url_prefix=self._build_bp_url_prefix(self._blueprint_url_prefix))
        self.__api_bp = flask_restful.Api(
            app=self.__blueprint, prefix=self._api_url_prefix,
            default_mediatype=self._default_mediatype,
            decorators=decorators, errors=errors)
        self._add_resources()

        # Apply Before and After request functions
        self._register_before_request_functions()
        self._register_after_request_functions()
        # Assert is intended to ensure code works as expected in development,
        # it is fine to optimize out with python -O
        msg = '%s_request functions not registered'
        assert self.__before_request_functions_added, msg % 'before'  # nosec
        assert self.__after_request_functions_added, msg % 'after'  # nosec

    def _add_resources(self):
        for r in self.resource_mapping:
            LOG.debug(
                'Adding resource routes to API %(name)s: '
                '[%(urls)r %(kwargs)r]',
                {'name': self._name, 'urls': r.urls, 'kwargs': r.kwargs})
            self.blueprint.add_resource(r.resource, *r.urls, **r.kwargs)

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

        # Add Passed-In Functions
        for f in functions:
            self.__blueprint.after_request(f)
        self.__after_request_functions_added = True

    @staticmethod
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
            setattr(g, enforcer._ENFORCEMENT_CHECK_ATTR, True)
            return f(*args, **kwargs)
        return wrapper

    @classmethod
    def instantiate_and_register_to_app(cls, flask_app):
        """Build the API object and register to the passed in flask_app.

        This is a simplistic loader that makes assumptions about how the
        blueprint is loaded. Anything beyond defaults should be done
        explicitly via normal instantiation where more values may be passed
        via :meth:`__init__`.
        """
        flask_app.register_blueprint(cls().blueprint)
