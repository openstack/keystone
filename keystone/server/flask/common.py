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

from flask import blueprints
import flask_restful
from oslo_log import log
import six


LOG = log.getLogger(__name__)
ResourceMap = collections.namedtuple('resource_map', 'resource, urls, kwargs')


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

    def _add_resources(self):
        for r in self.resource_mapping:
            LOG.debug(
                'Adding resource routes to API %(name)s: '
                '[%(urls)r %(kwargs)r]',
                {'name': self._name, 'urls': r.urls, 'kwargs': r.kwargs})
            self._blueprint.add_resource(r.resource, *r.urls, **r.kwargs)

    @classmethod
    def instantiate_and_register_to_app(cls, flask_app):
        """Build the API object and register to the passed in flask_app.

        This is a simplistic loader that makes assumptions about how the
        blueprint is loaded. Anything beyond defaults should be done
        explicitly via normal instantiation where more values may be passed
        via :meth:`__init__`.
        """
        flask_app.register_blueprint(cls().blueprint)
