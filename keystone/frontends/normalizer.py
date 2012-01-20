#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2010 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
Auth Middleware that accepts URL query extension.

This module can be installed as a filter in front of your service to
detect extension in the resource URI (e.g., foo/resource.xml) to
specify HTTP response body type. If an extension is specified, it
overwrites the Accept header in the request, if present.

"""

import logging
import webob.acceptparse
from webob import Request

logger = logging.getLogger(__name__)  # pylint: disable=C0103

# Maps supported URL prefixes to API_VERSION
PATH_PREFIXES = {
    '/v2.0': '2.0',
    '/v1.1': '1.1',
    '/v1.0': '1.0'}

# Maps supported URL extensions to RESPONSE_ENCODING
PATH_SUFFIXES = {
    '.json': 'json',
    '.xml': 'xml',
    '.atom': 'atom+xml'}

# Maps supported Accept headers to RESPONSE_ENCODING and API_VERSION
ACCEPT_HEADERS = {
    'application/vnd.openstack.identity+json;version=2.0': ('json', '2.0'),
    'application/vnd.openstack.identity+xml;version=2.0': ('xml', '2.0'),
    'application/vnd.openstack.identity-v2.0+json': ('json', '2.0'),
    'application/vnd.openstack.identity-v2.0+xml': ('xml', '2.0'),
    'application/vnd.openstack.identity+json;version=1.1': ('json', '1.1'),
    'application/vnd.openstack.identity+xml;version=1.1': ('xml', '1.1'),
    'application/vnd.openstack.identity-v1.1+json': ('json', '1.1'),
    'application/vnd.openstack.identity-v1.1+xml': ('xml', '1.1'),
    'application/vnd.openstack.identity-v1.0+json': ('json', '1.0'),
    'application/vnd.openstack.identity-v1.0+xml': ('xml', '1.0'),
    'application/vnd.openstack.identity+json;version=1.0': ('json', '1.0'),
    'application/vnd.openstack.identity+xml;version=1.0': ('xml', '1.0'),
    'application/json': ('json', None),
    'application/xml': ('xml', None),
    'application/atom+xml': ('atom+xml', None)}

DEFAULT_RESPONSE_ENCODING = 'json'
PROTOCOL_NAME = "URL Normalizer"


class NormalizingFilter(object):
    """Middleware filter to handle URL and Accept header normalization"""

    def __init__(self, app, conf):
        msg = "Starting the %s component" % PROTOCOL_NAME
        logger.info(msg)
        # app is the next app in WSGI chain - eventually the OpenStack service
        self.app = app
        self.conf = conf

    def __call__(self, env, start_response):
        # Inspect the request for mime type and API version
        env = normalize_accept_header(env)
        env = normalize_path_prefix(env)
        env = normalize_path_suffix(env)
        env['PATH_INFO'] = normalize_starting_slash(env.get('PATH_INFO'))
        env['PATH_INFO'] = normalize_trailing_slash(env['PATH_INFO'])

        # Fall back on defaults, if necessary
        env['KEYSTONE_RESPONSE_ENCODING'] = env.get(
            'KEYSTONE_RESPONSE_ENCODING') or DEFAULT_RESPONSE_ENCODING
        env['HTTP_ACCEPT'] = 'application/' + (env.get(
            'KEYSTONE_RESPONSE_ENCODING') or DEFAULT_RESPONSE_ENCODING)

        if 'KEYSTONE_API_VERSION' not in env:
            # Version was not specified in path or headers
            # return multiple choice unless the version controller can handle
            # this request
            if env['PATH_INFO'] not in ['/', '']:
                logger.debug("Call without a version - returning 300. Path=%s"
                             % env.get('PATH_INFO', ''))
                from keystone.controllers.version import VersionController
                controller = VersionController()
                response = controller.get_multiple_choice(req=Request(env),
                                file='multiple_choice')
                return response(env, start_response)

        return self.app(env, start_response)


def normalize_accept_header(env):
    """Matches the preferred Accept encoding to supported encodings.

    Sets KEYSTONE_RESPONSE_ENCODING and KEYSTONE_API_VERSION, if appropriate.

    Note:: webob.acceptparse ignores ';version=' values
    """
    accept_value = env.get('HTTP_ACCEPT')

    if accept_value:
        if accept_value in ACCEPT_HEADERS.keys():
            logger.debug("Found direct match for mimetype %s" % accept_value)
            best_accept = accept_value
        else:
            try:
                accept = webob.acceptparse.Accept(accept_value)
            except TypeError:
                logger.warn("Falling back to `webob` v1.1 and older support. "
                            "Check your version of webob")
                accept = webob.acceptparse.Accept('Accept', accept_value)

            best_accept = accept.best_match(ACCEPT_HEADERS.keys())

        if best_accept:
            response_encoding, api_version = ACCEPT_HEADERS[best_accept]
            logger.debug('%s header matched with %s (API=%s, TYPE=%s)',
                         accept_value, best_accept, api_version,
                         response_encoding)

            if response_encoding:
                env['KEYSTONE_RESPONSE_ENCODING'] = response_encoding

            if api_version:
                env['KEYSTONE_API_VERSION'] = api_version
        else:
            logger.debug('%s header could not be matched', accept_value)

    return env


def normalize_path_prefix(env):
    """Handles recognized PATH_INFO prefixes.

    Looks for a version prefix on the PATH_INFO, sets KEYSTONE_API_VERSION
    accordingly, and removes the prefix to normalize the request."""
    for prefix in PATH_PREFIXES.keys():
        if env['PATH_INFO'].startswith(prefix):
            env['KEYSTONE_API_VERSION'] = PATH_PREFIXES[prefix]
            env['PATH_INFO'] = env['PATH_INFO'][len(prefix):]
            break

    return env


def normalize_path_suffix(env):
    """Hnadles recognized PATH_INFO suffixes.

    Looks for a recognized suffix on the PATH_INFO, sets the
    KEYSTONE_RESPONSE_ENCODING accordingly, and removes the suffix to normalize
    the request."""
    for suffix in PATH_SUFFIXES.keys():
        if env['PATH_INFO'].endswith(suffix):
            env['KEYSTONE_RESPONSE_ENCODING'] = PATH_SUFFIXES[suffix]
            env['PATH_INFO'] = env['PATH_INFO'][:-len(suffix)]
            break

    return env


def normalize_starting_slash(path_info):
    """Removes a trailing slash from the given path, if any."""
    # Ensure the path at least contains a slash
    if not path_info:
        return '/'

    # Ensure the path starts with a slash
    elif path_info[0] != '/':
        return '/' + path_info

    # No need to change anything
    else:
        return path_info


def normalize_trailing_slash(path_info):
    """Removes a trailing slash from the given path, if any."""
    # Remove trailing slash, unless it's the only char
    if len(path_info) > 1 and path_info[-1] == '/':
        return path_info[:-1]

    # No need to change anything
    else:
        return path_info


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def ext_filter(app):
        return NormalizingFilter(app, conf)
    return ext_filter
