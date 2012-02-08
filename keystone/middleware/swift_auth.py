#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2010-2011 OpenStack, LLC.
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
TOKEN-BASED AUTH MIDDLEWARE FOR SWIFT

Authentication on incoming request
    * grab token from X-Auth-Token header
    * TODO: grab the memcache servers from the request env
    * TODOcheck for auth information in memcache
    * check for auth information from keystone
    * return if unauthorized
    * decorate the request for authorization in swift
    * forward to the swift proxy app

Authorization via callback
    * check the path and extract the tenant
    * get the auth information stored in keystone.identity during
        authentication
    * TODO: check if the user is an account admin or a reseller admin
    * determine what object-type to authorize (account, container, object)
    * use knowledge of tenant, admin status, and container acls to authorize

"""

import json
from urlparse import urlparse
from webob.exc import HTTPUnauthorized, HTTPNotFound, HTTPExpectationFailed

from keystone.common.bufferedhttp import http_connect_raw as http_connect

from swift.common.middleware.acl import clean_acl, parse_acl, referrer_allowed
from swift.common.utils import get_logger, split_path


PROTOCOL_NAME = 'Swift Token Authentication'


class AuthProtocol(object):
    """Handles authenticating and aurothrizing client calls.

    Add to your pipeline in paste config like:

        [pipeline:main]
        pipeline = catch_errors healthcheck cache keystone proxy-server

        [filter:keystone]
        use = egg:keystone#swiftauth
        keystone_url = http://127.0.0.1:8080
        keystone_admin_token = 999888777666
    """

    def __init__(self, app, conf):
        """Store valuable bits from the conf and set up logging."""
        self.app = app
        self.keystone_url = urlparse(conf.get('keystone_url'))
        self.admin_token = conf.get('keystone_admin_token')
        self.reseller_prefix = conf.get('reseller_prefix', 'AUTH')
        self.log = get_logger(conf, log_route='keystone')
        self.log.info('Keystone middleware started')

    def __call__(self, env, start_response):
        """Authenticate the incoming request.

        If authentication fails return an appropriate http status here,
        otherwise forward through the rest of the app.
        """

        self.log.debug('Keystone middleware called')
        token = self._get_claims(env)
        self.log.debug('token: %s', token)
        if token:
            identity = self._validate_claims(token)
            if identity:
                self.log.debug('request authenticated: %r', identity)
                return self.perform_authenticated_request(identity, env,
                                                          start_response)
            else:
                self.log.debug('anonymous request')
                return self.unauthorized_request(env, start_response)
        self.log.debug('no auth token in request headers')
        return self.perform_unidentified_request(env, start_response)

    def unauthorized_request(self, env, start_response):
        """Clinet provided a token that wasn't acceptable, error out."""
        return HTTPUnauthorized()(env, start_response)

    def unauthorized(self, req):
        """Return unauthorized given a webob Request object.

        This can be stuffed into the evironment for swift.authorize or
        called from the authoriztion callback when authorization fails.
        """
        return HTTPUnauthorized(request=req)

    def perform_authenticated_request(self, identity, env, start_response):
        """Client provieded a valid identity, so use it for authorization."""
        env['keystone.identity'] = identity
        env['swift.authorize'] = self.authorize
        env['swift.clean_acl'] = clean_acl
        self.log.debug('calling app: %s // %r', start_response, env)
        rv = self.app(env, start_response)
        self.log.debug('return from app: %r', rv)
        return rv

    def perform_unidentified_request(self, env, start_response):
        """Withouth authentication data, use acls for access control."""
        env['swift.authorize'] = self.authorize_via_acl
        env['swift.clean_acl'] = self.authorize_via_acl
        return self.app(env, start_response)

    def authorize(self, req):
        """Used when we have a valid identity from keystone."""
        self.log.debug('keystone middleware authorization begin')
        env = req.environ
        tenant = env.get('keystone.identity', {}).get('tenant')
        if not tenant:
            self.log.warn('identity info not present in authorize request')
            return HTTPExpectationFailed('Unable to locate auth claim',
                                         request=req)
        # TODO(todd): everyone under a tenant can do anything to that tenant.
        #             more realistic would be role/group checking to do things
        #             like deleting the account or creating/deleting containers
        #             esp. when owned by other users in the same tenant.
        if req.path.startswith('/v1/%s_%s' % (self.reseller_prefix, tenant)):
            self.log.debug('AUTHORIZED OKAY')
            return None

        self.log.debug('tenant mismatch: %r', tenant)
        return self.unauthorized(req)

    def authorize_via_acl(self, req):
        """Anon request handling.

        For now this only allows anon read of objects.  Container and account
        actions are prohibited.
        """

        self.log.debug('authorizing anonymous request')
        try:
            version, account, container, obj = split_path(req.path, 1, 4, True)
        except ValueError:
            return HTTPNotFound(request=req)

        if obj:
            return self._authorize_anon_object(req, account, container, obj)

        if container:
            return self._authorize_anon_container(req, account, container)

        if account:
            return self._authorize_anon_account(req, account)

        return self._authorize_anon_toplevel(req)

    def _authorize_anon_object(self, req, account, container, obj):
        referrers, groups = parse_acl(getattr(req, 'acl', None))
        if referrer_allowed(req.referer, referrers):
            self.log.debug('anonymous request AUTHORIZED OKAY')
            return None
        return self.unauthorized(req)

    def _authorize_anon_container(self, req, account, container):
        return self.unauthorized(req)

    def _authorize_anon_account(self, req, account):
        return self.unauthorized(req)

    def _authorize_anon_toplevel(self, req):
        return self.unauthorized(req)

    def _get_claims(self, env):
        claims = env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN'))
        return claims

    def _validate_claims(self, claims):
        """Ask keystone (as keystone admin) for information for this user."""

        # TODO(todd): cache

        self.log.debug('Asking keystone to validate token')
        headers = {'Content-type': 'application/json',
                    'Accept': 'application/json',
                    'X-Auth-Token': self.admin_token}
        self.log.debug('headers: %r', headers)
        self.log.debug('url: %s', self.keystone_url)
        conn = http_connect(self.keystone_url.hostname, self.keystone_url.port,
                            'GET', '/v2.0/tokens/%s' % claims, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()

        # Check http status code for the 'OK' family of responses
        if not str(resp.status).startswith('20'):
            return False

        identity_info = json.loads(data)
        roles = []
        role_refs = identity_info['access']['user']['roles']

        if role_refs is not None:
            for role_ref in role_refs:
                roles.append(role_ref['id'])

        try:
            tenant = identity_info['access']['token']['tenantId']
        except:
            tenant = None
        if not tenant:
            tenant = identity_info['access']['user']['tenantId']
        # TODO(Ziad): add groups back in
        identity = {'user': identity_info['access']['user']['username'],
                    'tenant': tenant,
                    'roles': roles}

        return identity


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return AuthProtocol(app, conf)

    return auth_filter
