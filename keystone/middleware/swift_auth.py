# Copyright (c) 2011 OpenStack, LLC.
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

import json

from urllib import quote
from urlparse import urlparse

from webob.exc import HTTPForbidden, HTTPNotFound, \
    HTTPUnauthorized, HTTPBadRequest
from webob import Request

from swift.common.utils import cache_from_env, get_logger, split_path, \
    get_remote_client
from swift.common.middleware.acl import clean_acl, parse_acl, referrer_allowed
from swift.common.bufferedhttp import http_connect_raw as http_connect
from time import time, mktime
from datetime import datetime


class AuthProtocol(object):
    """
    Keystone to Swift authentication and authorization system.

    Add to your pipeline in proxy-server.conf, such as::

        [pipeline:main]
        pipeline = catch_errors cache keystone proxy-server

    Set account auto creation to true::

        [app:proxy-server]
        account_autocreate = true

    And add a keystone filter section, such as::

        [filter:keystone]
        use = egg:keystone#swiftauth
        keystone_url = http://keystone_url:5000/v2.0
        keystone_admin_token = admin_token
        keystone_swift_operator_roles = Admin, SwiftOperator
        keystone_tenant_user_admin = true

    This maps tenants to account in Swift.

    The user whose able to give ACL / create Containers permissions
    will be the one that are inside the keystone_swift_operator_roles
    setting which by default includes the Admin and the SwiftOperator
    roles.

    The option keystone_tenant_user_admin if set to true will allow the
    username that has the same name as the account name to be the owner.

    Example: If we have the account called hellocorp with a user
    hellocorp that user will be admin on that account and can give ACL
    to all other users for hellocorp.

    :param app: The next WSGI app in the pipeline
    :param conf: The dict of configuration values
    """
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='keystone')
        self.reseller_prefix = conf.get('reseller_prefix', 'AUTH').strip()
        #TODO: Error out if no url
        self.keystone_url = urlparse(conf.get('keystone_url'))
        self.keystone_swift_operator_roles = \
            conf.get('keystone_swift_operator_roles', 'Admin, SwiftOperator')
        self.admin_token = conf.get('keystone_admin_token')
        self.keystone_tenant_user_admin = \
            conf.get('keystone_tenant_user_admin', "false").lower() in \
            ('true', 't', '1', 'on', 'yes', 'y')
        self.allowed_sync_hosts = [h.strip()
            for h in conf.get('allowed_sync_hosts', '127.0.0.1').split(',')
            if h.strip()]

    def __call__(self, environ, start_response):
        self.logger.debug('Initialise keystone middleware')

        req = Request(environ)
        token = environ.get('HTTP_X_AUTH_TOKEN',
                            environ.get('HTTP_X_STORAGE_TOKEN'))
        if not token:
            self.logger.debug('No token: exiting')
            environ['swift.authorize'] = self.denied_response
            return self.app(environ, start_response)

        self.logger.debug('Got token: %s' % (token))

        identity = None
        memcache_client = cache_from_env(environ)
        memcache_key = 'tokens/%s' % (token)
        candidate_cache = memcache_client.get(memcache_key)
        if candidate_cache:
            expires, _identity = candidate_cache
            if expires > time():
                self.logger.debug('getting identity info from memcache')
                identity = _identity

        if not identity:
            self.logger.debug("No memcache, requesting it from keystone")
            identity = self._keystone_validate_token(token)
            if identity and memcache_client:
                expires = identity['expires']
                memcache_client.set(memcache_key,
                                    (expires, identity),
                                    timeout=expires - time())
                ts = str(datetime.fromtimestamp(expires))
                self.logger.debug('setting memcache expiration to %s' % ts)
            else:  # if we didn't get identity it means there was an error.
                return HTTPBadRequest(request=req)

        self.logger.debug("Using identity: %r" % (identity))

        if not identity:
            #TODO: non authenticated access allow via refer
            environ['swift.authorize'] = self.denied_response
            return self.app(environ, start_response)

        self.logger.debug("Using identity: %r" % (identity))
        environ['keystone.identity'] = identity
        environ['REMOTE_USER'] = identity.get('tenant')
        environ['swift.authorize'] = self.authorize
        environ['swift.clean_acl'] = clean_acl
        return self.app(environ, start_response)

    def convert_date(self, date):
        """ Convert datetime to unix timestamp """
        return mktime(datetime.strptime(
                date[:date.rfind(':')].replace('-', ''), "%Y%m%dT%H:%M",
                ).timetuple())

    def _keystone_validate_token(self, claim):
        """
        Will take a claimed token and validate it in keystone.
        """
        headers = {"X-Auth-Token": self.admin_token}
        conn = http_connect(self.keystone_url.hostname,
                            self.keystone_url.port, 'GET',
                            '%s/tokens/%s' % \
                                (self.keystone_url.path,
                                 quote(claim)),
                            headers=headers,
                            ssl=(self.keystone_url.scheme == 'https'))
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        self.logger.debug("Keystone came back with: status:%d, data:%s" % \
                            (resp.status, data))

        if not str(resp.status).startswith('20'):
            #TODO: Make the self.keystone_url more meaningfull
            raise Exception('Error: Keystone : %s Returned: %d' % \
                                (self.keystone_url, resp.status))
        identity_info = json.loads(data)

        try:
            tenant = (identity_info['access']['token']['tenant']['id'],
                         identity_info['access']['token']['tenant']['name'])
            expires = self.convert_date(
                identity_info['access']['token']['expires'])
            user = 'username' in identity_info['access']['user'] and \
                identity_info['access']['user']['username'] or \
                identity_info['access']['user']['name']
            roles = [x['name'] for x in \
                         identity_info['access']['user']['roles']]
        except (KeyError, IndexError):
            raise

        identity = {'user': user,
                    'tenant': tenant,
                    'roles': roles,
                    'expires': expires,
                    }

        return identity

    def authorize(self, req):
        env = req.environ
        env_identity = env.get('keystone.identity', {})
        tenant = env_identity.get('tenant')

        try:
            version, account, container, obj = split_path(req.path, 1, 4, True)
        except ValueError:
            return HTTPNotFound(request=req)

        if account != '%s_%s' % (self.reseller_prefix, tenant[0]):
            self.logger.debug('tenant mismatch')
            return self.denied_response(req)

        # If user is in the swift operator group then make the owner of it.
        user_groups = env_identity.get('roles', [])
        for _group in self.keystone_swift_operator_roles.split(','):
            _group = _group.strip()
            if  _group in user_groups:
                self.logger.debug(
                    "User in group: %s allow to manage this account" % \
                        (_group))
                req.environ['swift_owner'] = True
                return None

        # If user is of the same name of the tenant then make owner of it.
        user = env_identity.get('user', '')
        if self.keystone_tenant_user_admin and user == tenant[1]:
            self.logger.debug("user: %s == %s tenant and option "\
                               "keystone_tenant_user_admin is set" % \
                               (user, tenant))
            req.environ['swift_owner'] = True
            return None

        # Allow container sync
        if (req.environ.get('swift_sync_key') and
            req.environ['swift_sync_key'] ==
                req.headers.get('x-container-sync-key', None) and
            'x-timestamp' in req.headers and
            (req.remote_addr in self.allowed_sync_hosts or
             get_remote_client(req) in self.allowed_sync_hosts)):
            self.logger.debug('allowing container-sync')
            return None

        # Check if Referrer allow it
        referrers, groups = parse_acl(getattr(req, 'acl', None))
        if referrer_allowed(req.referer, referrers):
            if obj or '.rlistings' in groups:
                self.logger.debug('authorizing via ACL')
                return None
            return self.denied_response(req)

        # Check if we have the group in the usergroups and allow it
        for user_group in user_groups:
            if user_group in groups:
                self.logger.debug('user in group which is allowed in" \
                        " ACL: %s authorizing' % (user_group))
                return None

        # last but not least retun deny
        return self.denied_response(req)

    def denied_response(self, req):
        """
        Returns a standard WSGI response callable with the status of 403 or 401
        depending on whether the REMOTE_USER is set or not.
        """
        if req.remote_user:
            return HTTPForbidden(request=req)
        else:
            return HTTPUnauthorized(request=req)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return AuthProtocol(app, conf)
    return auth_filter
