# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# Copyright (c) 2012 OpenStack, LLC.
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

import webob

from swift.common import utils as swift_utils
from swift.common.middleware import acl as swift_acl


class SwiftAuth(object):
    """Swift middleware to Keystone authorization system.

    In Swift's proxy-server.conf add the middleware to your pipeline::

        [pipeline:main]
        pipeline = catch_errors cache tokenauth swiftauth proxy-server

    Set account auto creation to true::

        [app:proxy-server]
        account_autocreate = true

    And add a swift authorization filter section, such as::

        [filter:swiftauth]
        use = egg:keystone#swiftauth
        operator_roles = admin, SwiftOperator
        is_admin = true

    If Swift memcache is to be used for caching tokens, add the additional
    property in the tokenauth filter:

        [filter:tokenauth]
        paste.filter_factory = keystone.middleware.auth_token:filter_factory
        ...
        cache = swift.cache

    This maps tenants to account in Swift.

    The user whose able to give ACL / create Containers permissions
    will be the one that are inside the operator_roles
    setting which by default includes the Admin and the SwiftOperator
    roles.

    The option is_admin if set to true will allow the
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
        self.logger = swift_utils.get_logger(conf, log_route='keystoneauth')
        self.reseller_prefix = conf.get('reseller_prefix', 'AUTH').strip()
        self.operator_roles = conf.get('operator_roles',
                                       'admin, SwiftOperator')
        config_is_admin = conf.get('is_admin', "false").lower()
        self.is_admin = config_is_admin in ('true', 't', '1', 'on', 'yes', 'y')
        cfg_synchosts = conf.get('allowed_sync_hosts', '127.0.0.1')
        self.allowed_sync_hosts = [h.strip() for h in cfg_synchosts.split(',')
                                   if h.strip()]

    def __call__(self, environ, start_response):
        identity = self._keystone_identity(environ)

        if not identity:
            environ['swift.authorize'] = self.denied_response
            return self.app(environ, start_response)

        self.logger.debug("Using identity: %r" % (identity))
        environ['keystone.identity'] = identity
        environ['REMOTE_USER'] = identity.get('tenant')
        environ['swift.authorize'] = self.authorize
        environ['swift.clean_acl'] = swift_acl.clean_acl
        return self.app(environ, start_response)

    def _keystone_identity(self, environ):
        """Extract the identity from the Keystone auth component."""
        if environ.get('HTTP_X_IDENTITY_STATUS') != 'Confirmed':
            return
        roles = []
        if 'HTTP_X_ROLE' in environ:
            roles = environ['HTTP_X_ROLE'].split(',')
        identity = {'user': environ.get('HTTP_X_USER'),
                    'tenant': (environ.get('HTTP_X_TENANT_ID'),
                               environ.get('HTTP_X_TENANT_NAME')),
                    'roles': roles}
        return identity

    def _reseller_check(self, account, tenant_id):
        """Check reseller prefix."""
        return account == '%s_%s' % (self.reseller_prefix, tenant_id)

    def authorize(self, req):
        env = req.environ
        env_identity = env.get('keystone.identity', {})
        tenant = env_identity.get('tenant')

        try:
            part = swift_utils.split_path(req.path, 1, 4, True)
            version, account, container, obj = part
        except ValueError:
            return webob.exc.HTTPNotFound(request=req)

        if not self._reseller_check(account, tenant[0]):
            log_msg = 'tenant mismatch: %s != %s' % (account, tenant[0])
            self.logger.debug(log_msg)
            return self.denied_response(req)

        user_groups = env_identity.get('roles', [])

        # Check the groups the user is belonging to. If the user is
        # part of the group defined in the config variable
        # operator_roles (like Admin) then it will be
        # promoted as an Admin of the account/tenant.
        for group in self.operator_roles.split(','):
            group = group.strip()
            if group in user_groups:
                log_msg = "allow user in group %s as account admin" % group
                self.logger.debug(log_msg)
                req.environ['swift_owner'] = True
                return

        # If user is of the same name of the tenant then make owner of it.
        user = env_identity.get('user', '')
        if self.is_admin and user == tenant[1]:
            req.environ['swift_owner'] = True
            return

        # Allow container sync.
        if (req.environ.get('swift_sync_key')
            and req.environ['swift_sync_key'] ==
                req.headers.get('x-container-sync-key', None)
            and 'x-timestamp' in req.headers
            and (req.remote_addr in self.allowed_sync_hosts
                 or swift_utils.get_remote_client(req)
                 in self.allowed_sync_hosts)):
            log_msg = 'allowing proxy %s for container-sync' % req.remote_addr
            self.logger.debug(log_msg)
            return

        # Check if referrer is allowed.
        referrers, groups = swift_acl.parse_acl(getattr(req, 'acl', None))
        if swift_acl.referrer_allowed(req.referer, referrers):
            if obj or '.rlistings' in groups:
                log_msg = 'authorizing %s via referer ACL' % req.referrer
                self.logger.debug(log_msg)
                return
            return self.denied_response(req)

        # Allow ACL at individual user level (tenant:user format)
        if '%s:%s' % (tenant[0], user) in groups:
            log_msg = 'user %s:%s allowed in ACL authorizing'
            self.logger.debug(log_msg % (tenant[0], user))
            return

        # Check if we have the group in the usergroups and allow it
        for user_group in user_groups:
            if user_group in groups:
                log_msg = 'user %s:%s allowed in ACL: %s authorizing'
                self.logger.debug(log_msg % (tenant[0], user, user_group))
                return

        return self.denied_response(req)

    def denied_response(self, req):
        """Deny WSGI Response.

        Returns a standard WSGI response callable with the status of 403 or 401
        depending on whether the REMOTE_USER is set or not.
        """
        if req.remote_user:
            return webob.exc.HTTPForbidden(request=req)
        else:
            return webob.exc.HTTPUnauthorized(request=req)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return SwiftAuth(app, conf)
    return auth_filter
