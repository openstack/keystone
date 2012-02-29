# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010-2012 OpenStack LLC
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
TOKEN-BASED AUTH MIDDLEWARE

This WSGI component:

* Verifies that incoming client requests have valid tokens by validating
  tokens with the auth service.
* Rejects unauthenticated requests UNLESS it is in 'delay_auth_decision'
  mode, which means the final decision is delegated to the downstream WSGI
  component (usually the OpenStack service)
* Collects and forwards identity information based on a valid token
  such as user name, tenant, etc

Refer to: http://keystone.openstack.org/middleware_architecture.html

HEADERS
-------

* Headers starting with HTTP\_ is a standard http header
* Headers starting with HTTP_X is an extended http header

Coming in from initial call from client or customer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HTTP_X_AUTH_TOKEN
    The client token being passed in.

HTTP_X_STORAGE_TOKEN
    The client token being passed in (legacy Rackspace use) to support
    swift/cloud files

Used for communication between components
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

WWW-Authenticate
    HTTP header returned to a user indicating which endpoint to use
    to retrieve a new token

HTTP_AUTHORIZATION
    basic auth password used to validate the connection

What we add to the request for use by the OpenStack service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HTTP_X_AUTHORIZATION
    The client identity being passed in

HTTP_X_IDENTITY_STATUS
    'Confirmed' or 'Invalid'
    The underlying service will only see a value of 'Invalid' if the Middleware
    is configured to run in 'delay_auth_decision' mode

HTTP_X_TENANT_ID
    Identity service managed unique identifier, string

HTTP_X_TENANT_NAME
    Unique tenant identifier, string

HTTP_X_USER_ID
    Identity-service managed unique identifier, string

HTTP_X_USER_NAME
    Unique user identifier, string

HTTP_X_ROLES
    Comma delimited list of case-sensitive Roles

HTTP_X_TENANT
    *Deprecated* in favor of HTTP_X_TENANT_ID and HTTP_X_TENANT_NAME
    Keystone-assigned unique identifier, deprecated

HTTP_X_USER
    *Deprecated* in favor of HTTP_X_USER_ID and HTTP_X_USER_NAME
    Unique user name, string

HTTP_X_ROLE
    *Deprecated* in favor of HTTP_X_ROLES
    This is being renamed, and the new header contains the same data.

"""

import httplib
import json
import logging

import webob
import webob.exc


logger = logging.getLogger('keystone.middleware.auth_token')


class InvalidUserToken(Exception):
    pass


class ServiceError(Exception):
    pass


class AuthProtocol(object):
    """Auth Middleware that handles authenticating client calls."""

    def __init__(self, app, conf):
        logger.info('Starting keystone auth_token middleware')
        self.conf = conf
        self.app = app

        # delay_auth_decision means we still allow unauthenticated requests
        # through and we let the downstream service make the final decision
        self.delay_auth_decision = int(conf.get('delay_auth_decision', 0))

        # where to find the auth service (we use this to validate tokens)
        self.auth_host = conf.get('auth_host')
        self.auth_port = int(conf.get('auth_port'))

        auth_protocol = conf.get('auth_protocol', 'https')
        if auth_protocol == 'http':
            self.http_client_class = httplib.HTTPConnection
        else:
            self.http_client_class = httplib.HTTPSConnection

        default_auth_uri = '%s://%s:%s' % (auth_protocol,
                                           self.auth_host,
                                           self.auth_port)
        self.auth_uri = conf.get('auth_uri', default_auth_uri)

        # Credentials used to verify this component with the Auth service since
        # validating tokens is a privileged call
        self.admin_token = conf.get('admin_token')
        self.admin_user = conf.get('admin_user')
        self.admin_password = conf.get('admin_password')
        self.admin_tenant_name = conf.get('admin_tenant_name', 'admin')

    def __call__(self, env, start_response):
        """Handle incoming request.

        Authenticate send downstream on success. Reject request if
        we can't authenticate.

        """
        logger.debug('Authenticating user token')
        try:
            self._remove_auth_headers(env)
            user_token = self._get_user_token_from_header(env)
            token_info = self._validate_user_token(user_token)
            user_headers = self._build_user_headers(token_info)
            self._add_headers(env, user_headers)
            return self.app(env, start_response)

        except InvalidUserToken:
            if self.delay_auth_decision:
                logger.info('Invalid user token - deferring reject downstream')
                self._add_headers(env, {'X-Identity-Status': 'Invalid'})
                return self.app(env, start_response)
            else:
                logger.info('Invalid user token - rejecting request')
                return self._reject_request(env, start_response)

        except ServiceError, e:
            logger.critical('Unable to obtain admin token: %s' % e)
            resp = webob.exc.HTTPServiceUnavailable()
            return resp(env, start_response)

    def _remove_auth_headers(self, env):
        """Remove headers so a user can't fake authentication.

        :param env: wsgi request environment

        """
        auth_headers = (
            'X-Identity-Status',
            'X-Tenant-Id',
            'X-Tenant-Name',
            'X-User-Id',
            'X-User-Name',
            'X-Roles',
            # Deprecated
            'X-User',
            'X-Tenant',
            'X-Role',
        )
        logger.debug('Removing headers from request environment: %s' %
                     ','.join(auth_headers))
        self._remove_headers(env, auth_headers)

    def _get_user_token_from_header(self, env):
        """Get token id from request.

        :param env: wsgi request environment
        :return token id
        :raises InvalidUserToken if no token is provided in request

        """
        token = self._get_header(env, 'X-Auth-Token',
                                 self._get_header(env, 'X-Storage-Token'))
        if token:
            return token
        else:
            raise InvalidUserToken('Unable to find token in headers')

    def _reject_request(self, env, start_response):
        """Redirect client to auth server.

        :param env: wsgi request environment
        :param start_response: wsgi response callback
        :returns HTTPUnauthorized http response

        """
        headers = [('WWW-Authenticate', 'Keystone uri=\'%s\'' % self.auth_uri)]
        resp = webob.exc.HTTPUnauthorized('Authentication required', headers)
        return resp(env, start_response)

    def get_admin_token(self):
        """Return admin token, possibly fetching a new one.

        :return admin token id
        :raise ServiceError when unable to retrieve token from keystone

        """
        if not self.admin_token:
            self.admin_token = self._request_admin_token()

        return self.admin_token

    def _get_http_connection(self):
        return self.http_client_class(self.auth_host, self.auth_port)

    def _json_request(self, method, path, body=None, additional_headers=None):
        """HTTP request helper used to make json requests.

        :param method: http method
        :param path: relative request url
        :param body: dict to encode to json as request body. Optional.
        :param additional_headers: dict of additional headers to send with
                                   http request. Optional.
        :return (http response object, response body parsed as json)
        :raise ServerError when unable to communicate with keystone

        """
        conn = self._get_http_connection()

        kwargs = {
            'headers': {
                'Content-type': 'application/json',
                'Accept': 'application/json',
            },
        }

        if additional_headers:
            kwargs['headers'].update(additional_headers)

        if body:
            kwargs['body'] = json.dumps(body)

        try:
            conn.request(method, path, **kwargs)
            response = conn.getresponse()
            body = response.read()
            data = json.loads(body)
        except Exception, e:
            logger.error('HTTP connection exception: %s' % e)
            raise ServiceError('Unable to communicate with keystone')
        finally:
            conn.close()

        return response, data

    def _request_admin_token(self):
        """Retrieve new token as admin user from keystone.

        :return token id upon success
        :raises ServerError when unable to communicate with keystone

        """
        params = {
            'auth': {
                'passwordCredentials': {
                    'username': self.admin_user,
                    'password': self.admin_password,
                },
                'tenantName': self.admin_tenant_name,
            }
        }

        response, data = self._json_request('POST',
                                            '/v2.0/tokens',
                                            body=params)

        try:
            token = data['access']['token']['id']
            assert token
            return token
        except (AssertionError, KeyError):
            raise ServiceError('invalid json response')

    def _validate_user_token(self, user_token, retry=True):
        """Authenticate user token with keystone.

        :param user_token: user's token id
        :param retry: flag that forces the middleware to retry
                      user authentication when an indeterminate
                      response is received. Optional.
        :return token object received from keystone on success
        :raise InvalidUserToken if token is rejected
        :raise ServiceError if unable to authenticate token

        """
        headers = {'X-Auth-Token': self.get_admin_token()}
        response, data = self._json_request('GET',
                                            '/v2.0/tokens/%s' % user_token,
                                            additional_headers=headers)

        if response.status == 200:
            return data
        if response.status == 404:
            # FIXME(ja): I'm assuming the 404 status means that user_token is
            #            invalid - not that the admin_token is invalid
            raise InvalidUserToken('Token authorization failed')
        if response.status == 401:
            logger.info('Keystone rejected admin token, resetting')
            self.admin_token = None
        else:
            logger.error('Bad response code while validating token: %s' %
                         response.status)
        if retry:
            logger.info('Retrying validation')
            return self._validate_user_token(user_token, False)
        else:
            raise InvalidUserToken()

    def _build_user_headers(self, token_info):
        """Convert token object into headers.

        Build headers that represent authenticated user:
         * X_IDENTITY_STATUS: Confirmed or Invalid
         * X_TENANT_ID: id of tenant if tenant is present
         * X_TENANT_NAME: name of tenant if tenant is present
         * X_USER_ID: id of user
         * X_USER_NAME: name of user
         * X_ROLES: list of roles

        Additional (deprecated) headers include:
         * X_USER: name of user
         * X_TENANT: For legacy compatibility before we had ID and Name
         * X_ROLE: list of roles

        :param token_info: token object returned by keystone on authentication
        :raise InvalidUserToken when unable to parse token object

        """
        user = token_info['access']['user']
        token = token_info['access']['token']
        roles = ','.join([role['name'] for role in user.get('roles', [])])

        # FIXME(ja): I think we are checking in both places because:
        # tenant might not be returned, and there was a pre-release
        # that put tenant objects inside the user object?
        try:
            tenant_id = token['tenant']['id']
            tenant_name = token['tenant']['name']
        except:
            tenant_id = user.get('tenantId')
            tenant_name = user.get('tenantName')

        user_id = user['id']
        user_name = user['username']

        return {
            'X-Identity-Status': 'Confirmed',
            'X-Tenant-Id': tenant_id,
            'X-Tenant-Name': tenant_name,
            'X-User-Id': user_id,
            'X-User-Name': user_name,
            'X-Roles': roles,
            # Deprecated
            'X-User': user_name,
            'X-Tenant': tenant_name,
            'X-Role': roles,
        }

    def _header_to_env_var(self, key):
        """Convert header to wsgi env variable.

        :param key: http header name (ex. 'X-Auth-Token')
        :return wsgi env variable name (ex. 'HTTP_X_AUTH_TOKEN')

        """
        return  'HTTP_%s' % key.replace('-', '_').upper()

    def _add_headers(self, env, headers):
        """Add http headers to environment."""
        for (k, v) in headers.iteritems():
            env_key = self._header_to_env_var(k)
            env[env_key] = v

    def _remove_headers(self, env, keys):
        """Remove http headers from environment."""
        for k in keys:
            env_key = self._header_to_env_var(k)
            try:
                del env[env_key]
            except KeyError:
                pass

    def _get_header(self, env, key, default=None):
        """Get http header from environment."""
        env_key = self._header_to_env_var(key)
        return env.get(env_key, default)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return AuthProtocol(app, conf)
    return auth_filter


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return AuthProtocol(None, conf)
