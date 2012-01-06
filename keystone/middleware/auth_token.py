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

www-authenticate
    only used if this component is being used remotely

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

HTTP_X_TENANT
    *Deprecated* in favor of HTTP_X_TENANT_ID and HTTP_X_TENANT_NAME
    Keystone-assigned unique identifier, deprecated

HTTP_X_TENANT_ID
    Identity service managed unique identifier, string

HTTP_X_TENANT_NAME
    Unique tenant identifier, string

HTTP_X_USER
    *Deprecated* in favor of HTTP_X_USER_ID and HTTP_X_USER_NAME
    Unique user name, string

HTTP_X_USER_ID
    Identity-service managed unique identifier, string

HTTP_X_USER_NAME
    Unique user identifier, string

HTTP_X_ROLE
    *Deprecated* in favor of HTTP_X_ROLES
    This is being renamed, and the new header contains the same data.

HTTP_X_ROLES
    Comma delimited list of case-sensitive Roles

"""

from datetime import datetime
from dateutil import parser
import errno
import eventlet
from eventlet import wsgi
from httplib import HTTPException
import json
# memcache is imported in __init__ if memcache caching is configured
import logging
import os
from paste.deploy import loadapp
import time
import urllib
from urlparse import urlparse
from webob.exc import HTTPUnauthorized
from webob.exc import Request, Response

from keystone.common.bufferedhttp import http_connect_raw as http_connect

logger = logging.getLogger(__name__)  # pylint: disable=C0103

PROTOCOL_NAME = "Token Authentication"
# The time format of the 'expires' property of a token
EXPIRE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
MAX_CACHE_TIME = 86400


class ValidationFailed(Exception):
    pass


class TokenExpired(Exception):
    pass


class KeystoneUnreachable(Exception):
    pass


class AuthProtocol(object):
    """Auth Middleware that handles authenticating client calls"""

    # pylint: disable=W0613
    def _init_protocol_common(self, app, conf):
        """ Common initialization code

        When we eventually superclass this, this will be the superclass
        initialization code that applies to all protocols
        """
        logger.info("Starting the %s component", PROTOCOL_NAME)

        #if app is set, then we are in a WSGI pipeline and requests get passed
        # on to app. If it is not set, this component should forward requests

        # where to find the OpenStack service (if not in local WSGI chain)
        # these settings are only used if this component is acting as a proxy
        # and the OpenSTack service is running remotely
        self.service_protocol = conf.get('service_protocol', 'https')
        self.service_host = conf.get('service_host')
        service_port = conf.get('service_port')
        service_ids = conf.get('service_ids')
        self.service_id_querystring = ''
        if service_ids:
            self.service_id_querystring = '?HP-IDM-serviceId=%s' % \
                                (urllib.quote(service_ids))
        if service_port:
            self.service_port = int(service_port)
        self.service_url = '%s://%s:%s' % (self.service_protocol,
                                           self.service_host,
                                           self.service_port)
        self.service_timeout = conf.get('service_timeout', 30)
        # used to verify this component with the OpenStack service or PAPIAuth
        self.service_pass = conf.get('service_pass')

        # delay_auth_decision means we still allow unauthenticated requests
        # through and we let the downstream service make the final decision
        self.delay_auth_decision = int(conf.get('delay_auth_decision', 0))

    def _init_protocol(self, conf):
        """ Protocol specific initialization """

        # where to find the auth service (we use this to validate tokens)
        self.auth_host = conf.get('auth_host')
        self.auth_port = int(conf.get('auth_port'))
        self.auth_protocol = conf.get('auth_protocol', 'https')
        self.auth_timeout = float(conf.get('auth_timeout', 30))

        # where to tell clients to find the auth service (default to url
        # constructed based on endpoint we have for the service to use)
        self.auth_location = conf.get('auth_uri',
                                        "%s://%s:%s" % (self.auth_protocol,
                                        self.auth_host,
                                        self.auth_port))
        logger.debug("Authentication Service:%s", self.auth_location)

        # Credentials used to verify this component with the Auth service since
        # validating tokens is a privileged call
        self.admin_token = conf.get('admin_token')
        # Certificate file and key file used to authenticate with Keystone
        # server
        self.cert_file = conf.get('certfile', None)
        self.key_file = conf.get('keyfile', None)
        # Caching
        self.cache = conf.get('cache', None)
        self.memcache_hosts = conf.get('memcache_hosts', None)
        if self.memcache_hosts:
            if self.cache is None:
                self.cache = "keystone.cache"
        self.tested_for_osksvalidate = False
        self.last_test_for_osksvalidate = None
        self.osksvalidate = self._supports_osksvalidate()

    def __init__(self, app, conf):
        """ Common initialization code """
        #TODO(ziad): maybe we refactor this into a superclass
        # Defining instance variables here for improving pylint score
        # NOTE(salvatore-orlando): the following vars are assigned values
        # either in init_protocol or init_protocol_common. We should not
        # worry about them being initialized to None
        self.conf = conf
        self.app = app
        self.admin_password = None
        self.admin_token = None
        self.admin_user = None
        self.auth_api_version = None
        self.auth_host = None
        self.auth_location = None
        self.auth_port = None
        self.auth_protocol = None
        self.auth_timeout = None
        self.cert_file = None
        self.key_file = None
        self.delay_auth_decision = None
        self.service_pass = None
        self.service_host = None
        self.service_port = None
        self.service_protocol = None
        self.service_timeout = None
        self.service_url = None
        self.service_id_querystring = None
        self.osksvalidate = None
        self.tested_for_osksvalidate = None
        self.last_test_for_osksvalidate = None
        self.cache = None
        self.memcache_hosts = None
        self._init_protocol_common(app, conf)  # Applies to all protocols
        self._init_protocol(conf)  # Specific to this protocol

    def __call__(self, env, start_response):
        """ Handle incoming request. Authenticate. And send downstream. """
        logger.debug("entering AuthProtocol.__call__")
        # Initialize caching client
        if self.memcache_hosts:
            # This will only be used if the configuration calls for memcache
            import memcache

            if env.get(self.cache, None) is None:
                memcache_client = memcache.Client([self.memcache_hosts])
                env[self.cache] = memcache_client

        # Check if we're set up to use OS-KSVALIDATE periodically if not on
        if self.tested_for_osksvalidate != True:
            if self.last_test_for_osksvalidate is None or \
                    (time.time() - self.last_test_for_osksvalidate) > 60:
                # Try test again every 60 seconds if failed
                # this also handles if middleware was started before
                # the keystone server
                try:
                    self.osksvalidate = self._supports_osksvalidate()
                except (HTTPException, StandardError):
                    pass

        #Prep headers to forward request to local or remote downstream service
        proxy_headers = env.copy()
        for header in proxy_headers.iterkeys():
            if header[0:5] == 'HTTP_':
                proxy_headers[header[5:]] = proxy_headers[header]
                del proxy_headers[header]

        #Look for authentication claims
        token = self._get_claims(env)
        if not token:
            logger.debug("No claims provided")
            if self.delay_auth_decision:
                #Configured to allow downstream service to make final decision.
                #So mark status as Invalid and forward the request downstream
                logger.debug("delay_auth_decision is %s, so sending request "
                        "down the pipeline" % self.delay_auth_decision)
                self._decorate_request("X_IDENTITY_STATUS",
                    "Invalid", env, proxy_headers)
            else:
                #Respond to client as appropriate for this auth protocol
                return self._reject_request(env, start_response)
        else:
            # this request is presenting claims. Let's validate them
            try:
                claims = self._verify_claims(env, token)
            except (ValidationFailed, TokenExpired):
                # Keystone rejected claim
                if self.delay_auth_decision:
                    # Downstream service will receive call still and decide
                    self._decorate_request("X_IDENTITY_STATUS",
                        "Invalid", env, proxy_headers)
                else:
                    #Respond to client as appropriate for this auth protocol
                    return self._reject_claims(env, start_response)
            else:
                self._decorate_request("X_IDENTITY_STATUS",
                    "Confirmed", env, proxy_headers)

                # Store authentication data
                if claims:
                    self._decorate_request('X_AUTHORIZATION', "Proxy %s" %
                        claims['user']['name'], env, proxy_headers)

                    self._decorate_request('X_TENANT_ID',
                        claims['tenant']['id'], env, proxy_headers)
                    self._decorate_request('X_TENANT_NAME',
                        claims['tenant']['name'], env, proxy_headers)

                    self._decorate_request('X_USER_ID',
                        claims['user']['id'], env, proxy_headers)
                    self._decorate_request('X_USER_NAME',
                        claims['user']['name'], env, proxy_headers)

                    roles = ','.join(claims['roles'])
                    self._decorate_request('X_ROLES',
                        roles, env, proxy_headers)

                    # Deprecated in favor of X_TENANT_ID and _NAME
                    self._decorate_request('X_TENANT',
                        claims['tenant']['id'], env, proxy_headers)

                    # Deprecated in favor of X_USER_ID and _NAME
                    # TODO(zns): documentation says this should be the username
                    # the user logged in with. We've been returning the id...
                    self._decorate_request('X_USER',
                        claims['user']['id'], env, proxy_headers)

                    # Deprecated in favor of X_ROLES
                    self._decorate_request('X_ROLE',
                        roles, env, proxy_headers)

        #Send request downstream
        return self._forward_request(env, start_response, proxy_headers)

    @staticmethod
    def _convert_date(date):
        """ Convert datetime to unix timestamp for caching """
        return time.mktime(parser.parse(date).utctimetuple())

    # pylint: disable=W0613
    @staticmethod
    def _protect_claims(token, claims):
        """ encrypt or mac claims if necessary """
        return claims

    # pylint: disable=W0613
    @staticmethod
    def _unprotect_claims(token, pclaims):
        """ decrypt or demac claims if necessary """
        return pclaims

    def _cache_put(self, env, token, claims, valid):
        """ Put a claim into the cache """
        cache = self._cache(env)
        if cache and claims:
            key = 'tokens/%s' % (token)
            if "timeout" in cache.set.func_code.co_varnames:
                # swift cache
                expires = self._convert_date(claims['expires'])
                claims = self._protect_claims(token, claims)
                cache.set(key, (claims, expires, valid),
                             timeout=expires - time.time())
            else:
                # normal memcache client
                expires = self._convert_date(claims['expires'])
                timeout = expires - time.time()
                if timeout > MAX_CACHE_TIME or not valid:
                    # Limit cache to one day (and cache bad tokens for a day)
                    timeout = MAX_CACHE_TIME
                claims = self._protect_claims(token, claims)
                cache.set(key, (claims, expires, valid), time=timeout)

    def _cache_get(self, env, token):
        """ Return claim and relevant information (expiration and validity)
        from cache """
        cache = self._cache(env)
        if cache:
            key = 'tokens/%s' % (token)
            cached_claims = cache.get(key)
            if cached_claims:
                claims, expires, valid = cached_claims
                if valid:
                    if "timeout" in cache.set.func_code.co_varnames:
                        if expires > time.time():
                            claims = self._unprotect_claims(token, claims)
                    else:
                        if expires > time.time():
                            claims = self._unprotect_claims(token, claims)
                return (claims, expires, valid)
        return None

    def _cache(self, env):
        """ Return a cache to use for token caching, or none """
        if self.cache is not None:
            return env.get(self.cache, None)
        return None

    @staticmethod
    def _get_claims(env):
        """Get claims from request"""
        logger.debug("Looking for authentication claims in _get_claims")
        claims = env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN'))
        return claims

    def _reject_request(self, env, start_response):
        """Redirect client to auth server"""
        logger.debug("Rejecting request - authentication required")
        return HTTPUnauthorized("Authentication required",
                    [("WWW-Authenticate",
                      "Keystone uri='%s'" % self.auth_location)])(env,
                                                        start_response)

    @staticmethod
    def _reject_claims(env, start_response):
        """Client sent bad claims"""
        logger.debug("Rejecting request - bad claim or token")
        return HTTPUnauthorized()(env,
            start_response)

    def _verify_claims(self, env, claims):
        """Verify claims and extract identity information, if applicable."""

        cached_claims = self._cache_get(env, claims)
        if cached_claims:
            logger.debug("Found cached claims")
            claims, expires, valid = cached_claims
            if not valid:
                logger.debug("Claims not valid (according to cache)")
                raise ValidationFailed()
            if expires <= time.time():
                logger.debug("Claims (token) expired (according to cache)")
                raise TokenExpired()
            return claims

        # Step 1: We need to auth with the keystone service, so get an
        # admin token
        #TODO(ziad): Need to properly implement this, where to store creds
        # for now using token from ini
        #auth = self.get_admin_auth_token("admin", "secrete", "1")
        #admin_token = json.loads(auth)["auth"]["token"]["id"]

        # Step 2: validate the user's token with the auth service
        # since this is a priviledged op,m we need to auth ourselves
        # by using an admin token
        headers = {"Content-type": "application/json",
                    "Accept": "application/json",
                    "X-Auth-Token": self.admin_token}
        if self.osksvalidate:
            headers['X-Subject-Token'] = claims
            path = '/v2.0/OS-KSVALIDATE/token/validate/%s' % \
                   self.service_id_querystring
            logger.debug("Connecting to %s://%s:%s to check claims using the"
                      "OS-KSVALIDATE extension" % (self.auth_protocol,
                            self.auth_host, self.auth_port))
        else:
            path = '/v2.0/tokens/%s%s' % (claims, self.service_id_querystring)
            logger.debug("Connecting to %s://%s:%s to check claims" % (
                    self.auth_protocol, self.auth_host, self.auth_port))

        ##TODO(ziad):we need to figure out how to auth to keystone
        #since validate_token is a priviledged call
        #Khaled's version uses creds to get a token
        # "X-Auth-Token": admin_token}
        # we're using a test token from the ini file for now
        try:
            conn = http_connect(self.auth_host, self.auth_port, 'GET',
                                path,
                                headers=headers,
                                ssl=(self.auth_protocol == 'https'),
                                key_file=self.key_file,
                                cert_file=self.cert_file,
                                timeout=self.auth_timeout)
            resp = conn.getresponse()
            data = resp.read()
        except EnvironmentError as exc:
            if exc.errno == errno.ECONNREFUSED:
                logger.error("Keystone server not responding on %s://%s:%s "
                             "to check claims" % (self.auth_protocol,
                                                  self.auth_host,
                                                  self.auth_port))
                raise KeystoneUnreachable("Unable to connect to authentication"
                                          " server")
            else:
                logger.exception(exc)
                raise

        logger.debug("Response received: %s" % resp.status)
        if not str(resp.status).startswith('20'):
            # Cache it if there is a cache available
            if self.cache:
                logger.debug("Caching that results were invalid")
                self._cache_put(env, claims,
                                claims={'expires':
                                datetime.strftime(time.time(),
                                                  EXPIRE_TIME_FORMAT)},
                                valid=False)
            # Keystone rejected claim
            logger.debug("Failing the validation")
            raise ValidationFailed()

        token_info = json.loads(data)

        roles = [role['name'] for role in token_info[
            "access"]["user"]["roles"]]

        # in diablo, there were two ways to get tenant data
        tenant = token_info['access']['token'].get('tenant')
        if tenant:
            # post diablo
            tenant_id = tenant['id']
            tenant_name = tenant['name']
        else:
            # diablo only
            tenant_id = token_info['access']['user'].get('tenantId')
            tenant_name = token_info['access']['user'].get('tenantName')
        logger.debug("Tenant identified: id=%s, name=%s" % (tenant_id,
                                                                tenant_name))

        verified_claims = {
            'user': {
                'id': token_info['access']['user']['id'],
                'name': token_info['access']['user']['name'],
            },
            'tenant': {
                'id': tenant_id,
                'name': tenant_name
            },
            'roles': roles,
            'expires': token_info['access']['token']['expires']}
        logger.debug("User identified: id=%s, name=%s" % (
                token_info['access']['user']['id'],
                token_info['access']['user']['name']))

        expires = self._convert_date(verified_claims['expires'])
        if expires <= time.time():
            logger.debug("Claims (token) expired: %s" % str(expires))
            # Cache it if there is a cache available (we also cached bad
            # claims)
            if self.cache:
                logger.debug("Caching expired claim (token)")
                self._cache_put(env, claims, verified_claims, valid=False)
            raise TokenExpired()

        # Cache it if there is a cache available
        if self.cache:
            logger.debug("Caching validated claim")
            self._cache_put(env, claims, verified_claims, valid=True)
        logger.debug("Returning successful validation")
        return verified_claims

    @staticmethod
    def _decorate_request(index, value, env, proxy_headers):
        """Add headers to request"""
        logger.debug("Decorating request with HTTP_%s=%s" % (index, value))
        proxy_headers[index] = value
        env["HTTP_%s" % index] = value

    def _forward_request(self, env, start_response, proxy_headers):
        """Token/Auth processed & claims added to headers"""
        self._decorate_request('AUTHORIZATION',
            "Basic %s" % self.service_pass, env, proxy_headers)
        #now decide how to pass on the call
        if self.app:
            # Pass to downstream WSGI component
            logger.debug("Sending request to next app in WSGI pipeline")
            return self.app(env, start_response)
            #.custom_start_response)
        else:
            # We are forwarding to a remote service (no downstream WSGI app)
            logger.debug("Sending request to %s" % self.service_url)
            req = Request(proxy_headers)
            parsed = urlparse(req.url)

            # pylint: disable=E1101
            conn = http_connect(self.service_host,
                                self.service_port,
                                req.method,
                                parsed.path,
                                proxy_headers,
                                ssl=(self.service_protocol == 'https'),
                                timeout=self.service_timeout)
            resp = conn.getresponse()
            data = resp.read()
            logger.debug("Response was %s" % resp.status)

            #TODO(ziad): use a more sophisticated proxy
            # we are rewriting the headers now

            if resp.status in (401, 305):
                # Add our own headers to the list
                headers = [("WWW_AUTHENTICATE",
                   "Keystone uri='%s'" % self.auth_location)]
                return Response(status=resp.status, body=data,
                            headerlist=headers)(env,
                                                start_response)
            else:
                return Response(status=resp.status, body=data)(env,
                                                start_response)

    def _supports_osksvalidate(self):
        """Check if target Keystone server supports OS-KSVALIDATE."""
        if self.tested_for_osksvalidate:
            return self.osksvalidate

        headers = {"Accept": "application/json"}
        logger.debug("Connecting to %s://%s:%s to check extensions" % (
                self.auth_protocol, self.auth_host, self.auth_port))
        try:
            self.last_test_for_osksvalidate = time.time()
            conn = http_connect(self.auth_host, self.auth_port, 'GET',
                                '/v2.0/extensions/',
                                headers=headers,
                                ssl=(self.auth_protocol == 'https'),
                                key_file=self.key_file,
                                cert_file=self.cert_file,
                                timeout=self.auth_timeout)
            resp = conn.getresponse()
            data = resp.read()

            logger.debug("Response received: %s" % resp.status)
            if not str(resp.status).startswith('20'):
                logger.debug("Failed to detect extensions. "
                             "Falling back to core API")
                return False
        except EnvironmentError as exc:
            if exc.errno == errno.ECONNREFUSED:
                logger.warning("Keystone server not responding. Extension "
                            "detection will be retried later.")
            else:
                logger.exception("Unexpected error trying to detect "
                                 "extensions.")
            logger.debug("Falling back to core API behavior (using tokens in "
                         "URL)")
            return False
        except HTTPException as exc:
            logger.exception("Error trying to detect extensions.")
            logger.debug("Falling back to core API behavior (using tokens in "
                         "URL)")
            return False

        self.tested_for_osksvalidate = True
        return "OS-KSVALIDATE" in data


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(filteredapp):
        return AuthProtocol(filteredapp, conf)
    return auth_filter


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return AuthProtocol(None, conf)


def main():
    """Called when the middleware is started up separately (as in a remote
    proxy configuration)
    """
    config_file = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                     os.pardir,
                     os.pardir,
                    "examples/paste/auth_token.ini")
    logger.debug("Initializing with config file: %s" % config_file)
    wsgiapp = loadapp("config:%s" % config_file,
                    global_conf={"log_name": "auth_token.log"})
    wsgi.server(eventlet.listen(('', 8090)), wsgiapp)


if __name__ == "__main__":
    main()
