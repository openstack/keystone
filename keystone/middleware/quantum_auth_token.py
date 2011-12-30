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

This WSGI component performs multiple jobs:

- it verifies that incoming client requests have valid tokens by verifying
  tokens with the auth service.
- it will reject unauthenticated requests UNLESS it is in 'delay_auth_decision'
  mode, which means the final decision is delegated to the downstream WSGI
  component (usually the OpenStack service)
- it will collect and forward identity information from a valid token
  such as user name, groups, etc...

Refer to: http://wiki.openstack.org/openstack-authn

This WSGI component has been derived from Keystone's auth_token
middleware module. It contains some specialization for Quantum.

HEADERS
=======

Headers starting with ``HTTP_`` is a standard http header
Headers starting with ``HTTP_X`` is an extended http header

Coming in from initial call from client or customer
---------------------------------------------------

HTTP_X_AUTH_TOKEN
    The client token being passed in

HTTP_X_STORAGE_TOKEN
    The client token being passed in (legacy Rackspace use) to support
    cloud files

Used for communication between components
-----------------------------------------

www-Authenticate
    Only used if this component is being used remotely

HTTP_AUTHORIZATION
    Basic auth password used to validate the connection

What we add to the request for use by the OpenStack service
-----------------------------------------------------------

HTTP_X_AUTHORIZATION
    The client identity being passed in

"""

import httplib
import json
import logging
import urllib
from urlparse import urlparse
from webob.exc import HTTPUnauthorized, Request, Response

from keystone.common.bufferedhttp import http_connect_raw as http_connect

PROTOCOL_NAME = "Quantum Token Authentication"
logger = logging.getLogger(__name__)  # pylint: disable=C0103


# pylint: disable=R0902
class AuthProtocol(object):
    """Auth Middleware that handles authenticating client calls"""

    def _init_protocol_common(self, app, conf):
        """ Common initialization code"""
        logger.info("Starting the %s component", PROTOCOL_NAME)

        self.conf = conf
        self.app = app
        #if app is set, then we are in a WSGI pipeline and requests get passed
        # on to app. If it is not set, this component should forward requests

        # where to find the Quantum service (if not in local WSGI chain)
        # these settings are only used if this component is acting as a proxy
        # and the OpenSTack service is running remotely
        if not self.app:
            self.service_protocol = conf.get('quantum_protocol', 'https')
            self.service_host = conf.get('quantum_host')
            self.service_port = int(conf.get('quantum_port'))
            self.service_url = '%s://%s:%s' % (self.service_protocol,
                                           self.service_host,
                                           self.service_port)

        # delay_auth_decision means we still allow unauthenticated requests
        # through and we let the downstream service make the final decision
        self.delay_auth_decision = int(conf.get('delay_auth_decision', 0))

    def _init_protocol(self, _app, conf):
        """ Protocol specific initialization """

        # where to find the auth service (we use this to validate tokens)
        self.auth_host = conf.get('auth_host')
        self.auth_port = int(conf.get('auth_port'))
        self.auth_protocol = conf.get('auth_protocol', 'http')
        self.cert_file = conf.get('certfile', None)
        self.key_file = conf.get('keyfile', None)
        self.auth_timeout = conf.get('auth_timeout', 30)
        self.auth_api_version = conf.get('auth_version', '2.0')
        self.auth_location = "%s://%s:%s" % (self.auth_protocol,
                                             self.auth_host,
                                             self.auth_port)
        self.auth_uri = conf.get('auth_uri', self.auth_location)
        logger.debug("Authentication Service:%s", self.auth_location)
        # Credentials used to verify this component with the Auth service
        # since validating tokens is a privileged call
        self.admin_user = conf.get('auth_admin_user')
        self.admin_password = conf.get('auth_admin_password')
        self.admin_token = conf.get('auth_admin_token')
        # bind to one or more service instances
        service_ids = conf.get('service_ids')
        self.serviceId_qs = ''
        if service_ids:
            self.serviceId_qs = '?HP-IDM-serviceId=%s' % \
                                (urllib.quote(service_ids))

    def _build_token_uri(self, claims=None):
        claim_str = "/%s" % claims if claims else ""
        return "/v%s/tokens%s%s" % (self.auth_api_version, claim_str,
                                    self.serviceId_qs or '')

    def __init__(self, app, conf):
        """ Common initialization code """
        # Defining instance variables here for improving pylint score
        # NOTE(salvatore-orlando): the following vars are assigned values
        # either in init_protocol or init_protocol_common. We should not
        # worry about them being initialized to None
        self.admin_password = None
        self.admin_token = None
        self.admin_user = None
        self.auth_api_version = None
        self.auth_host = None
        self.auth_location = None
        self.auth_uri = None
        self.auth_port = None
        self.auth_protocol = None
        self.auth_timeout = None
        self.cert_file = None
        self.key_file = None
        self.service_host = None
        self.service_port = None
        self.service_protocol = None
        self.service_url = None
        self.proxy_headers = None
        self.start_response = None
        self.app = None
        self.conf = None
        self.env = None
        self.delay_auth_decision = None
        self.expanded = None
        self.claims = None

        self._init_protocol_common(app, conf)  # Applies to all protocols
        self._init_protocol(app, conf)  # Specific to this protocol

    # pylint: disable=R0912
    def __call__(self, env, start_response):
        """ Handle incoming request. Authenticate. And send downstream. """
        logger.debug("entering AuthProtocol.__call__")
        logger.debug("start response:%s", start_response)
        self.start_response = start_response
        self.env = env

        #Prep headers to forward request to local or remote downstream service
        self.proxy_headers = env.copy()
        for header in self.proxy_headers.iterkeys():
            if header[0:5] == 'HTTP_':
                self.proxy_headers[header[5:]] = self.proxy_headers[header]
                del self.proxy_headers[header]

        #Look for authentication claims
        logger.debug("Looking for authentication claims")
        self.claims = self._get_claims(env)
        if not self.claims:
            #No claim(s) provided
            logger.debug("No claims provided")
            if self.delay_auth_decision:
                #Configured to allow downstream service to make final decision.
                #So mark status as Invalid and forward the request downstream
                self._decorate_request("X_IDENTITY_STATUS", "Invalid")
            else:
                #Respond to client as appropriate for this auth protocol
                return self._reject_request()
        else:
            # this request is presenting claims. Let's validate them
            logger.debug("Claims found. Validating.")
            valid = self._validate_claims(self.claims)
            if not valid:
                # Keystone rejected claim
                if self.delay_auth_decision:
                    # Downstream service will receive call still and decide
                    self._decorate_request("X_IDENTITY_STATUS", "Invalid")
                else:
                    #Respond to client as appropriate for this auth protocol
                    return self._reject_claims()
            else:
                self._decorate_request("X_IDENTITY_STATUS", "Confirmed")

            #Collect information about valid claims
            if valid:
                logger.debug("Validation successful")
                claims = self._expound_claims()

                # Store authentication data
                if claims:
                    # TODO(Ziad): add additional details we may need,
                    #             like tenant and group info
                    self._decorate_request('X_AUTHORIZATION', "Proxy %s" %
                        claims['user'])

                    self._decorate_request('X_TENANT_ID',
                                        claims['tenant']['id'],)
                    self._decorate_request('X_TENANT_NAME',
                                        claims['tenant']['name'])

                    self._decorate_request('X_USER_ID',
                                        claims['user']['id'])
                    self._decorate_request('X_USER_NAME',
                                        claims['user']['name'])

                    self._decorate_request('X_TENANT', claims['tenant']['id'])
                    self._decorate_request('X_USER', claims['user']['id'])

                    if 'group' in claims:
                        self._decorate_request('X_GROUP', claims['group'])
                    if 'roles' in claims and len(claims['roles']) > 0:
                        if claims['roles'] is not None:
                            roles = ''
                            for role in claims['roles']:
                                if len(roles) > 0:
                                    roles += ','
                                roles += role
                            self._decorate_request('X_ROLE', roles)

                    # NOTE(todd): unused
                    self.expanded = True
            logger.debug("About to forward request")
            #Send request downstream
            return self._forward_request()

    # NOTE(salvatore-orlando): this function is now used again
    def get_admin_auth_token(self, username, password):
        """
        This function gets an admin auth token to be used by this service to
        validate a user's token. Validate_token is a priviledged call so
        it needs to be authenticated by a service that is calling it
        """
        headers = {
            "Content-type": "application/json",
            "Accept": "application/json"}
        params = {
                  "auth":
                  {
                   "passwordCredentials":
                   {
                    "username": username,
                    "password": password
                    }
                   }
                  }
        if self.auth_protocol == "http":
            conn = httplib.HTTPConnection(self.auth_host, self.auth_port)
        else:
            conn = httplib.HTTPSConnection(self.auth_host, self.auth_port,
                cert_file=self.cert_file)
        conn.request("POST", self._build_token_uri(), json.dumps(params), \
            headers=headers)
        response = conn.getresponse()
        data = response.read()
        return data

    @staticmethod
    def _get_claims(env):
        """Get claims from request"""
        claims = env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN'))
        return claims

    def _reject_request(self):
        """Redirect client to auth server"""
        return HTTPUnauthorized("Authentication required",
                    [("WWW-Authenticate",
                      "Keystone uri='%s'" % self.auth_uri)])(self.env,
                                                        self.start_response)

    def _reject_claims(self):
        """Client sent bad claims"""
        return HTTPUnauthorized()(self.env, self.start_response)

    def _validate_claims(self, claims, retry=False):
        """Validate claims, and provide identity information if applicable """

        # Step 1: We need to auth with the keystone service, so get an
        # admin token
        # TODO(ziad): Need to properly implement this, where to store creds
        # for now using token from ini
        # NOTE(salvatore-orlando): Temporarily restoring auth token retrieval,
        # with credentials in configuration file
        if not self.admin_token:
            auth = self.get_admin_auth_token(self.admin_user,
                                             self.admin_password)
            self.admin_token = json.loads(auth)["access"]["token"]["id"]

        # Step 2: validate the user's token with the auth service
        # since this is a priviledged op,m we need to auth ourselves
        # by using an admin token
        headers = {"Content-type": "application/json",
                    "Accept": "application/json",
                    "X-Auth-Token": self.admin_token}
        conn = http_connect(self.auth_host, self.auth_port, 'GET',
                            self._build_token_uri(claims), headers=headers,
                            ssl=(self.auth_protocol == 'https'),
                            key_file=self.key_file, cert_file=self.cert_file,
                            timeout=self.auth_timeout)
        resp = conn.getresponse()
        # pylint: disable=E1103
        conn.close()

        if not str(resp.status).startswith('20'):
            # Keystone rejected claim
            # In case a 404 error it might just be that the token has expired
            # Therefore try and get a new token
            # of course assuming admin credentials have been specified
            # Note(salvatore-orlando): the 404 here is not really
            # what should be returned
            if self.admin_user and self.admin_password and \
               not retry and str(resp.status) == '404':
                logger.warn("Unable to validate token." +
                         "Admin token possibly expired.")
                self.admin_token = None
                return self._validate_claims(claims, True)
            return False
        else:
            #TODO(Ziad): there is an optimization we can do here. We have just
            #received data from Keystone that we can use instead of making
            #another call in _expound_claims
            logger.info("Claims successfully validated")
            return True

    def _expound_claims(self):
        # Valid token. Get user data and put it in to the call
        # so the downstream service can use it
        headers = {"Content-type": "application/json",
                    "Accept": "application/json",
                    "X-Auth-Token": self.admin_token}
        conn = http_connect(self.auth_host, self.auth_port, 'GET',
                            self._build_token_uri(self.claims),
                            headers=headers,
                            ssl=(self.auth_protocol == 'https'),
                            key_file=self.key_file, cert_file=self.cert_file,
                            timeout=self.auth_timeout)
        resp = conn.getresponse()
        data = resp.read()
        # pylint: disable=E1103
        conn.close()

        if not str(resp.status).startswith('20'):
            raise LookupError('Unable to locate claims: %s' % resp.status)

        token_info = json.loads(data)
        #TODO(Ziad): make this more robust
        #first_group = token_info['auth']['user']['groups']['group'][0]
        roles = []
        rolegrants = token_info["access"]["user"]["roles"]
        if rolegrants is not None:
            roles = [rolegrant["id"] for rolegrant in rolegrants]

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

        verified_claims = {
            'user': {
                'id': token_info['access']['user']['id'],
                'name': token_info['access']['user']['name'],
            },
            'tenant': {
                'id': tenant_id,
                'name': tenant_name
            },
            'roles': roles}

        return verified_claims

    def _decorate_request(self, index, value):
        """Add headers to request"""
        self.proxy_headers[index] = value
        self.env["HTTP_%s" % index] = value

    def _forward_request(self):
        """Token/Auth processed & claims added to headers"""
        #now decide how to pass on the call
        if self.app:
            # Pass to downstream WSGI component
            return self.app(self.env, self.start_response)
            #.custom_start_response)
        else:
            # We are forwarding to a remote service (no downstream WSGI app)
            req = Request(self.proxy_headers)
            # pylint: disable=E1101
            parsed = urlparse(req.url)
            conn = http_connect(self.service_host,
                                self.service_port,
                                req.method,
                                parsed.path,
                                self.proxy_headers,
                                ssl=(self.service_protocol == 'https'))
            resp = conn.getresponse()
            data = resp.read()
            return Response(status=resp.status, body=data)(self.proxy_headers,
                                                           self.start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(application):
        return AuthProtocol(application, conf)
    return auth_filter


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return AuthProtocol(None, conf)
