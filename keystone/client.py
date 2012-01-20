# Copyright (C) 2011 OpenStack LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Python HTTP clients for accessing Keystone's Service and Admin APIs."""

import httplib
import json
import logging

import keystone.common.exception

LOG = logging.getLogger(__name__)


class ServiceClient(object):
    """Keystone v2.0 HTTP API client for normal service function.

    Provides functionality for retrieving new tokens and for retrieving
    a list of tenants which the supplied token has access to.

    """

    _default_port = 5000

    def __init__(self, host, port=None, is_ssl=False, cert_file=None):
        """Initialize client.

        :param host: The hostname or IP of the Keystone service to use
        :param port: The port of the Keystone service to use

        """
        self.host = host
        self.port = port or self._default_port
        self.is_ssl = is_ssl
        self.cert_file = cert_file

    def _http_request(self, verb, path, body=None, headers=None):
        """Perform an HTTP request and return the HTTP response.

        :param verb: HTTP verb (e.g. GET, POST, etc.)
        :param path: HTTP path (e.g. /v2.0/tokens)
        :param body: HTTP Body content
        :param headers: Dictionary of HTTP headers
        :returns: httplib.HTTPResponse object

        """
        LOG.debug("Connecting to %s" % self.auth_address)
        if (self.is_ssl):
            connection = httplib.HTTPSConnection(self.auth_address,
                                                 cert_file=self.cert_file)
        else:
            connection = httplib.HTTPConnection(self.auth_address)
        connection.request(verb, path, body=body, headers=headers)
        response = connection.getresponse()
        response.body = response.read()
        status_int = int(response.status)
        connection.close()

        if status_int < 200 or status_int >= 300:
            msg = "Client received HTTP %d" % status_int
            raise keystone.common.exception.ClientError(msg)

        return response

    @property
    def auth_address(self):
        """Return a host:port combination string."""
        return "%s:%d" % (self.host, self.port)

    def get_token(self, username, password):
        """Retrieve a token from Keystone for a given user/password.

        :param username: The user name to authenticate with
        :param password: The password to authenticate with
        :returns: A string token

        """
        body = json.dumps({
            "auth": {
                "passwordCredentials": {
                    "username": username,
                    "password": password,
                },
            },
        })

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        response = self._http_request("POST", "/v2.0/tokens", body, headers)
        token_id = json.loads(response.body)["access"]["token"]["id"]

        return token_id


class AdminClient(ServiceClient):
    """Keystone v2.0 HTTP API client for administrative functions.

    Provides functionality for retrieving new tokens, validating existing
    tokens, and retrieving user information from valid tokens.

    """

    _default_port = 35357
    _default_admin_name = "admin"
    _default_admin_pass = "password"

    # pylint: disable=R0913
    def __init__(self, host, port=None, is_ssl=False, cert_file=None,
                 admin_name=None, admin_pass=None):
        """Initialize client.

        :param host: The hostname or IP of the Keystone service to use
        :param port: The port of the Keystone service to use
        :param admin_name: The username to use for admin purposes
        :param admin_pass: The password to use for the admin account

        """
        super(AdminClient, self).__init__(host, port=port, is_ssl=is_ssl,
                                          cert_file=cert_file)
        self.admin_name = admin_name or self._default_admin_name
        self.admin_pass = admin_pass or self._default_admin_pass
        self._admin_token = None

    @property
    def admin_token(self):
        """Retrieve a valid admin token.

        If a token has already been retrieved, ensure that it is still valid
        and then return it. If it has not already been retrieved or the token
        is found to be invalid, retrieve a new token and return it.

        """
        token = self._admin_token

        if token is None or not self.check_token(token, token):
            token = self.get_token(self.admin_name, self.admin_pass)

        self._admin_token = token
        return self._admin_token

    def validate_token(self, token):
        """Validate a token, returning details about the user.

        :param token: A token string
        :returns: Object representing the user the token belongs to, or None
                  if the token is not valid.

        """
        url = "/v2.0/tokens/%s" % token

        headers = {
            "Accept": "application/json",
            "X-Auth-Token": self.admin_token,
        }

        try:
            response = self._http_request("GET", url, headers=headers)
        except keystone.common.exception.ClientError:
            return None

        return json.loads(response.body)

    def check_token(self, token, admin_token=None):
        """Check to see if given token is valid.

        :param token: A token string
        :param admin_token: The administrative token to use
        :returns: True if token is valid, otherwise False

        """
        url = "/v2.0/tokens/%s" % token
        headers = {"X-Auth-Token": admin_token or self.admin_token}

        try:
            self._http_request("HEAD", url, headers=headers)
        except keystone.common.exception.ClientError:
            return False

        return True
