# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
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

"""Extensions supporting OAuth1."""

from __future__ import absolute_import

import abc

import oauth2 as oauth
import six

from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone import config
from keystone import exception


Consumer = oauth.Consumer
Request = oauth.Request
Server = oauth.Server
SignatureMethod = oauth.SignatureMethod
SignatureMethod_HMAC_SHA1 = oauth.SignatureMethod_HMAC_SHA1
SignatureMethod_PLAINTEXT = oauth.SignatureMethod_PLAINTEXT
Token = oauth.Token
Client = oauth.Client


CONF = config.CONF


EXTENSION_DATA = {
    'name': 'OpenStack OAUTH1 API',
    'namespace': 'http://docs.openstack.org/identity/api/ext/'
                 'OS-OAUTH1/v1.0',
    'alias': 'OS-OAUTH1',
    'updated': '2013-07-07T12:00:0-00:00',
    'description': 'OpenStack OAuth 1.0a Delegated Auth Mechanism.',
    'links': [
        {
            'rel': 'describedby',
            # TODO(dolph): link needs to be revised after
            #              bug 928059 merges
            'type': 'text/html',
            'href': 'https://github.com/openstack/identity-api',
        }
    ]}
extension.register_admin_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)
extension.register_public_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)


def filter_consumer(consumer_ref):
    """Filter out private items in a consumer dict.

    'secret' is never returned.

    :returns: consumer_ref

    """
    if consumer_ref:
        consumer_ref = consumer_ref.copy()
        consumer_ref.pop('secret', None)
    return consumer_ref


def filter_token(access_token_ref):
    """Filter out private items in an access token dict.

    'access_secret' is never returned.

    :returns: access_token_ref

    """
    if access_token_ref:
        access_token_ref = access_token_ref.copy()
        access_token_ref.pop('access_secret', None)
    return access_token_ref


def rebuild_url(path):
    endpoint = CONF.public_endpoint % CONF

    # allow a missing trailing slash in the config
    if endpoint[-1] != '/':
        endpoint += '/'

    url = endpoint + 'v3'
    return url + path


def get_oauth_headers(headers):
    parameters = {}

    # The incoming headers variable is your usual heading from context
    # In an OAuth signed req, where the oauth variables are in the header,
    # they with the key 'Authorization'.

    if headers and 'Authorization' in headers:
        # A typical value for Authorization is seen below
        # 'OAuth realm="", oauth_body_hash="2jm%3D", oauth_nonce="14475435"
        # along with other oauth variables, the 'OAuth ' part is trimmed
        # to split the rest of the headers.

        auth_header = headers['Authorization']
        # Check that the authorization header is OAuth.
        if auth_header[:6] == 'OAuth ':
            auth_header = auth_header[6:]
            # Get the parameters from the header.
            header_params = oauth.Request._split_header(auth_header)
            parameters.update(header_params)
            return parameters


@dependency.provider('oauth_api')
class Manager(manager.Manager):
    """Default pivot point for the OAuth1 backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.oauth1.driver)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for an OAuth1 driver."""

    @abc.abstractmethod
    def create_consumer(self, consumer_ref):
        """Create consumer.

        :param consumer_ref: consumer ref with consumer name
        :type consumer_ref: dict
        :returns: consumer_ref

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_consumer(self, consumer_id, consumer_ref):
        """Update consumer.

        :param consumer_id: id of consumer to update
        :type consumer_ref: string
        :param consumer_ref: new consumer ref with consumer name
        :type consumer_ref: dict
        :returns: consumer_ref

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_consumers(self):
        """List consumers.

        returns: list of consumers

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_consumer(self, consumer_id):
        """Get consumer, returns the consumer id (key)
        and description.

        :param consumer_id: id of consumer to get
        :type consumer_ref: string
        :returns: consumer_ref

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_consumer_with_secret(self, consumer_id):
        """Like get_consumer() but returned consumer_ref includes
        the consumer secret.

        Secrets should only be shared upon consumer creation; the
        consumer secret is required to verify incoming OAuth requests.

        :param consumer_id: id of consumer to get
        :type consumer_ref: string
        :returns: consumer_ref

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_consumer(self, consumer_id):
        """Delete consumer.

        :param consumer_id: id of consumer to get
        :type consumer_ref: string
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_access_tokens(self, user_id):
        """List access tokens.

        :param user_id: search for access tokens authorized by given user id
        :type user_id: string
        returns: list of access tokens the user has authorized

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_access_token(self, user_id, access_token_id):
        """Delete access token.

        :param user_id: authorizing user id
        :type user_id: string
        :param access_token_id: access token to delete
        :type access_token_id: string
        returns: None

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_request_token(self, consumer_id, requested_project,
                             request_token_duration):
        """Create request token.

        :param consumer_id: the id of the consumer
        :type consumer_id: string
        :param requested_project_id: requested project id
        :type requested_project_id: string
        :param request_token_duration: duration of request token
        :type request_token_duration: string
        returns: request_token_ref

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_request_token(self, request_token_id):
        """Get request token.

        :param request_token_id: the id of the request token
        :type request_token_id: string
        returns: request_token_ref

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_access_token(self, access_token_id):
        """Get access token.

        :param access_token_id: the id of the access token
        :type access_token_id: string
        returns: access_token_ref

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def authorize_request_token(self, request_id, user_id, role_ids):
        """Authorize request token.

        :param request_id: the id of the request token, to be authorized
        :type request_id: string
        :param user_id: the id of the authorizing user
        :type user_id: string
        :param role_ids: list of role ids to authorize
        :type role_ids: list
        returns: verifier

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_access_token(self, request_id, access_token_duration):
        """Create access token.

        :param request_id: the id of the request token, to be deleted
        :type request_id: string
        :param access_token_duration: duration of an access token
        :type access_token_duration: string
        returns: access_token_ref

        """
        raise exception.NotImplemented()
