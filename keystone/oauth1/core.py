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

"""Main entry point into the OAuth1 service."""

from __future__ import absolute_import

import uuid

import oauthlib.common
from oauthlib import oauth1
from oslo_config import cfg
from oslo_log import log
from oslo_log import versionutils

from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone import exception
from keystone.i18n import _LE
from keystone import notifications
from keystone.oauth1.backends import base


RequestValidator = oauth1.RequestValidator
Client = oauth1.Client
AccessTokenEndpoint = oauth1.AccessTokenEndpoint
ResourceEndpoint = oauth1.ResourceEndpoint
AuthorizationEndpoint = oauth1.AuthorizationEndpoint
SIG_HMAC = oauth1.SIGNATURE_HMAC
RequestTokenEndpoint = oauth1.RequestTokenEndpoint
oRequest = oauthlib.common.Request


class Token(object):
    def __init__(self, key, secret):
        self.key = key
        self.secret = secret
        self.verifier = None

    def set_verifier(self, verifier):
        self.verifier = verifier


CONF = cfg.CONF
LOG = log.getLogger(__name__)


def token_generator(*args, **kwargs):
    return uuid.uuid4().hex


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
            'type': 'text/html',
            'href': 'http://specs.openstack.org/openstack/keystone-specs/api/'
                    'v3/identity-api-v3-os-oauth1-ext.html',
        }
    ]}
extension.register_admin_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)
extension.register_public_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)


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
        params = oauth1.rfc5849.utils.parse_authorization_header(auth_header)
        parameters.update(dict(params))
        return parameters
    else:
        msg = _LE('Cannot retrieve Authorization headers')
        LOG.error(msg)
        raise exception.OAuthHeadersMissingError()


def extract_non_oauth_params(query_string):
    params = oauthlib.common.extract_params(query_string)
    return {k: v for k, v in params if not k.startswith('oauth_')}


@dependency.provider('oauth_api')
class Manager(manager.Manager):
    """Default pivot point for the OAuth1 backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.oauth1'

    _ACCESS_TOKEN = "OS-OAUTH1:access_token"
    _REQUEST_TOKEN = "OS-OAUTH1:request_token"
    _CONSUMER = "OS-OAUTH1:consumer"

    def __init__(self):
        super(Manager, self).__init__(CONF.oauth1.driver)

    def create_consumer(self, consumer_ref, initiator=None):
        consumer_ref = consumer_ref.copy()
        consumer_ref['secret'] = uuid.uuid4().hex
        ret = self.driver.create_consumer(consumer_ref)
        notifications.Audit.created(self._CONSUMER, ret['id'], initiator)
        return ret

    def update_consumer(self, consumer_id, consumer_ref, initiator=None):
        ret = self.driver.update_consumer(consumer_id, consumer_ref)
        notifications.Audit.updated(self._CONSUMER, consumer_id, initiator)
        return ret

    def delete_consumer(self, consumer_id, initiator=None):
        ret = self.driver.delete_consumer(consumer_id)
        notifications.Audit.deleted(self._CONSUMER, consumer_id, initiator)
        return ret

    def create_access_token(self, request_id, access_token_duration,
                            initiator=None):
        ret = self.driver.create_access_token(request_id,
                                              access_token_duration)
        notifications.Audit.created(self._ACCESS_TOKEN, ret['id'], initiator)
        return ret

    def delete_access_token(self, user_id, access_token_id, initiator=None):
        ret = self.driver.delete_access_token(user_id, access_token_id)
        notifications.Audit.deleted(self._ACCESS_TOKEN, access_token_id,
                                    initiator)
        return ret

    def create_request_token(self, consumer_id, requested_project,
                             request_token_duration, initiator=None):
        ret = self.driver.create_request_token(
            consumer_id, requested_project, request_token_duration)
        notifications.Audit.created(self._REQUEST_TOKEN, ret['id'],
                                    initiator)
        return ret


@versionutils.deprecated(
    versionutils.deprecated.NEWTON,
    what='keystone.oauth1.Oauth1DriverV8',
    in_favor_of='keystone.oauth1.backends.base.Oauth1DriverV8',
    remove_in=+1)
class Oauth1DriverV8(base.Oauth1DriverV8):
    pass


Driver = manager.create_legacy_driver(base.Oauth1DriverV8)
