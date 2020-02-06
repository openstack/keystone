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

from oslo_log import log
from pycadf import cadftaxonomy as taxonomy
from pycadf import reason
from pycadf import resource

from keystone.common import driver_hints
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone import notifications


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs
_NOTIFY_OP = 'authenticate'
_NOTIFY_EVENT = '{service}.{event}'.format(service=notifications.SERVICE,
                                           event=_NOTIFY_OP)


def construct_method_map_from_config():
    """Determine authentication method types for deployment.

    :returns: a dictionary containing the methods and their indexes

    """
    method_map = dict()
    method_index = 1
    for method in CONF.auth.methods:
        method_map[method_index] = method
        method_index = method_index * 2

    return method_map


def convert_method_list_to_integer(methods):
    """Convert the method type(s) to an integer.

    :param methods: a list of method names
    :returns: an integer representing the methods

    """
    method_map = construct_method_map_from_config()

    method_ints = []
    for method in methods:
        for k, v in method_map.items():
            if v == method:
                method_ints.append(k)
    return sum(method_ints)


def convert_integer_to_method_list(method_int):
    """Convert an integer to a list of methods.

    :param method_int: an integer representing methods
    :returns: a corresponding list of methods

    """
    # If the method_int is 0 then no methods were used so return an empty
    # method list
    if method_int == 0:
        return []

    method_map = construct_method_map_from_config()
    method_ints = sorted(method_map, reverse=True)

    methods = []
    for m_int in method_ints:
        # (lbragstad): By dividing the method_int by each key in the
        # method_map, we know if the division results in an integer of 1, that
        # key was used in the construction of the total sum of the method_int.
        # In that case, we should confirm the key value and store it so we can
        # look it up later. Then we should take the remainder of what is
        # confirmed and the method_int and continue the process. In the end, we
        # should have a list of integers that correspond to indexes in our
        # method_map and we can reinflate the methods that the original
        # method_int represents.
        result = int(method_int / m_int)
        if result == 1:
            methods.append(method_map[m_int])
            method_int = method_int - m_int

    return methods


class BaseUserInfo(provider_api.ProviderAPIMixin, object):

    @classmethod
    def create(cls, auth_payload, method_name):
        user_auth_info = cls()
        user_auth_info._validate_and_normalize_auth_data(auth_payload)
        user_auth_info.METHOD_NAME = method_name
        return user_auth_info

    def __init__(self):
        self.user_id = None
        self.user_ref = None
        self.METHOD_NAME = None

    def _assert_domain_is_enabled(self, domain_ref):
        try:
            PROVIDERS.resource_api.assert_domain_enabled(
                domain_id=domain_ref['id'],
                domain=domain_ref)
        except AssertionError as e:
            LOG.warning(e)
            raise exception.Unauthorized from e

    def _assert_user_is_enabled(self, user_ref):
        try:
            PROVIDERS.identity_api.assert_user_enabled(
                user_id=user_ref['id'],
                user=user_ref)
        except AssertionError as e:
            LOG.warning(e)
            raise exception.Unauthorized from e

    def _lookup_domain(self, domain_info):
        domain_id = domain_info.get('id')
        domain_name = domain_info.get('name')
        if not domain_id and not domain_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='domain')
        try:
            if domain_name:
                domain_ref = PROVIDERS.resource_api.get_domain_by_name(
                    domain_name)
            else:
                domain_ref = PROVIDERS.resource_api.get_domain(domain_id)
        except exception.DomainNotFound as e:
            LOG.warning(e)
            raise exception.Unauthorized(e)
        self._assert_domain_is_enabled(domain_ref)
        return domain_ref

    def _validate_and_normalize_auth_data(self, auth_payload):
        if 'user' not in auth_payload:
            raise exception.ValidationError(attribute='user',
                                            target=self.METHOD_NAME)
        user_info = auth_payload['user']
        user_id = user_info.get('id')
        user_name = user_info.get('name')
        domain_ref = {}
        if not user_id and not user_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='user')
        try:
            if user_name:
                if 'domain' not in user_info:
                    raise exception.ValidationError(attribute='domain',
                                                    target='user')
                domain_ref = self._lookup_domain(user_info['domain'])
                user_ref = PROVIDERS.identity_api.get_user_by_name(
                    user_name, domain_ref['id'])
            else:
                user_ref = PROVIDERS.identity_api.get_user(user_id)
                domain_ref = PROVIDERS.resource_api.get_domain(
                    user_ref['domain_id'])
                self._assert_domain_is_enabled(domain_ref)
        except exception.UserNotFound as e:
            LOG.warning(e)

            # We need to special case USER NOT FOUND here for CADF
            # notifications as the normal path for notification(s) come from
            # `identity_api.authenticate` and we are a bit before dropping into
            # that method.
            audit_reason = reason.Reason(str(e), str(e.code))
            audit_initiator = notifications.build_audit_initiator()
            # build an appropriate audit initiator with relevant information
            # for the failed request. This will catch invalid user_name and
            # invalid user_id.
            if user_name:
                audit_initiator.user_name = user_name
            else:
                audit_initiator.user_id = user_id
            audit_initiator.domain_id = domain_ref.get('id')
            audit_initiator.domain_name = domain_ref.get('name')
            notifications._send_audit_notification(
                action=_NOTIFY_OP,
                initiator=audit_initiator,
                outcome=taxonomy.OUTCOME_FAILURE,
                target=resource.Resource(typeURI=taxonomy.ACCOUNT_USER),
                event_type=_NOTIFY_EVENT,
                reason=audit_reason)
            raise exception.Unauthorized(e)
        self._assert_user_is_enabled(user_ref)
        self.user_ref = user_ref
        self.user_id = user_ref['id']
        self.domain_id = domain_ref['id']


class UserAuthInfo(BaseUserInfo):

    def __init__(self):
        super(UserAuthInfo, self).__init__()
        self.password = None

    def _validate_and_normalize_auth_data(self, auth_payload):
        super(UserAuthInfo, self)._validate_and_normalize_auth_data(
            auth_payload)
        user_info = auth_payload['user']
        self.password = user_info.get('password')


class TOTPUserInfo(BaseUserInfo):

    def __init__(self):
        super(TOTPUserInfo, self).__init__()
        self.passcode = None

    def _validate_and_normalize_auth_data(self, auth_payload):
        super(TOTPUserInfo, self)._validate_and_normalize_auth_data(
            auth_payload)
        user_info = auth_payload['user']
        self.passcode = user_info.get('passcode')


class AppCredInfo(BaseUserInfo):
    def __init__(self):
        super(AppCredInfo, self).__init__()
        self.id = None
        self.secret = None

    def _validate_and_normalize_auth_data(self, auth_payload):
        app_cred_api = PROVIDERS.application_credential_api
        if auth_payload.get('id'):
            app_cred = app_cred_api.get_application_credential(
                auth_payload['id'])
            self.user_id = app_cred['user_id']
            if not auth_payload.get('user'):
                auth_payload['user'] = {}
                auth_payload['user']['id'] = self.user_id
            super(AppCredInfo, self)._validate_and_normalize_auth_data(
                auth_payload)
        elif auth_payload.get('name'):
            super(AppCredInfo, self)._validate_and_normalize_auth_data(
                auth_payload)
            hints = driver_hints.Hints()
            hints.add_filter('name', auth_payload['name'])
            app_cred = app_cred_api.list_application_credentials(
                self.user_id, hints)[0]
            auth_payload['id'] = app_cred['id']
        else:
            raise exception.ValidationError(attribute='id or name',
                                            target='application credential')
        self.id = auth_payload['id']
        self.secret = auth_payload.get('secret')
