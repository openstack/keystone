# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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

from __future__ import absolute_import

try:
    import pam
except ImportError:
    pam = None
    import PAM

from keystone import identity


def PAM_authenticate(username, password):
    def _pam_conv(auth, query_list):
        resp = []

        for query, q_type in query_list:
            if q_type in [PAM.PAM_PROMPT_ECHO_ON, PAM.PAM_PROMPT_ECHO_OFF]:
                resp.append((password, 0))
            elif q_type in [PAM.PAM_PROMPT_ERROR_MSG,
                            PAM.PAM_PROMPT_TEXT_INFO]:
                resp.append(('', 0))

        return resp

    auth = PAM.pam()
    auth.start('passwd')
    auth.set_item(PAM.PAM_USER, username)
    auth.set_item(PAM.PAM_CONV, _pam_conv)

    try:
        auth.authenticate()
        auth.acct_mgmt()
    except PAM.error:
        raise AssertionError('Invalid user / password')

    return True


class PamIdentity(identity.Driver):
    """Very basic identity based on PAM.

    Tenant is always the same as User, root user has admin role.
    """

    def is_domain_aware(self):
        return False

    def authenticate(self, user_id, password):
        auth = pam.authenticate if pam else PAM_authenticate
        if not auth(user_id, password):
            raise AssertionError('Invalid user / password')
        user = {'id': user_id, 'name': user_id}
        return user

    def get_project(self, tenant_id):
        return {'id': tenant_id, 'name': tenant_id}

    def get_project_by_name(self, tenant_name, domain_id):
        # TODO(henry-nash): Used domain_id once domains are implemented
        # in LDAP backend
        return {'id': tenant_name, 'name': tenant_name}

    def get_user(self, user_id):
        return {'id': user_id, 'name': user_id}

    def get_user_by_name(self, user_name, domain_id):
        # TODO(henry-nash): Used domain_id once domains are implemented
        # in LDAP backend
        return {'id': user_name, 'name': user_name}

    def list_users(self):
        raise NotImplementedError()

    def add_user_to_project(self, tenant_id, user_id):
        pass

    def remove_user_from_project(self, tenant_id, user_id):
        pass

    def list_projects_for_user(self, user_id):
        return [{'id': user_id, 'name': user_id}]

    def create_user(self, user_id, user):
        raise NotImplementedError()

    def update_user(self, user_id, user):
        raise NotImplementedError()

    def delete_user(self, user_id):
        raise NotImplementedError()

    def _get_metadata(self, user_id, tenant_id):
        metadata = {}
        if user_id == 'root':
            metadata['is_admin'] = True
        return metadata

    def _create_metadata(self, user_id, tenant_id, metadata):
        raise NotImplementedError()

    def _update_metadata(self, user_id, tenant_id, metadata):
        raise NotImplementedError()

    def add_user_to_group(self, user_id, group_id):
        raise NotImplementedError()

    def check_user_in_group(self, user_id, group_id):
        raise NotImplementedError()

    def remove_user_from_group(self, user_id, group_id):
        raise NotImplementedError()

    def create_group(self, group_id, group):
        raise NotImplementedError()

    def list_groups(self):
        raise NotImplementedError()

    def list_groups_for_user(self, user_id):
        raise NotImplementedError()

    def list_users_in_group(self, group_id):
        raise NotImplementedError()

    def get_group(self, group_id):
        raise NotImplementedError()

    def update_group(self, group_id, group):
        raise NotImplementedError()

    def delete_group(self, group_id):
        raise NotImplementedError()
