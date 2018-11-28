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

from keystone.i18n import _


class AuthTestMixin(object):
    """To hold auth building helper functions."""

    def _build_auth_scope(self, system=False, project_id=None,
                          project_name=None, project_domain_id=None,
                          project_domain_name=None, domain_id=None,
                          domain_name=None, trust_id=None, unscoped=None):
        scope_data = {}
        if system:
            scope_data['system'] = {'all': True}
        elif unscoped:
            scope_data['unscoped'] = {}
        elif project_id or project_name:
            scope_data['project'] = {}
            if project_id:
                scope_data['project']['id'] = project_id
            else:
                scope_data['project']['name'] = project_name
                if project_domain_id or project_domain_name:
                    project_domain_json = {}
                    if project_domain_id:
                        project_domain_json['id'] = project_domain_id
                    else:
                        project_domain_json['name'] = project_domain_name
                    scope_data['project']['domain'] = project_domain_json
        elif domain_id or domain_name:
            scope_data['domain'] = {}
            if domain_id:
                scope_data['domain']['id'] = domain_id
            else:
                scope_data['domain']['name'] = domain_name
        elif trust_id:
            scope_data['OS-TRUST:trust'] = {}
            scope_data['OS-TRUST:trust']['id'] = trust_id
        else:
            raise ValueError(_('Programming Error: Invalid arguments supplied '
                               'to build scope.'))

        return scope_data

    def _build_user(self, user_id=None, username=None, user_domain_id=None,
                    user_domain_name=None):
        user = {}
        if user_id:
            user['id'] = user_id
        else:
            user['name'] = username
            if user_domain_id or user_domain_name:
                user['domain'] = {}
                if user_domain_id:
                    user['domain']['id'] = user_domain_id
                else:
                    user['domain']['name'] = user_domain_name
        return user

    def _build_auth(self, user_id=None, username=None, user_domain_id=None,
                    user_domain_name=None, **kwargs):

        # NOTE(dstanek): just to ensure sanity in the tests
        self.assertEqual(1, len(kwargs),
                         message='_build_auth requires 1 (and only 1) '
                                 'secret type and value')

        secret_type, secret_value = list(kwargs.items())[0]

        # NOTE(dstanek): just to ensure sanity in the tests
        self.assertIn(secret_type, ('passcode', 'password'),
                      message="_build_auth only supports 'passcode' "
                              "and 'password' secret types")

        data = {}
        data['user'] = self._build_user(user_id=user_id, username=username,
                                        user_domain_id=user_domain_id,
                                        user_domain_name=user_domain_name)
        data['user'][secret_type] = secret_value
        return data

    def _build_token_auth(self, token):
        return {'id': token}

    def _build_app_cred_auth(self, secret, app_cred_id=None,
                             app_cred_name=None, user_id=None, username=None,
                             user_domain_id=None, user_domain_name=None):
        data = {'secret': secret}
        if app_cred_id:
            data['id'] = app_cred_id
        else:
            data['name'] = app_cred_name
            data['user'] = self._build_user(user_id=user_id,
                                            username=username,
                                            user_domain_id=user_domain_id,
                                            user_domain_name=user_domain_name)
        return data

    def build_authentication_request(self, token=None, user_id=None,
                                     username=None, user_domain_id=None,
                                     user_domain_name=None, password=None,
                                     kerberos=False, passcode=None,
                                     app_cred_id=None, app_cred_name=None,
                                     secret=None, **kwargs):
        """Build auth dictionary.

        It will create an auth dictionary based on all the arguments
        that it receives.
        """
        auth_data = {}
        auth_data['identity'] = {'methods': []}
        if kerberos:
            auth_data['identity']['methods'].append('kerberos')
            auth_data['identity']['kerberos'] = {}
        if token:
            auth_data['identity']['methods'].append('token')
            auth_data['identity']['token'] = self._build_token_auth(token)
        if password and (user_id or username):
            auth_data['identity']['methods'].append('password')
            auth_data['identity']['password'] = self._build_auth(
                user_id, username, user_domain_id, user_domain_name,
                password=password)
        if passcode and (user_id or username):
            auth_data['identity']['methods'].append('totp')
            auth_data['identity']['totp'] = self._build_auth(
                user_id, username, user_domain_id, user_domain_name,
                passcode=passcode)
        if (app_cred_id or app_cred_name) and secret:
            auth_data['identity']['methods'].append('application_credential')
            identity = auth_data['identity']
            identity['application_credential'] = self._build_app_cred_auth(
                secret, app_cred_id=app_cred_id, app_cred_name=app_cred_name,
                user_id=user_id, username=username,
                user_domain_id=user_domain_id,
                user_domain_name=user_domain_name)
        if kwargs:
            auth_data['scope'] = self._build_auth_scope(**kwargs)
        return {'auth': auth_data}
