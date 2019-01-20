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

from keystone.common import provider_api
import keystone.conf


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


def render_token_response_from_model(token, include_catalog=True):
    token_reference = {
        'token': {
            'methods': token.methods,
            'user': {
                'domain': {
                    'id': token.user_domain['id'],
                    'name': token.user_domain['name']
                },
                'id': token.user_id,
                'name': token.user['name'],
                'password_expires_at': token.user[
                    'password_expires_at'
                ]
            },
            'audit_ids': token.audit_ids,
            'expires_at': token.expires_at,
            'issued_at': token.issued_at,
        }
    }
    if token.system_scoped:
        token_reference['token']['roles'] = token.roles
        token_reference['token']['system'] = {'all': True}
    elif token.domain_scoped:
        token_reference['token']['domain'] = {
            'id': token.domain['id'],
            'name': token.domain['name']
        }
        token_reference['token']['roles'] = token.roles
    elif token.trust_scoped:
        token_reference['token']['OS-TRUST:trust'] = {
            'id': token.trust_id,
            'trustor_user': {'id': token.trustor['id']},
            'trustee_user': {'id': token.trustee['id']},
            'impersonation': token.trust['impersonation']
        }
        token_reference['token']['project'] = {
            'domain': {
                'id': token.project_domain['id'],
                'name': token.project_domain['name']
            },
            'id': token.trust_project['id'],
            'name': token.trust_project['name']
        }
        if token.trust.get('impersonation'):
            trustor_domain = PROVIDERS.resource_api.get_domain(
                token.trustor['domain_id']
            )
            token_reference['token']['user'] = {
                'domain': {
                    'id': trustor_domain['id'],
                    'name': trustor_domain['name']
                },
                'id': token.trustor['id'],
                'name': token.trustor['name'],
                'password_expires_at': token.trustor[
                    'password_expires_at'
                ]
            }
        token_reference['token']['roles'] = token.roles
    elif token.project_scoped:
        token_reference['token']['project'] = {
            'domain': {
                'id': token.project_domain['id'],
                'name': token.project_domain['name']
            },
            'id': token.project['id'],
            'name': token.project['name']
        }
        token_reference['token']['is_domain'] = token.project.get(
            'is_domain', False
        )
        token_reference['token']['roles'] = token.roles
        ap_name = CONF.resource.admin_project_name
        ap_domain_name = CONF.resource.admin_project_domain_name
        if ap_name and ap_domain_name:
            is_ap = (
                token.project['name'] == ap_name and
                ap_domain_name == token.project_domain['name']
            )
            token_reference['token']['is_admin_project'] = is_ap
    if include_catalog and not token.unscoped:
        user_id = token.user_id
        if token.trust_id:
            user_id = token.trust['trustor_user_id']
        catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id, token.project_id
        )
        token_reference['token']['catalog'] = catalog
    sps = PROVIDERS.federation_api.get_enabled_service_providers()
    if sps:
        token_reference['token']['service_providers'] = sps
    if token.is_federated:
        PROVIDERS.federation_api.get_idp(token.identity_provider_id)
        federated_dict = dict(
            groups=token.federated_groups,
            identity_provider={'id': token.identity_provider_id},
            protocol={'id': token.protocol_id},

        )
        token_reference['token']['user']['OS-FEDERATION'] = (
            federated_dict
        )
        del token_reference['token']['user']['password_expires_at']
    if token.access_token_id:
        token_reference['token']['OS-OAUTH1'] = {
            'access_token_id': token.access_token_id,
            'consumer_id': token.access_token['consumer_id']
        }
    if token.application_credential_id:
        key = 'application_credential'
        token_reference['token'][key] = {}
        token_reference['token'][key]['id'] = (
            token.application_credential['id']
        )
        token_reference['token'][key]['name'] = (
            token.application_credential['name']
        )
        restricted = not token.application_credential['unrestricted']
        token_reference['token'][key]['restricted'] = restricted
        if token.application_credential.get('access_rules'):
            token_reference['token'][key]['access_rules'] = (
                token.application_credential['access_rules']
            )

    return token_reference
