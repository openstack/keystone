#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.federation import idp as keystone_idp
from keystone.federation import utils as federation_utils
from keystone.i18n import _


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


def create_base_saml_assertion(auth):
    issuer = CONF.saml.idp_entity_id
    sp_id = auth['scope']['service_provider']['id']
    service_provider = PROVIDERS.federation_api.get_sp(sp_id)
    federation_utils.assert_enabled_service_provider_object(service_provider)
    sp_url = service_provider['sp_url']

    token_id = auth['identity']['token']['id']
    token = PROVIDERS.token_provider_api.validate_token(token_id)

    if not token.project_scoped:
        action = _('Use a project scoped token when attempting to create '
                   'a SAML assertion')
        raise exception.ForbiddenAction(action=action)

    subject = token.user['name']
    role_names = []
    for role in token.roles:
        role_names.append(role['name'])
    project = token.project['name']
    # NOTE(rodrigods): the domain name is necessary in order to distinguish
    # between projects and users with the same name in different domains.
    project_domain_name = token.project_domain['name']
    subject_domain_name = token.user_domain['name']

    generator = keystone_idp.SAMLGenerator()
    response = generator.samlize_token(
        issuer, sp_url, subject, subject_domain_name,
        role_names, project, project_domain_name)
    return response, service_provider
