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

# This file handles all flask-restful resources for /v3/access_rules_config

from keystone.common import provider_api
import keystone.conf
from keystone.server import flask as ks_flask


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class AccessRulesConfigResource(ks_flask.ResourceBase):
    collection_key = 'access_rules_config'

    @ks_flask.unenforced_api
    def get(self, service=None):
        """List all access rules config.

        GET/HEAD /v3/access_rules_config
        """
        refs = PROVIDERS.access_rules_config_api.list_access_rules_config(
            service=service)
        return refs


class AccessRulesConfigAPI(ks_flask.APIBase):
    _name = 'access_rules_config'
    _import_name = __name__
    resources = []
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=AccessRulesConfigResource,
            url='/access_rules_config',
            resource_kwargs={},
            rel='access_rules_config')
    ]


APIs = (AccessRulesConfigAPI,)
