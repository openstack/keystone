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

# NOTE(morgan): This file does not implement any API-specific code. It simply
# supplies shared functions between the "role_inferences" and "roles" (for
# implied roles) APIs. In general, all code for an API should be isolated to
# it's own keystone.api.XXX module and not in the _shared module.

from keystone.common import provider_api
from keystone.server import flask as ks_flask


PROVIDERS = provider_api.ProviderAPIs


def build_prior_role_response_data(prior_role_id, prior_role_name):
    return {
        'id': prior_role_id,
        'links': {
            'self': ks_flask.base_url(path='/roles/%s' % prior_role_id)
        },
        'name': prior_role_name}


def build_implied_role_response_data(implied_role):
    return {
        'id': implied_role['id'],
        'links': {
            'self': ks_flask.base_url(
                path='/roles/%s' % implied_role['id'])
        },
        'name': implied_role['name']}


def role_inference_response(prior_role_id):
    prior_role = PROVIDERS.role_api.get_role(prior_role_id)
    response = {
        'role_inference': {
            'prior_role': build_prior_role_response_data(
                prior_role_id, prior_role['name'])}}
    return response
