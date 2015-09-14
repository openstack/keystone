# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import functools
import random

import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
from six.moves import http_client
from testtools import matchers as tt_matchers
import webob

from keystone.common import json_home
from keystone import controllers
from keystone.tests import unit
from keystone.tests.unit import utils


CONF = cfg.CONF

v2_MEDIA_TYPES = [
    {
        "base": "application/json",
        "type": "application/"
                "vnd.openstack.identity-v2.0+json"
    }
]

v2_HTML_DESCRIPTION = {
    "rel": "describedby",
    "type": "text/html",
    "href": "http://docs.openstack.org/"
}


v2_EXPECTED_RESPONSE = {
    "id": "v2.0",
    "status": "stable",
    "updated": "2014-04-17T00:00:00Z",
    "links": [
        {
            "rel": "self",
            "href": "",     # Will get filled in after initialization
        },
        v2_HTML_DESCRIPTION
    ],
    "media-types": v2_MEDIA_TYPES
}

v2_VERSION_RESPONSE = {
    "version": v2_EXPECTED_RESPONSE
}

v3_MEDIA_TYPES = [
    {
        "base": "application/json",
        "type": "application/"
                "vnd.openstack.identity-v3+json"
    }
]

v3_EXPECTED_RESPONSE = {
    "id": "v3.4",
    "status": "stable",
    "updated": "2015-03-30T00:00:00Z",
    "links": [
        {
            "rel": "self",
            "href": "",     # Will get filled in after initialization
        }
    ],
    "media-types": v3_MEDIA_TYPES
}

v3_VERSION_RESPONSE = {
    "version": v3_EXPECTED_RESPONSE
}

VERSIONS_RESPONSE = {
    "versions": {
        "values": [
            v3_EXPECTED_RESPONSE,
            v2_EXPECTED_RESPONSE
        ]
    }
}

_build_ec2tokens_relation = functools.partial(
    json_home.build_v3_extension_resource_relation, extension_name='OS-EC2',
    extension_version='1.0')

REVOCATIONS_RELATION = json_home.build_v3_extension_resource_relation(
    'OS-PKI', '1.0', 'revocations')

_build_simple_cert_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-SIMPLE-CERT', extension_version='1.0')

_build_trust_relation = functools.partial(
    json_home.build_v3_extension_resource_relation, extension_name='OS-TRUST',
    extension_version='1.0')

_build_federation_rel = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-FEDERATION',
    extension_version='1.0')

_build_oauth1_rel = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-OAUTH1', extension_version='1.0')

_build_ep_policy_rel = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-ENDPOINT-POLICY', extension_version='1.0')

_build_ep_filter_rel = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-EP-FILTER', extension_version='1.0')

TRUST_ID_PARAMETER_RELATION = json_home.build_v3_extension_parameter_relation(
    'OS-TRUST', '1.0', 'trust_id')

IDP_ID_PARAMETER_RELATION = json_home.build_v3_extension_parameter_relation(
    'OS-FEDERATION', '1.0', 'idp_id')

PROTOCOL_ID_PARAM_RELATION = json_home.build_v3_extension_parameter_relation(
    'OS-FEDERATION', '1.0', 'protocol_id')

MAPPING_ID_PARAM_RELATION = json_home.build_v3_extension_parameter_relation(
    'OS-FEDERATION', '1.0', 'mapping_id')

SP_ID_PARAMETER_RELATION = json_home.build_v3_extension_parameter_relation(
    'OS-FEDERATION', '1.0', 'sp_id')

CONSUMER_ID_PARAMETER_RELATION = (
    json_home.build_v3_extension_parameter_relation(
        'OS-OAUTH1', '1.0', 'consumer_id'))

REQUEST_TOKEN_ID_PARAMETER_RELATION = (
    json_home.build_v3_extension_parameter_relation(
        'OS-OAUTH1', '1.0', 'request_token_id'))

ACCESS_TOKEN_ID_PARAMETER_RELATION = (
    json_home.build_v3_extension_parameter_relation(
        'OS-OAUTH1', '1.0', 'access_token_id'))

ENDPOINT_GROUP_ID_PARAMETER_RELATION = (
    json_home.build_v3_extension_parameter_relation(
        'OS-EP-FILTER', '1.0', 'endpoint_group_id'))

BASE_IDP_PROTOCOL = '/OS-FEDERATION/identity_providers/{idp_id}/protocols'
BASE_EP_POLICY = '/policies/{policy_id}/OS-ENDPOINT-POLICY'
BASE_EP_FILTER_PREFIX = '/OS-EP-FILTER'
BASE_EP_FILTER = BASE_EP_FILTER_PREFIX + '/endpoint_groups/{endpoint_group_id}'
BASE_ACCESS_TOKEN = (
    '/users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}')

# TODO(stevemar): Use BASE_IDP_PROTOCOL when bug 1420125 is resolved.
FEDERATED_AUTH_URL = ('/OS-FEDERATION/identity_providers/{identity_provider}'
                      '/protocols/{protocol}/auth')
FEDERATED_IDP_SPECIFIC_WEBSSO = ('/auth/OS-FEDERATION/identity_providers/'
                                 '{idp_id}/protocols/{protocol_id}/websso')

V3_JSON_HOME_RESOURCES_INHERIT_DISABLED = {
    json_home.build_v3_resource_relation('auth_tokens'): {
        'href': '/auth/tokens'},
    json_home.build_v3_resource_relation('auth_catalog'): {
        'href': '/auth/catalog'},
    json_home.build_v3_resource_relation('auth_projects'): {
        'href': '/auth/projects'},
    json_home.build_v3_resource_relation('auth_domains'): {
        'href': '/auth/domains'},
    json_home.build_v3_resource_relation('credential'): {
        'href-template': '/credentials/{credential_id}',
        'href-vars': {
            'credential_id':
            json_home.build_v3_parameter_relation('credential_id')}},
    json_home.build_v3_resource_relation('credentials'): {
        'href': '/credentials'},
    json_home.build_v3_resource_relation('domain'): {
        'href-template': '/domains/{domain_id}',
        'href-vars': {'domain_id': json_home.Parameters.DOMAIN_ID, }},
    json_home.build_v3_resource_relation('domain_group_role'): {
        'href-template':
        '/domains/{domain_id}/groups/{group_id}/roles/{role_id}',
        'href-vars': {
            'domain_id': json_home.Parameters.DOMAIN_ID,
            'group_id': json_home.Parameters.GROUP_ID,
            'role_id': json_home.Parameters.ROLE_ID, }},
    json_home.build_v3_resource_relation('domain_group_roles'): {
        'href-template': '/domains/{domain_id}/groups/{group_id}/roles',
        'href-vars': {
            'domain_id': json_home.Parameters.DOMAIN_ID,
            'group_id': json_home.Parameters.GROUP_ID}},
    json_home.build_v3_resource_relation('domain_user_role'): {
        'href-template':
        '/domains/{domain_id}/users/{user_id}/roles/{role_id}',
        'href-vars': {
            'domain_id': json_home.Parameters.DOMAIN_ID,
            'role_id': json_home.Parameters.ROLE_ID,
            'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('domain_user_roles'): {
        'href-template': '/domains/{domain_id}/users/{user_id}/roles',
        'href-vars': {
            'domain_id': json_home.Parameters.DOMAIN_ID,
            'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('domains'): {'href': '/domains'},
    json_home.build_v3_resource_relation('endpoint'): {
        'href-template': '/endpoints/{endpoint_id}',
        'href-vars': {
            'endpoint_id':
            json_home.build_v3_parameter_relation('endpoint_id'), }},
    json_home.build_v3_resource_relation('endpoints'): {
        'href': '/endpoints'},
    _build_ec2tokens_relation(resource_name='ec2tokens'): {
        'href': '/ec2tokens'},
    _build_ec2tokens_relation(resource_name='user_credential'): {
        'href-template': '/users/{user_id}/credentials/OS-EC2/{credential_id}',
        'href-vars': {
            'credential_id': json_home.build_v3_extension_parameter_relation(
                'OS-EC2', '1.0', 'credential_id'),
            'user_id': json_home.Parameters.USER_ID, }},
    _build_ec2tokens_relation(resource_name='user_credentials'): {
        'href-template': '/users/{user_id}/credentials/OS-EC2',
        'href-vars': {
            'user_id': json_home.Parameters.USER_ID, }},
    REVOCATIONS_RELATION: {
        'href': '/auth/tokens/OS-PKI/revoked'},
    'http://docs.openstack.org/api/openstack-identity/3/ext/OS-REVOKE/1.0/rel/'
    'events': {
        'href': '/OS-REVOKE/events'},
    _build_simple_cert_relation(resource_name='ca_certificate'): {
        'href': '/OS-SIMPLE-CERT/ca'},
    _build_simple_cert_relation(resource_name='certificates'): {
        'href': '/OS-SIMPLE-CERT/certificates'},
    _build_trust_relation(resource_name='trust'):
    {
        'href-template': '/OS-TRUST/trusts/{trust_id}',
        'href-vars': {'trust_id': TRUST_ID_PARAMETER_RELATION, }},
    _build_trust_relation(resource_name='trust_role'): {
        'href-template': '/OS-TRUST/trusts/{trust_id}/roles/{role_id}',
        'href-vars': {
            'role_id': json_home.Parameters.ROLE_ID,
            'trust_id': TRUST_ID_PARAMETER_RELATION, }},
    _build_trust_relation(resource_name='trust_roles'): {
        'href-template': '/OS-TRUST/trusts/{trust_id}/roles',
        'href-vars': {'trust_id': TRUST_ID_PARAMETER_RELATION, }},
    _build_trust_relation(resource_name='trusts'): {
        'href': '/OS-TRUST/trusts'},
    'http://docs.openstack.org/api/openstack-identity/3/ext/s3tokens/1.0/rel/'
    's3tokens': {
        'href': '/s3tokens'},
    json_home.build_v3_resource_relation('group'): {
        'href-template': '/groups/{group_id}',
        'href-vars': {
            'group_id': json_home.Parameters.GROUP_ID, }},
    json_home.build_v3_resource_relation('group_user'): {
        'href-template': '/groups/{group_id}/users/{user_id}',
        'href-vars': {
            'group_id': json_home.Parameters.GROUP_ID,
            'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('group_users'): {
        'href-template': '/groups/{group_id}/users',
        'href-vars': {'group_id': json_home.Parameters.GROUP_ID, }},
    json_home.build_v3_resource_relation('groups'): {'href': '/groups'},
    json_home.build_v3_resource_relation('policies'): {
        'href': '/policies'},
    json_home.build_v3_resource_relation('policy'): {
        'href-template': '/policies/{policy_id}',
        'href-vars': {
            'policy_id':
            json_home.build_v3_parameter_relation('policy_id'), }},
    json_home.build_v3_resource_relation('project'): {
        'href-template': '/projects/{project_id}',
        'href-vars': {
            'project_id': json_home.Parameters.PROJECT_ID, }},
    json_home.build_v3_resource_relation('project_group_role'): {
        'href-template':
        '/projects/{project_id}/groups/{group_id}/roles/{role_id}',
        'href-vars': {
            'group_id': json_home.Parameters.GROUP_ID,
            'project_id': json_home.Parameters.PROJECT_ID,
            'role_id': json_home.Parameters.ROLE_ID, }},
    json_home.build_v3_resource_relation('project_group_roles'): {
        'href-template': '/projects/{project_id}/groups/{group_id}/roles',
        'href-vars': {
            'group_id': json_home.Parameters.GROUP_ID,
            'project_id': json_home.Parameters.PROJECT_ID, }},
    json_home.build_v3_resource_relation('project_user_role'): {
        'href-template':
        '/projects/{project_id}/users/{user_id}/roles/{role_id}',
        'href-vars': {
            'project_id': json_home.Parameters.PROJECT_ID,
            'role_id': json_home.Parameters.ROLE_ID,
            'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('project_user_roles'): {
        'href-template': '/projects/{project_id}/users/{user_id}/roles',
        'href-vars': {
            'project_id': json_home.Parameters.PROJECT_ID,
            'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('projects'): {
        'href': '/projects'},
    json_home.build_v3_resource_relation('region'): {
        'href-template': '/regions/{region_id}',
        'href-vars': {
            'region_id':
            json_home.build_v3_parameter_relation('region_id'), }},
    json_home.build_v3_resource_relation('regions'): {'href': '/regions'},
    json_home.build_v3_resource_relation('role'): {
        'href-template': '/roles/{role_id}',
        'href-vars': {
            'role_id': json_home.Parameters.ROLE_ID, }},
    json_home.build_v3_resource_relation('role_assignments'): {
        'href': '/role_assignments'},
    json_home.build_v3_resource_relation('roles'): {'href': '/roles'},
    json_home.build_v3_resource_relation('service'): {
        'href-template': '/services/{service_id}',
        'href-vars': {
            'service_id':
            json_home.build_v3_parameter_relation('service_id')}},
    json_home.build_v3_resource_relation('services'): {
        'href': '/services'},
    json_home.build_v3_resource_relation('user'): {
        'href-template': '/users/{user_id}',
        'href-vars': {
            'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('user_change_password'): {
        'href-template': '/users/{user_id}/password',
        'href-vars': {'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('user_groups'): {
        'href-template': '/users/{user_id}/groups',
        'href-vars': {'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('user_projects'): {
        'href-template': '/users/{user_id}/projects',
        'href-vars': {'user_id': json_home.Parameters.USER_ID, }},
    json_home.build_v3_resource_relation('users'): {'href': '/users'},
    _build_federation_rel(resource_name='domains'): {
        'href': '/auth/domains'},
    _build_federation_rel(resource_name='websso'): {
        'href-template': '/auth/OS-FEDERATION/websso/{protocol_id}',
        'href-vars': {
            'protocol_id': PROTOCOL_ID_PARAM_RELATION, }},
    _build_federation_rel(resource_name='projects'): {
        'href': '/auth/projects'},
    _build_federation_rel(resource_name='saml2'): {
        'href': '/auth/OS-FEDERATION/saml2'},
    _build_federation_rel(resource_name='ecp'): {
        'href': '/auth/OS-FEDERATION/saml2/ecp'},
    _build_federation_rel(resource_name='metadata'): {
        'href': '/OS-FEDERATION/saml2/metadata'},
    _build_federation_rel(resource_name='identity_providers'): {
        'href': '/OS-FEDERATION/identity_providers'},
    _build_federation_rel(resource_name='service_providers'): {
        'href': '/OS-FEDERATION/service_providers'},
    _build_federation_rel(resource_name='mappings'): {
        'href': '/OS-FEDERATION/mappings'},
    _build_federation_rel(resource_name='identity_provider'):
    {
        'href-template': '/OS-FEDERATION/identity_providers/{idp_id}',
        'href-vars': {'idp_id': IDP_ID_PARAMETER_RELATION, }},
    _build_federation_rel(resource_name='identity_providers'): {
        'href-template': FEDERATED_IDP_SPECIFIC_WEBSSO,
        'href-vars': {
            'idp_id': IDP_ID_PARAMETER_RELATION,
            'protocol_id': PROTOCOL_ID_PARAM_RELATION, }},
    _build_federation_rel(resource_name='service_provider'):
    {
        'href-template': '/OS-FEDERATION/service_providers/{sp_id}',
        'href-vars': {'sp_id': SP_ID_PARAMETER_RELATION, }},
    _build_federation_rel(resource_name='mapping'):
    {
        'href-template': '/OS-FEDERATION/mappings/{mapping_id}',
        'href-vars': {'mapping_id': MAPPING_ID_PARAM_RELATION, }},
    _build_federation_rel(resource_name='identity_provider_protocol'): {
        'href-template': BASE_IDP_PROTOCOL + '/{protocol_id}',
        'href-vars': {
            'idp_id': IDP_ID_PARAMETER_RELATION,
            'protocol_id': PROTOCOL_ID_PARAM_RELATION, }},
    _build_federation_rel(resource_name='identity_provider_protocols'): {
        'href-template': BASE_IDP_PROTOCOL,
        'href-vars': {
            'idp_id': IDP_ID_PARAMETER_RELATION}},
    # TODO(stevemar): Update href-vars when bug 1420125 is resolved.
    _build_federation_rel(resource_name='identity_provider_protocol_auth'): {
        'href-template': FEDERATED_AUTH_URL,
        'href-vars': {
            'identity_provider': IDP_ID_PARAMETER_RELATION,
            'protocol': PROTOCOL_ID_PARAM_RELATION, }},
    _build_oauth1_rel(resource_name='access_tokens'): {
        'href': '/OS-OAUTH1/access_token'},
    _build_oauth1_rel(resource_name='request_tokens'): {
        'href': '/OS-OAUTH1/request_token'},
    _build_oauth1_rel(resource_name='consumers'): {
        'href': '/OS-OAUTH1/consumers'},
    _build_oauth1_rel(resource_name='authorize_request_token'):
    {
        'href-template': '/OS-OAUTH1/authorize/{request_token_id}',
        'href-vars': {'request_token_id':
                      REQUEST_TOKEN_ID_PARAMETER_RELATION, }},
    _build_oauth1_rel(resource_name='consumer'):
    {
        'href-template': '/OS-OAUTH1/consumers/{consumer_id}',
        'href-vars': {'consumer_id': CONSUMER_ID_PARAMETER_RELATION, }},
    _build_oauth1_rel(resource_name='user_access_token'):
    {
        'href-template': BASE_ACCESS_TOKEN,
        'href-vars': {'user_id': json_home.Parameters.USER_ID,
                      'access_token_id':
                      ACCESS_TOKEN_ID_PARAMETER_RELATION, }},
    _build_oauth1_rel(resource_name='user_access_tokens'):
    {
        'href-template': '/users/{user_id}/OS-OAUTH1/access_tokens',
        'href-vars': {'user_id': json_home.Parameters.USER_ID, }},
    _build_oauth1_rel(resource_name='user_access_token_role'):
    {
        'href-template': BASE_ACCESS_TOKEN + '/roles/{role_id}',
        'href-vars': {'user_id': json_home.Parameters.USER_ID,
                      'role_id': json_home.Parameters.ROLE_ID,
                      'access_token_id':
                      ACCESS_TOKEN_ID_PARAMETER_RELATION, }},
    _build_oauth1_rel(resource_name='user_access_token_roles'):
    {
        'href-template': BASE_ACCESS_TOKEN + '/roles',
        'href-vars': {'user_id': json_home.Parameters.USER_ID,
                      'access_token_id':
                      ACCESS_TOKEN_ID_PARAMETER_RELATION, }},
    _build_ep_policy_rel(resource_name='endpoint_policy'):
    {
        'href-template': '/endpoints/{endpoint_id}/OS-ENDPOINT-POLICY/policy',
        'href-vars': {'endpoint_id': json_home.Parameters.ENDPOINT_ID, }},
    _build_ep_policy_rel(resource_name='endpoint_policy_association'):
    {
        'href-template': BASE_EP_POLICY + '/endpoints/{endpoint_id}',
        'href-vars': {'endpoint_id': json_home.Parameters.ENDPOINT_ID,
                      'policy_id': json_home.Parameters.POLICY_ID, }},
    _build_ep_policy_rel(resource_name='policy_endpoints'):
    {
        'href-template': BASE_EP_POLICY + '/endpoints',
        'href-vars': {'policy_id': json_home.Parameters.POLICY_ID, }},
    _build_ep_policy_rel(
        resource_name='region_and_service_policy_association'):
    {
        'href-template': (BASE_EP_POLICY +
                          '/services/{service_id}/regions/{region_id}'),
        'href-vars': {'policy_id': json_home.Parameters.POLICY_ID,
                      'service_id': json_home.Parameters.SERVICE_ID,
                      'region_id': json_home.Parameters.REGION_ID, }},
    _build_ep_policy_rel(resource_name='service_policy_association'):
    {
        'href-template': BASE_EP_POLICY + '/services/{service_id}',
        'href-vars': {'policy_id': json_home.Parameters.POLICY_ID,
                      'service_id': json_home.Parameters.SERVICE_ID, }},
    _build_ep_filter_rel(resource_name='endpoint_group'):
    {
        'href-template': '/OS-EP-FILTER/endpoint_groups/{endpoint_group_id}',
        'href-vars': {'endpoint_group_id':
                      ENDPOINT_GROUP_ID_PARAMETER_RELATION, }},
    _build_ep_filter_rel(
        resource_name='endpoint_group_to_project_association'):
    {
        'href-template': BASE_EP_FILTER + '/projects/{project_id}',
        'href-vars': {'endpoint_group_id':
                      ENDPOINT_GROUP_ID_PARAMETER_RELATION,
                      'project_id': json_home.Parameters.PROJECT_ID, }},
    _build_ep_filter_rel(resource_name='endpoint_groups'):
    {'href': '/OS-EP-FILTER/endpoint_groups'},
    _build_ep_filter_rel(resource_name='endpoint_projects'):
    {
        'href-template': '/OS-EP-FILTER/endpoints/{endpoint_id}/projects',
        'href-vars': {'endpoint_id': json_home.Parameters.ENDPOINT_ID, }},
    _build_ep_filter_rel(resource_name='endpoints_in_endpoint_group'):
    {
        'href-template': BASE_EP_FILTER + '/endpoints',
        'href-vars': {'endpoint_group_id':
                      ENDPOINT_GROUP_ID_PARAMETER_RELATION, }},
    _build_ep_filter_rel(resource_name='project_endpoint_groups'):
    {
        'href-template': (BASE_EP_FILTER_PREFIX + '/projects/{project_id}' +
                          '/endpoint_groups'),
        'href-vars': {'project_id':
                      json_home.Parameters.PROJECT_ID, }},
    _build_ep_filter_rel(resource_name='project_endpoint'):
    {
        'href-template': ('/OS-EP-FILTER/projects/{project_id}'
                          '/endpoints/{endpoint_id}'),
        'href-vars': {'endpoint_id': json_home.Parameters.ENDPOINT_ID,
                      'project_id': json_home.Parameters.PROJECT_ID, }},
    _build_ep_filter_rel(resource_name='project_endpoints'):
    {
        'href-template': '/OS-EP-FILTER/projects/{project_id}/endpoints',
        'href-vars': {'project_id': json_home.Parameters.PROJECT_ID, }},
    _build_ep_filter_rel(
        resource_name='projects_associated_with_endpoint_group'):
    {
        'href-template': BASE_EP_FILTER + '/projects',
        'href-vars': {'endpoint_group_id':
                      ENDPOINT_GROUP_ID_PARAMETER_RELATION, }},
    json_home.build_v3_resource_relation('domain_config'): {
        'href-template':
        '/domains/{domain_id}/config',
        'href-vars': {
            'domain_id': json_home.Parameters.DOMAIN_ID},
        'hints': {'status': 'experimental'}},
    json_home.build_v3_resource_relation('domain_config_group'): {
        'href-template':
        '/domains/{domain_id}/config/{group}',
        'href-vars': {
            'domain_id': json_home.Parameters.DOMAIN_ID,
            'group': json_home.build_v3_parameter_relation('config_group')},
        'hints': {'status': 'experimental'}},
    json_home.build_v3_resource_relation('domain_config_option'): {
        'href-template':
        '/domains/{domain_id}/config/{group}/{option}',
        'href-vars': {
            'domain_id': json_home.Parameters.DOMAIN_ID,
            'group': json_home.build_v3_parameter_relation('config_group'),
            'option': json_home.build_v3_parameter_relation('config_option')},
        'hints': {'status': 'experimental'}},
}


# with os-inherit enabled, there's some more resources.

build_os_inherit_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-INHERIT', extension_version='1.0')

V3_JSON_HOME_RESOURCES_INHERIT_ENABLED = dict(
    V3_JSON_HOME_RESOURCES_INHERIT_DISABLED)
V3_JSON_HOME_RESOURCES_INHERIT_ENABLED.update(
    (
        (
            build_os_inherit_relation(
                resource_name='domain_user_role_inherited_to_projects'),
            {
                'href-template': '/OS-INHERIT/domains/{domain_id}/users/'
                '{user_id}/roles/{role_id}/inherited_to_projects',
                'href-vars': {
                    'domain_id': json_home.Parameters.DOMAIN_ID,
                    'role_id': json_home.Parameters.ROLE_ID,
                    'user_id': json_home.Parameters.USER_ID,
                },
            }
        ),
        (
            build_os_inherit_relation(
                resource_name='domain_group_role_inherited_to_projects'),
            {
                'href-template': '/OS-INHERIT/domains/{domain_id}/groups/'
                '{group_id}/roles/{role_id}/inherited_to_projects',
                'href-vars': {
                    'domain_id': json_home.Parameters.DOMAIN_ID,
                    'group_id': json_home.Parameters.GROUP_ID,
                    'role_id': json_home.Parameters.ROLE_ID,
                },
            }
        ),
        (
            build_os_inherit_relation(
                resource_name='domain_user_roles_inherited_to_projects'),
            {
                'href-template': '/OS-INHERIT/domains/{domain_id}/users/'
                '{user_id}/roles/inherited_to_projects',
                'href-vars': {
                    'domain_id': json_home.Parameters.DOMAIN_ID,
                    'user_id': json_home.Parameters.USER_ID,
                },
            }
        ),
        (
            build_os_inherit_relation(
                resource_name='domain_group_roles_inherited_to_projects'),
            {
                'href-template': '/OS-INHERIT/domains/{domain_id}/groups/'
                '{group_id}/roles/inherited_to_projects',
                'href-vars': {
                    'domain_id': json_home.Parameters.DOMAIN_ID,
                    'group_id': json_home.Parameters.GROUP_ID,
                },
            }
        ),
        (
            build_os_inherit_relation(
                resource_name='project_user_role_inherited_to_projects'),
            {
                'href-template': '/OS-INHERIT/projects/{project_id}/users/'
                '{user_id}/roles/{role_id}/inherited_to_projects',
                'href-vars': {
                    'project_id': json_home.Parameters.PROJECT_ID,
                    'role_id': json_home.Parameters.ROLE_ID,
                    'user_id': json_home.Parameters.USER_ID,
                },
            }
        ),
        (
            build_os_inherit_relation(
                resource_name='project_group_role_inherited_to_projects'),
            {
                'href-template': '/OS-INHERIT/projects/{project_id}/groups/'
                '{group_id}/roles/{role_id}/inherited_to_projects',
                'href-vars': {
                    'project_id': json_home.Parameters.PROJECT_ID,
                    'group_id': json_home.Parameters.GROUP_ID,
                    'role_id': json_home.Parameters.ROLE_ID,
                },
            }
        ),
    )
)


class TestClient(object):
    def __init__(self, app=None, token=None):
        self.app = app
        self.token = token

    def request(self, method, path, headers=None, body=None):
        if headers is None:
            headers = {}

        if self.token:
            headers.setdefault('X-Auth-Token', self.token)

        req = webob.Request.blank(path)
        req.method = method
        for k, v in headers.items():
            req.headers[k] = v
        if body:
            req.body = body
        return req.get_response(self.app)

    def get(self, path, headers=None):
        return self.request('GET', path=path, headers=headers)

    def post(self, path, headers=None, body=None):
        return self.request('POST', path=path, headers=headers, body=body)

    def put(self, path, headers=None, body=None):
        return self.request('PUT', path=path, headers=headers, body=body)


class _VersionsEqual(tt_matchers.MatchesListwise):
    def __init__(self, expected):
        super(_VersionsEqual, self).__init__([
            tt_matchers.KeysEqual(expected),
            tt_matchers.KeysEqual(expected['versions']),
            tt_matchers.HasLength(len(expected['versions']['values'])),
            tt_matchers.ContainsAll(expected['versions']['values']),
        ])

    def match(self, other):
        return super(_VersionsEqual, self).match([
            other,
            other['versions'],
            other['versions']['values'],
            other['versions']['values'],
        ])


class VersionTestCase(unit.TestCase):
    def setUp(self):
        super(VersionTestCase, self).setUp()
        self.load_backends()
        self.public_app = self.loadapp('keystone', 'main')
        self.admin_app = self.loadapp('keystone', 'admin')

        self.config_fixture.config(
            public_endpoint='http://localhost:%(public_port)d',
            admin_endpoint='http://localhost:%(admin_port)d')

    def config_overrides(self):
        super(VersionTestCase, self).config_overrides()
        admin_port = random.randint(10000, 30000)
        public_port = random.randint(40000, 60000)
        self.config_fixture.config(group='eventlet_server',
                                   public_port=public_port,
                                   admin_port=admin_port)

    def _paste_in_port(self, response, port):
        for link in response['links']:
            if link['rel'] == 'self':
                link['href'] = port

    def test_public_versions(self):
        client = TestClient(self.public_app)
        resp = client.get('/')
        self.assertEqual(300, resp.status_int)
        data = jsonutils.loads(resp.body)
        expected = VERSIONS_RESPONSE
        for version in expected['versions']['values']:
            if version['id'].startswith('v3'):
                self._paste_in_port(
                    version, 'http://localhost:%s/v3/' %
                    CONF.eventlet_server.public_port)
            elif version['id'] == 'v2.0':
                self._paste_in_port(
                    version, 'http://localhost:%s/v2.0/' %
                    CONF.eventlet_server.public_port)
        self.assertThat(data, _VersionsEqual(expected))

    def test_admin_versions(self):
        client = TestClient(self.admin_app)
        resp = client.get('/')
        self.assertEqual(300, resp.status_int)
        data = jsonutils.loads(resp.body)
        expected = VERSIONS_RESPONSE
        for version in expected['versions']['values']:
            if version['id'].startswith('v3'):
                self._paste_in_port(
                    version, 'http://localhost:%s/v3/' %
                    CONF.eventlet_server.admin_port)
            elif version['id'] == 'v2.0':
                self._paste_in_port(
                    version, 'http://localhost:%s/v2.0/' %
                    CONF.eventlet_server.admin_port)
        self.assertThat(data, _VersionsEqual(expected))

    def test_use_site_url_if_endpoint_unset(self):
        self.config_fixture.config(public_endpoint=None, admin_endpoint=None)

        for app in (self.public_app, self.admin_app):
            client = TestClient(app)
            resp = client.get('/')
            self.assertEqual(300, resp.status_int)
            data = jsonutils.loads(resp.body)
            expected = VERSIONS_RESPONSE
            for version in expected['versions']['values']:
                # localhost happens to be the site url for tests
                if version['id'].startswith('v3'):
                    self._paste_in_port(
                        version, 'http://localhost/v3/')
                elif version['id'] == 'v2.0':
                    self._paste_in_port(
                        version, 'http://localhost/v2.0/')
            self.assertThat(data, _VersionsEqual(expected))

    def test_public_version_v2(self):
        client = TestClient(self.public_app)
        resp = client.get('/v2.0/')
        self.assertEqual(200, resp.status_int)
        data = jsonutils.loads(resp.body)
        expected = v2_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v2.0/' %
                            CONF.eventlet_server.public_port)
        self.assertEqual(expected, data)

    def test_admin_version_v2(self):
        client = TestClient(self.admin_app)
        resp = client.get('/v2.0/')
        self.assertEqual(200, resp.status_int)
        data = jsonutils.loads(resp.body)
        expected = v2_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v2.0/' %
                            CONF.eventlet_server.admin_port)
        self.assertEqual(expected, data)

    def test_use_site_url_if_endpoint_unset_v2(self):
        self.config_fixture.config(public_endpoint=None, admin_endpoint=None)
        for app in (self.public_app, self.admin_app):
            client = TestClient(app)
            resp = client.get('/v2.0/')
            self.assertEqual(200, resp.status_int)
            data = jsonutils.loads(resp.body)
            expected = v2_VERSION_RESPONSE
            self._paste_in_port(expected['version'], 'http://localhost/v2.0/')
            self.assertEqual(data, expected)

    def test_public_version_v3(self):
        client = TestClient(self.public_app)
        resp = client.get('/v3/')
        self.assertEqual(200, resp.status_int)
        data = jsonutils.loads(resp.body)
        expected = v3_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v3/' %
                            CONF.eventlet_server.public_port)
        self.assertEqual(expected, data)

    @utils.wip('waiting on bug #1381961')
    def test_admin_version_v3(self):
        client = TestClient(self.admin_app)
        resp = client.get('/v3/')
        self.assertEqual(200, resp.status_int)
        data = jsonutils.loads(resp.body)
        expected = v3_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v3/' %
                            CONF.eventlet_server.admin_port)
        self.assertEqual(expected, data)

    def test_use_site_url_if_endpoint_unset_v3(self):
        self.config_fixture.config(public_endpoint=None, admin_endpoint=None)
        for app in (self.public_app, self.admin_app):
            client = TestClient(app)
            resp = client.get('/v3/')
            self.assertEqual(200, resp.status_int)
            data = jsonutils.loads(resp.body)
            expected = v3_VERSION_RESPONSE
            self._paste_in_port(expected['version'], 'http://localhost/v3/')
            self.assertEqual(expected, data)

    @mock.patch.object(controllers, '_VERSIONS', ['v3'])
    def test_v2_disabled(self):
        client = TestClient(self.public_app)
        # request to /v2.0 should fail
        resp = client.get('/v2.0/')
        self.assertEqual(http_client.NOT_FOUND, resp.status_int)

        # request to /v3 should pass
        resp = client.get('/v3/')
        self.assertEqual(200, resp.status_int)
        data = jsonutils.loads(resp.body)
        expected = v3_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v3/' %
                            CONF.eventlet_server.public_port)
        self.assertEqual(expected, data)

        # only v3 information should be displayed by requests to /
        v3_only_response = {
            "versions": {
                "values": [
                    v3_EXPECTED_RESPONSE
                ]
            }
        }
        self._paste_in_port(v3_only_response['versions']['values'][0],
                            'http://localhost:%s/v3/' %
                            CONF.eventlet_server.public_port)
        resp = client.get('/')
        self.assertEqual(300, resp.status_int)
        data = jsonutils.loads(resp.body)
        self.assertEqual(v3_only_response, data)

    @mock.patch.object(controllers, '_VERSIONS', ['v2.0'])
    def test_v3_disabled(self):
        client = TestClient(self.public_app)
        # request to /v3 should fail
        resp = client.get('/v3/')
        self.assertEqual(http_client.NOT_FOUND, resp.status_int)

        # request to /v2.0 should pass
        resp = client.get('/v2.0/')
        self.assertEqual(200, resp.status_int)
        data = jsonutils.loads(resp.body)
        expected = v2_VERSION_RESPONSE
        self._paste_in_port(expected['version'],
                            'http://localhost:%s/v2.0/' %
                            CONF.eventlet_server.public_port)
        self.assertEqual(expected, data)

        # only v2 information should be displayed by requests to /
        v2_only_response = {
            "versions": {
                "values": [
                    v2_EXPECTED_RESPONSE
                ]
            }
        }
        self._paste_in_port(v2_only_response['versions']['values'][0],
                            'http://localhost:%s/v2.0/' %
                            CONF.eventlet_server.public_port)
        resp = client.get('/')
        self.assertEqual(300, resp.status_int)
        data = jsonutils.loads(resp.body)
        self.assertEqual(v2_only_response, data)

    def _test_json_home(self, path, exp_json_home_data):
        client = TestClient(self.public_app)
        resp = client.get(path, headers={'Accept': 'application/json-home'})

        self.assertThat(resp.status, tt_matchers.Equals('200 OK'))
        self.assertThat(resp.headers['Content-Type'],
                        tt_matchers.Equals('application/json-home'))

        self.assertThat(jsonutils.loads(resp.body),
                        tt_matchers.Equals(exp_json_home_data))

    def test_json_home_v3(self):
        # If the request is /v3 and the Accept header is application/json-home
        # then the server responds with a JSON Home document.

        exp_json_home_data = {
            'resources': V3_JSON_HOME_RESOURCES_INHERIT_DISABLED}

        self._test_json_home('/v3', exp_json_home_data)

    def test_json_home_root(self):
        # If the request is / and the Accept header is application/json-home
        # then the server responds with a JSON Home document.

        exp_json_home_data = copy.deepcopy({
            'resources': V3_JSON_HOME_RESOURCES_INHERIT_DISABLED})
        json_home.translate_urls(exp_json_home_data, '/v3')

        self._test_json_home('/', exp_json_home_data)

    def test_accept_type_handling(self):
        # Accept headers with multiple types and qvalues are handled.

        def make_request(accept_types=None):
            client = TestClient(self.public_app)
            headers = None
            if accept_types:
                headers = {'Accept': accept_types}
            resp = client.get('/v3', headers=headers)
            self.assertThat(resp.status, tt_matchers.Equals('200 OK'))
            return resp.headers['Content-Type']

        JSON = controllers.MimeTypes.JSON
        JSON_HOME = controllers.MimeTypes.JSON_HOME

        JSON_MATCHER = tt_matchers.Equals(JSON)
        JSON_HOME_MATCHER = tt_matchers.Equals(JSON_HOME)

        # Default is JSON.
        self.assertThat(make_request(), JSON_MATCHER)

        # Can request JSON and get JSON.
        self.assertThat(make_request(JSON), JSON_MATCHER)

        # Can request JSONHome and get JSONHome.
        self.assertThat(make_request(JSON_HOME), JSON_HOME_MATCHER)

        # If request JSON, JSON Home get JSON.
        accept_types = '%s, %s' % (JSON, JSON_HOME)
        self.assertThat(make_request(accept_types), JSON_MATCHER)

        # If request JSON Home, JSON get JSON.
        accept_types = '%s, %s' % (JSON_HOME, JSON)
        self.assertThat(make_request(accept_types), JSON_MATCHER)

        # If request JSON Home, JSON;q=0.5 get JSON Home.
        accept_types = '%s, %s;q=0.5' % (JSON_HOME, JSON)
        self.assertThat(make_request(accept_types), JSON_HOME_MATCHER)

        # If request some unknown mime-type, get JSON.
        self.assertThat(make_request(self.getUniqueString()), JSON_MATCHER)

    @mock.patch.object(controllers, '_VERSIONS', [])
    def test_no_json_home_document_returned_when_v3_disabled(self):
        json_home_document = controllers.request_v3_json_home('some_prefix')
        expected_document = {'resources': {}}
        self.assertEqual(expected_document, json_home_document)

    def test_extension_property_method_returns_none(self):
        extension_obj = controllers.Extensions()
        extensions_property = extension_obj.extensions
        self.assertIsNone(extensions_property)


class VersionSingleAppTestCase(unit.TestCase):
    """Tests running with a single application loaded.

    These are important because when Keystone is running in Apache httpd
    there's only one application loaded for each instance.

    """

    def setUp(self):
        super(VersionSingleAppTestCase, self).setUp()
        self.load_backends()

        self.config_fixture.config(
            public_endpoint='http://localhost:%(public_port)d',
            admin_endpoint='http://localhost:%(admin_port)d')

    def config_overrides(self):
        super(VersionSingleAppTestCase, self).config_overrides()
        admin_port = random.randint(10000, 30000)
        public_port = random.randint(40000, 60000)
        self.config_fixture.config(group='eventlet_server',
                                   public_port=public_port,
                                   admin_port=admin_port)

    def _paste_in_port(self, response, port):
        for link in response['links']:
            if link['rel'] == 'self':
                link['href'] = port

    def _test_version(self, app_name):
        def app_port():
            if app_name == 'admin':
                return CONF.eventlet_server.admin_port
            else:
                return CONF.eventlet_server.public_port
        app = self.loadapp('keystone', app_name)
        client = TestClient(app)
        resp = client.get('/')
        self.assertEqual(300, resp.status_int)
        data = jsonutils.loads(resp.body)
        expected = VERSIONS_RESPONSE
        for version in expected['versions']['values']:
            if version['id'].startswith('v3'):
                self._paste_in_port(
                    version, 'http://localhost:%s/v3/' % app_port())
            elif version['id'] == 'v2.0':
                self._paste_in_port(
                    version, 'http://localhost:%s/v2.0/' % app_port())
        self.assertThat(data, _VersionsEqual(expected))

    def test_public(self):
        self._test_version('main')

    def test_admin(self):
        self._test_version('admin')


class VersionInheritEnabledTestCase(unit.TestCase):
    def setUp(self):
        super(VersionInheritEnabledTestCase, self).setUp()
        self.load_backends()
        self.public_app = self.loadapp('keystone', 'main')
        self.admin_app = self.loadapp('keystone', 'admin')

        self.config_fixture.config(
            public_endpoint='http://localhost:%(public_port)d',
            admin_endpoint='http://localhost:%(admin_port)d')

    def config_overrides(self):
        super(VersionInheritEnabledTestCase, self).config_overrides()
        admin_port = random.randint(10000, 30000)
        public_port = random.randint(40000, 60000)
        self.config_fixture.config(group='eventlet_server',
                                   public_port=public_port,
                                   admin_port=admin_port)

        self.config_fixture.config(group='os_inherit', enabled=True)

    def test_json_home_v3(self):
        # If the request is /v3 and the Accept header is application/json-home
        # then the server responds with a JSON Home document.

        client = TestClient(self.public_app)
        resp = client.get('/v3/', headers={'Accept': 'application/json-home'})

        self.assertThat(resp.status, tt_matchers.Equals('200 OK'))
        self.assertThat(resp.headers['Content-Type'],
                        tt_matchers.Equals('application/json-home'))

        exp_json_home_data = {
            'resources': V3_JSON_HOME_RESOURCES_INHERIT_ENABLED}

        self.assertThat(jsonutils.loads(resp.body),
                        tt_matchers.Equals(exp_json_home_data))


class VersionBehindSslTestCase(unit.TestCase):
    def setUp(self):
        super(VersionBehindSslTestCase, self).setUp()
        self.load_backends()
        self.public_app = self.loadapp('keystone', 'main')

    def config_overrides(self):
        super(VersionBehindSslTestCase, self).config_overrides()
        self.config_fixture.config(
            secure_proxy_ssl_header='HTTP_X_FORWARDED_PROTO')

    def _paste_in_port(self, response, port):
        for link in response['links']:
            if link['rel'] == 'self':
                link['href'] = port

    def _get_expected(self, host):
        expected = VERSIONS_RESPONSE
        for version in expected['versions']['values']:
            if version['id'].startswith('v3'):
                self._paste_in_port(version, host + 'v3/')
            elif version['id'] == 'v2.0':
                self._paste_in_port(version, host + 'v2.0/')
        return expected

    def test_versions_without_headers(self):
        client = TestClient(self.public_app)
        host_name = 'host-%d' % random.randint(10, 30)
        host_port = random.randint(10000, 30000)
        host = 'http://%s:%s/' % (host_name, host_port)
        resp = client.get(host)
        self.assertEqual(300, resp.status_int)
        data = jsonutils.loads(resp.body)
        expected = self._get_expected(host)
        self.assertThat(data, _VersionsEqual(expected))

    def test_versions_with_header(self):
        client = TestClient(self.public_app)
        host_name = 'host-%d' % random.randint(10, 30)
        host_port = random.randint(10000, 30000)
        resp = client.get('http://%s:%s/' % (host_name, host_port),
                          headers={'X-Forwarded-Proto': 'https'})
        self.assertEqual(300, resp.status_int)
        data = jsonutils.loads(resp.body)
        expected = self._get_expected('https://%s:%s/' % (host_name,
                                                          host_port))
        self.assertThat(data, _VersionsEqual(expected))
