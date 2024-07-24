# Copyright 2022 OpenStack Foundation
#
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

from oslo_config import cfg

from keystone.conf import utils

oauth2_authn_methods = cfg.ListOpt(
    'oauth2_authn_methods',
    default=['tls_client_auth', 'client_secret_basic'],
    help=utils.fmt(
        """
The OAuth2.0 authentication method supported by the system when user obtains
an access token through the OAuth2.0 token endpoint. This option can be set to
certificate or secret. If the option is not set, the default value is
certificate. When the option is set to secret, the OAuth2.0 token endpoint
uses client_secret_basic method for authentication, otherwise tls_client_auth
method is used for authentication.
"""
    ),
)

oauth2_cert_dn_mapping_id = cfg.StrOpt(
    'oauth2_cert_dn_mapping_id',
    default='oauth2_mapping',
    help=utils.fmt(
        """
Used to define the mapping rule id. When not set, the mapping rule id is
oauth2_mapping.
"""
    ),
)


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [oauth2_authn_methods, oauth2_cert_dn_mapping_id]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
