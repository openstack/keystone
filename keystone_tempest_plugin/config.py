# Copyright 2016 Red Hat, Inc.
# All Rights Reserved.
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

identity_feature_option = [
    cfg.BoolOpt('federation',
                default=False,
                help='Does the environment support the Federated Identity '
                     'feature?'),
]

fed_scenario_group = cfg.OptGroup(name='fed_scenario',
                                  title='Federation Scenario Tests Options')

FedScenarioGroup = [
    # Identity Provider
    cfg.StrOpt('idp_id',
               help='The Identity Provider ID'),
    cfg.ListOpt('idp_remote_ids',
                default=[],
                help='The Identity Provider remote IDs list'),
    cfg.StrOpt('idp_username',
               help='Username used to login in the Identity Provider'),
    cfg.StrOpt('idp_password',
               help='Password used to login in the Identity Provider'),
    cfg.StrOpt('idp_ecp_url',
               help='Identity Provider SAML2/ECP URL'),

    # Mapping rules
    cfg.StrOpt('mapping_remote_type',
               help='The assertion attribute to be used in the remote rules'),
    cfg.StrOpt('mapping_user_name',
               default='{0}',
               help='The username to be used in the local rules.'),
    cfg.StrOpt('mapping_group_name',
               default='federated_users',
               help='The group name to be used in the local rules. The group '
                    'must have at least one assignment in one project.'),
    cfg.StrOpt('mapping_group_domain_name',
               default='federated_domain',
               help='The domain name where the "mapping_group_name" is '
                    'created.'),

    # Protocol
    cfg.StrOpt('protocol_id',
               default='mapped',
               help='The Protocol ID')
]
