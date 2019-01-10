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

from oslo_policy import policy

IDENTITY = 'identity:%s'
RULE_ADMIN_REQUIRED = 'rule:admin_required'
RULE_ADMIN_OR_OWNER = 'rule:admin_or_owner'
RULE_ADMIN_OR_CREDENTIAL_OWNER = (
    'rule:admin_required or '
    '(rule:owner and user_id:%(target.credential.user_id)s)')
RULE_ADMIN_OR_TARGET_DOMAIN = (
    'rule:admin_required or '
    'project_domain_id:%(target.domain.id)s')
RULE_ADMIN_OR_TARGET_PROJECT = (
    'rule:admin_required or '
    'project_id:%(target.project.id)s')
RULE_ADMIN_OR_TOKEN_SUBJECT = 'rule:admin_or_token_subject'
RULE_REVOKE_EVENT_OR_ADMIN = 'rule:revoke_event_or_admin'
RULE_SERVICE_ADMIN_OR_TOKEN_SUBJECT = 'rule:service_admin_or_token_subject'
RULE_SERVICE_OR_ADMIN = 'rule:service_or_admin'
RULE_TRUST_OWNER = 'user_id:%(trust.trustor_user_id)s'


rules = [
    policy.RuleDefault(
        name='admin_required',
        check_str='role:admin or is_admin:1'),
    policy.RuleDefault(
        name='service_role',
        check_str='role:service'),
    policy.RuleDefault(
        name='service_or_admin',
        check_str='rule:admin_required or rule:service_role'),
    policy.RuleDefault(
        name='owner',
        check_str='user_id:%(user_id)s'),
    policy.RuleDefault(
        name='admin_or_owner',
        check_str='rule:admin_required or rule:owner'),
    policy.RuleDefault(
        name='token_subject',
        check_str='user_id:%(target.token.user_id)s'),
    policy.RuleDefault(
        name='admin_or_token_subject',
        check_str='rule:admin_required or rule:token_subject'),
    policy.RuleDefault(
        name='service_admin_or_token_subject',
        check_str='rule:service_or_admin or rule:token_subject'),
]


def list_rules():
    return rules
