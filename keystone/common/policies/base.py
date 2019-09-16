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
RULE_OWNER = 'user_id:%(user_id)s'
RULE_ADMIN_OR_OWNER = 'rule:admin_or_owner'
RULE_ADMIN_OR_CREDENTIAL_OWNER = (
    'rule:admin_required or '
    '(rule:owner and user_id:%(target.credential.user_id)s)')
RULE_ADMIN_OR_TARGET_DOMAIN = (
    'rule:admin_required or '
    'token.project.domain.id:%(target.domain.id)s')
RULE_ADMIN_OR_TARGET_PROJECT = (
    'rule:admin_required or '
    'project_id:%(target.project.id)s')
RULE_ADMIN_OR_TOKEN_SUBJECT = 'rule:admin_or_token_subject'  # nosec
RULE_REVOKE_EVENT_OR_ADMIN = 'rule:revoke_event_or_admin'
RULE_SERVICE_ADMIN_OR_TOKEN_SUBJECT = (
    'rule:service_admin_or_token_subject')  # nosec
RULE_SERVICE_OR_ADMIN = 'rule:service_or_admin'
RULE_TRUST_OWNER = 'user_id:%(trust.trustor_user_id)s'

# We are explicitly setting system_scope:all in these check strings because
# they provide backwards compatibility in the event a deployment sets
# ``keystone.conf [oslo_policy] enforce_scope = False``, which the default.
# Otherwise, this might open up APIs to be more permissive unintentionally if a
# deployment isn't enforcing scope. For example, the identity:get_endpoint
# policy might be ``rule:admin_required`` today and eventually ``role:reader``
# enforcing system scoped tokens. Until enforce_scope=True by default, it would
# be possible for users with the ``reader`` role on a project to access an API
# traditionally reserved for system administrators. Once keystone defaults
# ``keystone.conf [oslo_policy] enforce_scope=True``, the ``system_scope:all``
# bits of these check strings can be removed since that will be handled
# automatically by scope_types in oslo.policy's RuleDefault objects.
SYSTEM_READER = 'role:reader and system_scope:all'
SYSTEM_ADMIN = 'role:admin and system_scope:all'
DOMAIN_READER = 'role:reader and domain_id:%(target.domain_id)s'
RULE_SYSTEM_ADMIN_OR_OWNER = '(' + SYSTEM_ADMIN + ') or rule:owner'
RULE_SYSTEM_READER_OR_OWNER = '(' + SYSTEM_READER + ') or rule:owner'

# Credential and EC2 Credential policies
SYSTEM_READER_OR_CRED_OWNER = (
    '(' + SYSTEM_READER + ') '
    'or user_id:%(target.credential.user_id)s'
)
SYSTEM_ADMIN_OR_CRED_OWNER = (
    '(' + SYSTEM_ADMIN + ') '
    'or user_id:%(target.credential.user_id)s'
)

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
        check_str=RULE_OWNER),
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
