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

from oslo_policy import _checks
from oslo_policy import policy
from oslo_upgradecheck import upgradecheck

from keystone.common import rbac_enforcer
import keystone.conf

CONF = keystone.conf.CONF
ENFORCER = rbac_enforcer.RBACEnforcer


class Checks(upgradecheck.UpgradeCommands):
    """Programmable upgrade checks.

    Each method here should be a programmable check that helps check for things
    that might cause issues for deployers in the upgrade process. A good
    example of an upgrade check would be to ensure all roles defined in
    policies actually exist within the roles backend.
    """

    def check_trust_policies_are_not_empty(self):
        enforcer = policy.Enforcer(CONF)
        ENFORCER.register_rules(enforcer)
        enforcer.load_rules()
        rules = [
            'identity:list_trusts',
            'identity:delete_trust',
            'identity:get_trust',
            'identity:list_roles_for_trust'
        ]
        failed_rules = []
        for rule in rules:
            current_rule = enforcer.rules.get(rule)
            if isinstance(current_rule, _checks.TrueCheck):
                failed_rules.append(rule)
        if any(failed_rules):
            return upgradecheck.Result(
                upgradecheck.Code.FAILURE,
                "Policy check string for rules \"%s\" are overridden to "
                "\"\", \"@\", or []. In the next release, this will cause "
                "these rules to be fully permissive as hardcoded enforcement "
                "will be removed. To correct this issue, either stop "
                "overriding these rules in config to accept the defaults, or "
                "explicitly set check strings that are not empty." %
                "\", \"".join(failed_rules)
            )
        return upgradecheck.Result(
            upgradecheck.Code.SUCCESS, 'Trust policies are safe.')

    _upgrade_checks = (
        ("Check trust policies are not empty",
         check_trust_policies_are_not_empty),
    )


def main():
    keystone.conf.configure()
    return upgradecheck.main(CONF, 'keystone', Checks())
