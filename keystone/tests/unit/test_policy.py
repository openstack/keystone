# Copyright 2011 Piston Cloud Computing, Inc.
# All Rights Reserved.

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

import os
import subprocess
from unittest import mock
import uuid

from oslo_policy import policy as common_policy

from keystone.common import policies
from keystone.common.rbac_enforcer import policy
import keystone.conf
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile


CONF = keystone.conf.CONF


class PolicyFileTestCase(unit.TestCase):
    def setUp(self):
        # self.tmpfilename should exist before setUp super is called
        # this is to ensure it is available for the config_fixture in
        # the config_overrides call.
        self.tempfile = self.useFixture(temporaryfile.SecureTempFile())
        self.tmpfilename = self.tempfile.file_name
        super(PolicyFileTestCase, self).setUp()
        self.target = {}

    def _policy_fixture(self):
        return ksfixtures.Policy(
            self.config_fixture, policy_file=self.tmpfilename
        )

    def test_modified_policy_reloads(self):
        action = "example:test"
        empty_credentials = {}
        with open(self.tmpfilename, "w") as policyfile:
            policyfile.write("""{"example:test": []}""")
        policy.enforce(empty_credentials, action, self.target)
        with open(self.tmpfilename, "w") as policyfile:
            policyfile.write("""{"example:test": ["false:false"]}""")
        policy._ENFORCER._enforcer.clear()
        self.assertRaises(exception.ForbiddenAction, policy.enforce,
                          empty_credentials, action, self.target)


class PolicyTestCase(unit.TestCase):
    def setUp(self):
        super(PolicyTestCase, self).setUp()
        self.rules = {
            "true": [],
            "example:allowed": [],
            "example:denied": [["false:false"]],
            "example:get_http": [["http:http://www.example.com"]],
            "example:my_file": [["role:compute_admin"],
                                ["project_id:%(project_id)s"]],
            "example:early_and_fail": [["false:false", "rule:true"]],
            "example:early_or_success": [["rule:true"], ["false:false"]],
            "example:lowercase_admin": [["role:admin"], ["role:sysadmin"]],
            "example:uppercase_admin": [["role:ADMIN"], ["role:sysadmin"]],
        }

        # NOTE(vish): then overload underlying policy engine
        self._set_rules()
        self.credentials = {}
        self.target = {}

    def _set_rules(self):
        these_rules = common_policy.Rules.from_dict(self.rules)
        policy._ENFORCER._enforcer.set_rules(these_rules)

    def test_enforce_nonexistent_action_throws(self):
        action = "example:noexist"
        self.assertRaises(exception.ForbiddenAction, policy.enforce,
                          self.credentials, action, self.target)

    def test_enforce_bad_action_throws(self):
        action = "example:denied"
        self.assertRaises(exception.ForbiddenAction, policy.enforce,
                          self.credentials, action, self.target)

    def test_enforce_good_action(self):
        action = "example:allowed"
        policy.enforce(self.credentials, action, self.target)

    def test_templatized_enforcement(self):
        target_mine = {'project_id': 'fake'}
        target_not_mine = {'project_id': 'another'}
        credentials = {'project_id': 'fake', 'roles': []}
        action = "example:my_file"
        policy.enforce(credentials, action, target_mine)
        self.assertRaises(exception.ForbiddenAction, policy.enforce,
                          credentials, action, target_not_mine)

    def test_early_AND_enforcement(self):
        action = "example:early_and_fail"
        self.assertRaises(exception.ForbiddenAction, policy.enforce,
                          self.credentials, action, self.target)

    def test_early_OR_enforcement(self):
        action = "example:early_or_success"
        policy.enforce(self.credentials, action, self.target)

    def test_ignore_case_role_check(self):
        lowercase_action = "example:lowercase_admin"
        uppercase_action = "example:uppercase_admin"
        # NOTE(dprince): We mix case in the Admin role here to ensure
        # case is ignored
        admin_credentials = {'roles': ['AdMiN']}
        policy.enforce(admin_credentials, lowercase_action, self.target)
        policy.enforce(admin_credentials, uppercase_action, self.target)


class PolicyScopeTypesEnforcementTestCase(unit.TestCase):

    def setUp(self):
        super(PolicyScopeTypesEnforcementTestCase, self).setUp()
        rule = common_policy.RuleDefault(
            name='foo',
            check_str='',
            scope_types=['system']
        )
        policy._ENFORCER._enforcer.register_default(rule)
        self.credentials = {}
        self.action = 'foo'
        self.target = {}

    def test_forbidden_is_raised_if_enforce_scope_is_true(self):
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)
        self.assertRaises(
            exception.ForbiddenAction, policy.enforce, self.credentials,
            self.action, self.target
        )

    def test_warning_message_is_logged_if_enforce_scope_is_false(self):
        self.config_fixture.config(group='oslo_policy', enforce_scope=False)
        expected_msg = (
            'Policy "foo": "" failed scope check. The token used to make the '
            'request was project scoped but the policy requires [\'system\'] '
            'scope. This behavior may change in the future where using the '
            'intended scope is required'
        )
        with mock.patch('warnings.warn') as mock_warn:
            policy.enforce(self.credentials, self.action, self.target)
            mock_warn.assert_called_with(expected_msg)


class PolicyJsonTestCase(unit.TestCase):

    def _get_default_policy_rules(self):
        """Return a dictionary of all in-code policies.

        All policies have a default value that is maintained in code.
        This method returns a dictionary containing all default policies.
        """
        rules = dict()
        for rule in policies.list_rules():
            rules[rule.name] = rule.check_str
        return rules

    def test_policies_loads(self):
        action = 'identity:list_projects'
        target = {'user_id': uuid.uuid4().hex,
                  'user.domain_id': uuid.uuid4().hex,
                  'group.domain_id': uuid.uuid4().hex,
                  'project.domain_id': uuid.uuid4().hex,
                  'project_id': uuid.uuid4().hex,
                  'domain_id': uuid.uuid4().hex}
        credentials = {'username': uuid.uuid4().hex, 'token': uuid.uuid4().hex,
                       'project_name': None, 'user_id': uuid.uuid4().hex,
                       'roles': [u'admin'], 'is_admin': True,
                       'is_admin_project': True, 'project_id': None,
                       'domain_id': uuid.uuid4().hex}

        # The enforcer is setup behind the scenes and registers the in code
        # default policies.
        result = policy._ENFORCER._enforcer.enforce(action, target,
                                                    credentials)
        self.assertTrue(result)

    def test_all_targets_documented(self):
        policy_keys = self._get_default_policy_rules()

        # These keys are in the policy.yaml but aren't targets.
        policy_rule_keys = [
            'admin_or_owner', 'admin_or_token_subject', 'admin_required',
            'owner', 'service_admin_or_token_subject', 'service_or_admin',
            'service_role', 'token_subject', ]

        def read_doc_targets():
            # Parse the doc/source/policy_mapping.rst file and return the
            # targets.

            doc_path = os.path.join(
                unit.ROOTDIR, 'doc', 'source', 'getting-started',
                'policy_mapping.rst')
            with open(doc_path) as doc_file:
                for line in doc_file:
                    if line.startswith('Target'):
                        break
                for line in doc_file:
                    # Skip === line
                    if line.startswith('==='):
                        break
                for line in doc_file:
                    line = line.rstrip()
                    if not line or line.startswith(' '):
                        continue
                    if line.startswith('=='):
                        break
                    target, dummy, dummy = line.partition(' ')
                    yield str(target)

        doc_targets = list(read_doc_targets())
        self.assertCountEqual(policy_keys, doc_targets + policy_rule_keys)


class GeneratePolicyFileTestCase(unit.TestCase):

    def test_policy_generator_from_command_line(self):
        # This test ensures keystone.common.policy:get_enforcer ignores
        # unexpected arguments before handing them off to oslo.config, which
        # will fail and prevent users from generating policy files.
        ret_val = subprocess.Popen(
            ['oslopolicy-policy-generator', '--namespace', 'keystone'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        output = ret_val.communicate()
        self.assertEqual(ret_val.returncode, 0, output)
