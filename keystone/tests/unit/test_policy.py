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

import json
import os

from oslo_policy import policy as common_policy
import six
from testtools import matchers

from keystone import exception
from keystone.policy.backends import rules
from keystone.tests import unit
from keystone.tests.unit.ksfixtures import temporaryfile


class BasePolicyTestCase(unit.TestCase):
    def setUp(self):
        super(BasePolicyTestCase, self).setUp()
        rules.reset()
        self.addCleanup(rules.reset)
        self.addCleanup(self.clear_cache_safely)

    def clear_cache_safely(self):
        if rules._ENFORCER:
            rules._ENFORCER.clear()


class PolicyFileTestCase(BasePolicyTestCase):
    def setUp(self):
        # self.tmpfilename should exist before setUp super is called
        # this is to ensure it is available for the config_fixture in
        # the config_overrides call.
        self.tempfile = self.useFixture(temporaryfile.SecureTempFile())
        self.tmpfilename = self.tempfile.file_name
        super(PolicyFileTestCase, self).setUp()
        self.target = {}

    def config_overrides(self):
        super(PolicyFileTestCase, self).config_overrides()
        self.config_fixture.config(group='oslo_policy',
                                   policy_file=self.tmpfilename)

    def test_modified_policy_reloads(self):
        action = "example:test"
        empty_credentials = {}
        with open(self.tmpfilename, "w") as policyfile:
            policyfile.write("""{"example:test": []}""")
        rules.enforce(empty_credentials, action, self.target)
        with open(self.tmpfilename, "w") as policyfile:
            policyfile.write("""{"example:test": ["false:false"]}""")
        rules._ENFORCER.clear()
        self.assertRaises(exception.ForbiddenAction, rules.enforce,
                          empty_credentials, action, self.target)

    def test_invalid_policy_raises_error(self):
        action = "example:test"
        empty_credentials = {}
        invalid_json = '{"example:test": [],}'
        with open(self.tmpfilename, "w") as policyfile:
            policyfile.write(invalid_json)
        self.assertRaises(ValueError, rules.enforce,
                          empty_credentials, action, self.target)


class PolicyTestCase(BasePolicyTestCase):
    def setUp(self):
        super(PolicyTestCase, self).setUp()
        # NOTE(vish): preload rules to circumvent reloading from file
        rules.init()
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
        rules._ENFORCER.set_rules(these_rules)

    def test_enforce_nonexistent_action_throws(self):
        action = "example:noexist"
        self.assertRaises(exception.ForbiddenAction, rules.enforce,
                          self.credentials, action, self.target)

    def test_enforce_bad_action_throws(self):
        action = "example:denied"
        self.assertRaises(exception.ForbiddenAction, rules.enforce,
                          self.credentials, action, self.target)

    def test_enforce_good_action(self):
        action = "example:allowed"
        rules.enforce(self.credentials, action, self.target)

    def test_templatized_enforcement(self):
        target_mine = {'project_id': 'fake'}
        target_not_mine = {'project_id': 'another'}
        credentials = {'project_id': 'fake', 'roles': []}
        action = "example:my_file"
        rules.enforce(credentials, action, target_mine)
        self.assertRaises(exception.ForbiddenAction, rules.enforce,
                          credentials, action, target_not_mine)

    def test_early_AND_enforcement(self):
        action = "example:early_and_fail"
        self.assertRaises(exception.ForbiddenAction, rules.enforce,
                          self.credentials, action, self.target)

    def test_early_OR_enforcement(self):
        action = "example:early_or_success"
        rules.enforce(self.credentials, action, self.target)

    def test_ignore_case_role_check(self):
        lowercase_action = "example:lowercase_admin"
        uppercase_action = "example:uppercase_admin"
        # NOTE(dprince) we mix case in the Admin role here to ensure
        # case is ignored
        admin_credentials = {'roles': ['AdMiN']}
        rules.enforce(admin_credentials, lowercase_action, self.target)
        rules.enforce(admin_credentials, uppercase_action, self.target)


class DefaultPolicyTestCase(BasePolicyTestCase):
    def setUp(self):
        super(DefaultPolicyTestCase, self).setUp()
        rules.init()

        self.rules = {
            "default": [],
            "example:exist": [["false:false"]]
        }
        self._set_rules('default')
        self.credentials = {}

        # FIXME(gyee): latest Oslo policy Enforcer class reloads the rules in
        # its enforce() method even though rules has been initialized via
        # set_rules(). To make it easier to do our tests, we're going to
        # monkeypatch load_roles() so it does nothing. This seem like a bug in
        # Oslo policy as we shoudn't have to reload the rules if they have
        # already been set using set_rules().
        self._old_load_rules = rules._ENFORCER.load_rules
        self.addCleanup(setattr, rules._ENFORCER, 'load_rules',
                        self._old_load_rules)
        rules._ENFORCER.load_rules = lambda *args, **kwargs: None

    def _set_rules(self, default_rule):
        these_rules = common_policy.Rules.from_dict(self.rules, default_rule)
        rules._ENFORCER.set_rules(these_rules)

    def test_policy_called(self):
        self.assertRaises(exception.ForbiddenAction, rules.enforce,
                          self.credentials, "example:exist", {})

    def test_not_found_policy_calls_default(self):
        rules.enforce(self.credentials, "example:noexist", {})

    def test_default_not_found(self):
        new_default_rule = "default_noexist"
        # FIXME(gyee): need to overwrite the Enforcer's default_rule first
        # as it is recreating the rules with its own default_rule instead
        # of the default_rule passed in from set_rules(). I think this is a
        # bug in Oslo policy.
        rules._ENFORCER.default_rule = new_default_rule
        self._set_rules(new_default_rule)
        self.assertRaises(exception.ForbiddenAction, rules.enforce,
                          self.credentials, "example:noexist", {})


class PolicyJsonTestCase(unit.TestCase):

    def _load_entries(self, filename):
        return set(json.load(open(filename)))

    def test_json_examples_have_matching_entries(self):
        policy_keys = self._load_entries(unit.dirs.etc('policy.json'))
        cloud_policy_keys = self._load_entries(
            unit.dirs.etc('policy.v3cloudsample.json'))

        policy_extra_keys = ['admin_or_token_subject',
                             'service_admin_or_token_subject',
                             'token_subject', ]
        expected_policy_keys = list(cloud_policy_keys) + policy_extra_keys
        diffs = set(policy_keys).difference(set(expected_policy_keys))

        self.assertThat(diffs, matchers.Equals(set()))

    def test_all_targets_documented(self):
        # All the targets in the sample policy file must be documented in
        # doc/source/policy_mapping.rst.

        policy_keys = self._load_entries(unit.dirs.etc('policy.json'))

        # These keys are in the policy.json but aren't targets.
        policy_rule_keys = [
            'admin_or_owner', 'admin_or_token_subject', 'admin_required',
            'default', 'owner', 'service_admin_or_token_subject',
            'service_or_admin', 'service_role', 'token_subject', ]

        def read_doc_targets():
            # Parse the doc/source/policy_mapping.rst file and return the
            # targets.

            doc_path = os.path.join(
                unit.ROOTDIR, 'doc', 'source', 'policy_mapping.rst')
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
                    yield six.text_type(target)

        doc_targets = list(read_doc_targets())
        self.assertItemsEqual(policy_keys, doc_targets + policy_rule_keys)
