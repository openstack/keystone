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
import uuid

from oslo_policy import policy as common_policy
import six
from testtools import matchers

import keystone.conf
from keystone import exception
from keystone.policy.backends import rules
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
        return ksfixtures.Policy(self.tmpfilename, self.config_fixture)

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
        # NOTE(dprince): We mix case in the Admin role here to ensure
        # case is ignored
        admin_credentials = {'roles': ['AdMiN']}
        rules.enforce(admin_credentials, lowercase_action, self.target)
        rules.enforce(admin_credentials, uppercase_action, self.target)


class DefaultPolicyTestCase(unit.TestCase):
    def setUp(self):
        super(DefaultPolicyTestCase, self).setUp()

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
        # Oslo policy as we shouldn't have to reload the rules if they have
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

        standard_policy = unit.dirs.etc('policy.json')
        enforcer = common_policy.Enforcer(CONF, policy_file=standard_policy)
        result = enforcer.enforce(action, target, credentials)
        self.assertTrue(result)

        domain_policy = unit.dirs.etc('policy.v3cloudsample.json')
        enforcer = common_policy.Enforcer(CONF, policy_file=domain_policy)
        result = enforcer.enforce(action, target, credentials)
        self.assertTrue(result)

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
