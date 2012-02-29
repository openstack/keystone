# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import StringIO
import tempfile
import urllib2

from keystone import config
from keystone import exception
from keystone import test
from keystone.common import policy as common_policy
from keystone.policy.backends import rules


CONF = config.CONF


class PolicyFileTestCase(test.TestCase):
    def setUp(self):
        super(PolicyFileTestCase, self).setUp()
        rules.reset()
        _unused, self.tmpfilename = tempfile.mkstemp()
        self.opt(policy_file=self.tmpfilename)
        self.target = {}

    def tearDown(self):
        super(PolicyFileTestCase, self).tearDown()
        rules.reset()

    def test_modified_policy_reloads(self):
        action = "example:test"
        empty_credentials = {}
        with open(self.tmpfilename, "w") as policyfile:
            policyfile.write("""{"example:test": []}""")
        rules.enforce(empty_credentials, action, self.target)
        with open(self.tmpfilename, "w") as policyfile:
            policyfile.write("""{"example:test": ["false:false"]}""")
        # NOTE(vish): reset stored policy cache so we don't have to sleep(1)
        rules._POLICY_CACHE = {}
        self.assertRaises(exception.Forbidden, rules.enforce,
                          empty_credentials, action, self.target)


class PolicyTestCase(test.TestCase):
    def setUp(self):
        super(PolicyTestCase, self).setUp()
        rules.reset()
        # NOTE(vish): preload rules to circumvent reloading from file
        rules.init()
        brain = {
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
        # NOTE(vish): then overload underlying brain
        common_policy.set_brain(common_policy.HttpBrain(brain))
        self.credentials = {}
        self.target = {}

    def tearDown(self):
        rules.reset()
        super(PolicyTestCase, self).tearDown()

    def test_enforce_nonexistent_action_throws(self):
        action = "example:noexist"
        self.assertRaises(exception.Forbidden, rules.enforce,
                          self.credentials, action, self.target)

    def test_enforce_bad_action_throws(self):
        action = "example:denied"
        self.assertRaises(exception.Forbidden, rules.enforce,
                          self.credentials, action, self.target)

    def test_enforce_good_action(self):
        action = "example:allowed"
        rules.enforce(self.credentials, action, self.target)

    def test_enforce_http_true(self):

        def fakeurlopen(url, post_data):
            return StringIO.StringIO("True")

        self.stubs.Set(urllib2, 'urlopen', fakeurlopen)
        action = "example:get_http"
        target = {}
        result = rules.enforce(self.credentials, action, target)
        self.assertEqual(result, None)

    def test_enforce_http_false(self):

        def fakeurlopen(url, post_data):
            return StringIO.StringIO("False")
        self.stubs.Set(urllib2, 'urlopen', fakeurlopen)
        action = "example:get_http"
        target = {}
        self.assertRaises(exception.Forbidden, rules.enforce,
                          self.credentials, action, target)

    def test_templatized_enforcement(self):
        target_mine = {'project_id': 'fake'}
        target_not_mine = {'project_id': 'another'}
        credentials = {'project_id': 'fake', 'roles': []}
        action = "example:my_file"
        rules.enforce(credentials, action, target_mine)
        self.assertRaises(exception.Forbidden, rules.enforce,
                          credentials, action, target_not_mine)

    def test_early_AND_enforcement(self):
        action = "example:early_and_fail"
        self.assertRaises(exception.Forbidden, rules.enforce,
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


class DefaultPolicyTestCase(test.TestCase):
    def setUp(self):
        super(DefaultPolicyTestCase, self).setUp()
        rules.reset()
        rules.init()

        self.brain = {
            "default": [],
            "example:exist": [["false:false"]]
        }

        self._set_brain('default')
        self.credentials = {}

    def _set_brain(self, default_rule):
        brain = common_policy.HttpBrain(self.brain, default_rule)
        common_policy.set_brain(brain)

    def tearDown(self):
        super(DefaultPolicyTestCase, self).setUp()
        rules.reset()

    def test_policy_called(self):
        self.assertRaises(exception.Forbidden, rules.enforce,
                          self.credentials, "example:exist", {})

    def test_not_found_policy_calls_default(self):
        rules.enforce(self.credentials, "example:noexist", {})

    def test_default_not_found(self):
        self._set_brain("default_noexist")
        self.assertRaises(exception.Forbidden, rules.enforce,
                          self.credentials, "example:noexist", {})
