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

import uuid

from keystone.auth.plugins import mapped
from keystone.contrib.federation import utils as mapping_utils
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import mapping_fixtures


class MappingRuleEngineTests(unit.BaseTestCase):
    """A class for testing the mapping rule engine."""

    def assertValidMappedUserObject(self, mapped_properties,
                                    user_type='ephemeral',
                                    domain_id=None):
        """Check whether mapped properties object has 'user' within.

        According to today's rules, RuleProcessor does not have to issue user's
        id or name. What's actually required is user's type and for ephemeral
        users that would be service domain named 'Federated'.
        """
        self.assertIn('user', mapped_properties,
                      message='Missing user object in mapped properties')
        user = mapped_properties['user']
        self.assertIn('type', user)
        self.assertEqual(user_type, user['type'])
        self.assertIn('domain', user)
        domain = user['domain']
        domain_name_or_id = domain.get('id') or domain.get('name')
        domain_ref = domain_id or 'Federated'
        self.assertEqual(domain_ref, domain_name_or_id)

    def test_rule_engine_any_one_of_and_direct_mapping(self):
        """Should return user's name and group id EMPLOYEE_GROUP_ID.

        The ADMIN_ASSERTION should successfully have a match in MAPPING_LARGE.
        They will test the case where `any_one_of` is valid, and there is
        a direct mapping for the users name.

        """

        mapping = mapping_fixtures.MAPPING_LARGE
        assertion = mapping_fixtures.ADMIN_ASSERTION
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        values = rp.process(assertion)

        fn = assertion.get('FirstName')
        ln = assertion.get('LastName')
        full_name = '%s %s' % (fn, ln)
        group_ids = values.get('group_ids')
        user_name = values.get('user', {}).get('name')

        self.assertIn(mapping_fixtures.EMPLOYEE_GROUP_ID, group_ids)
        self.assertEqual(full_name, user_name)

    def test_rule_engine_no_regex_match(self):
        """Should deny authorization, the email of the tester won't match.

        This will not match since the email in the assertion will fail
        the regex test. It is set to match any @example.com address.
        But the incoming value is set to eviltester@example.org.
        RuleProcessor should return list of empty group_ids.

        """

        mapping = mapping_fixtures.MAPPING_LARGE
        assertion = mapping_fixtures.BAD_TESTER_ASSERTION
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        mapped_properties = rp.process(assertion)

        self.assertValidMappedUserObject(mapped_properties)
        self.assertIsNone(mapped_properties['user'].get('name'))
        self.assertListEqual(list(), mapped_properties['group_ids'])

    def test_rule_engine_regex_many_groups(self):
        """Should return group CONTRACTOR_GROUP_ID.

        The TESTER_ASSERTION should successfully have a match in
        MAPPING_TESTER_REGEX. This will test the case where many groups
        are in the assertion, and a regex value is used to try and find
        a match.

        """

        mapping = mapping_fixtures.MAPPING_TESTER_REGEX
        assertion = mapping_fixtures.TESTER_ASSERTION
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        values = rp.process(assertion)

        self.assertValidMappedUserObject(values)
        user_name = assertion.get('UserName')
        group_ids = values.get('group_ids')
        name = values.get('user', {}).get('name')

        self.assertEqual(user_name, name)
        self.assertIn(mapping_fixtures.TESTER_GROUP_ID, group_ids)

    def test_rule_engine_any_one_of_many_rules(self):
        """Should return group CONTRACTOR_GROUP_ID.

        The CONTRACTOR_ASSERTION should successfully have a match in
        MAPPING_SMALL. This will test the case where many rules
        must be matched, including an `any_one_of`, and a direct
        mapping.

        """

        mapping = mapping_fixtures.MAPPING_SMALL
        assertion = mapping_fixtures.CONTRACTOR_ASSERTION
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        values = rp.process(assertion)

        self.assertValidMappedUserObject(values)
        user_name = assertion.get('UserName')
        group_ids = values.get('group_ids')
        name = values.get('user', {}).get('name')

        self.assertEqual(user_name, name)
        self.assertIn(mapping_fixtures.CONTRACTOR_GROUP_ID, group_ids)

    def test_rule_engine_not_any_of_and_direct_mapping(self):
        """Should return user's name and email.

        The CUSTOMER_ASSERTION should successfully have a match in
        MAPPING_LARGE. This will test the case where a requirement
        has `not_any_of`, and direct mapping to a username, no group.

        """

        mapping = mapping_fixtures.MAPPING_LARGE
        assertion = mapping_fixtures.CUSTOMER_ASSERTION
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        values = rp.process(assertion)

        self.assertValidMappedUserObject(values)
        user_name = assertion.get('UserName')
        group_ids = values.get('group_ids')
        name = values.get('user', {}).get('name')

        self.assertEqual(user_name, name)
        self.assertEqual([], group_ids,)

    def test_rule_engine_not_any_of_many_rules(self):
        """Should return group EMPLOYEE_GROUP_ID.

        The EMPLOYEE_ASSERTION should successfully have a match in
        MAPPING_SMALL. This will test the case where many remote
        rules must be matched, including a `not_any_of`.

        """

        mapping = mapping_fixtures.MAPPING_SMALL
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        values = rp.process(assertion)

        self.assertValidMappedUserObject(values)
        user_name = assertion.get('UserName')
        group_ids = values.get('group_ids')
        name = values.get('user', {}).get('name')

        self.assertEqual(user_name, name)
        self.assertIn(mapping_fixtures.EMPLOYEE_GROUP_ID, group_ids)

    def test_rule_engine_not_any_of_regex_verify_pass(self):
        """Should return group DEVELOPER_GROUP_ID.

        The DEVELOPER_ASSERTION should successfully have a match in
        MAPPING_DEVELOPER_REGEX. This will test the case where many
        remote rules must be matched, including a `not_any_of`, with
        regex set to True.

        """

        mapping = mapping_fixtures.MAPPING_DEVELOPER_REGEX
        assertion = mapping_fixtures.DEVELOPER_ASSERTION
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        values = rp.process(assertion)

        self.assertValidMappedUserObject(values)
        user_name = assertion.get('UserName')
        group_ids = values.get('group_ids')
        name = values.get('user', {}).get('name')

        self.assertEqual(user_name, name)
        self.assertIn(mapping_fixtures.DEVELOPER_GROUP_ID, group_ids)

    def test_rule_engine_not_any_of_regex_verify_fail(self):
        """Should deny authorization.

        The email in the assertion will fail the regex test.
        It is set to reject any @example.org address, but the
        incoming value is set to evildeveloper@example.org.
        RuleProcessor should return list of empty group_ids.

        """

        mapping = mapping_fixtures.MAPPING_DEVELOPER_REGEX
        assertion = mapping_fixtures.BAD_DEVELOPER_ASSERTION
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        mapped_properties = rp.process(assertion)

        self.assertValidMappedUserObject(mapped_properties)
        self.assertIsNone(mapped_properties['user'].get('name'))
        self.assertListEqual(list(), mapped_properties['group_ids'])

    def _rule_engine_regex_match_and_many_groups(self, assertion):
        """Should return group DEVELOPER_GROUP_ID and TESTER_GROUP_ID.

        A helper function injecting assertion passed as an argument.
        Expect DEVELOPER_GROUP_ID and TESTER_GROUP_ID in the results.

        """

        mapping = mapping_fixtures.MAPPING_LARGE
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        values = rp.process(assertion)

        user_name = assertion.get('UserName')
        group_ids = values.get('group_ids')
        name = values.get('user', {}).get('name')

        self.assertValidMappedUserObject(values)
        self.assertEqual(user_name, name)
        self.assertIn(mapping_fixtures.DEVELOPER_GROUP_ID, group_ids)
        self.assertIn(mapping_fixtures.TESTER_GROUP_ID, group_ids)

    def test_rule_engine_regex_match_and_many_groups(self):
        """Should return group DEVELOPER_GROUP_ID and TESTER_GROUP_ID.

        The TESTER_ASSERTION should successfully have a match in
        MAPPING_LARGE. This will test a successful regex match
        for an `any_one_of` evaluation type, and will have many
        groups returned.

        """
        self._rule_engine_regex_match_and_many_groups(
            mapping_fixtures.TESTER_ASSERTION)

    def test_rule_engine_discards_nonstring_objects(self):
        """Check whether RuleProcessor discards non string objects.

        Despite the fact that assertion is malformed and contains
        non string objects, RuleProcessor should correctly discard them and
        successfully have a match in MAPPING_LARGE.

        """
        self._rule_engine_regex_match_and_many_groups(
            mapping_fixtures.MALFORMED_TESTER_ASSERTION)

    def test_rule_engine_fails_after_discarding_nonstring(self):
        """Check whether RuleProcessor discards non string objects.

        Expect RuleProcessor to discard non string object, which
        is required for a correct rule match. RuleProcessor will result with
        empty list of groups.

        """
        mapping = mapping_fixtures.MAPPING_SMALL
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        assertion = mapping_fixtures.CONTRACTOR_MALFORMED_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertValidMappedUserObject(mapped_properties)
        self.assertIsNone(mapped_properties['user'].get('name'))
        self.assertListEqual(list(), mapped_properties['group_ids'])

    def test_rule_engine_returns_group_names(self):
        """Check whether RuleProcessor returns group names with their domains.

        RuleProcessor should return 'group_names' entry with a list of
        dictionaries with two entries 'name' and 'domain' identifying group by
        its name and domain.

        """
        mapping = mapping_fixtures.MAPPING_GROUP_NAMES
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(mapped_properties)
        reference = {
            mapping_fixtures.DEVELOPER_GROUP_NAME:
            {
                "name": mapping_fixtures.DEVELOPER_GROUP_NAME,
                "domain": {
                    "name": mapping_fixtures.DEVELOPER_GROUP_DOMAIN_NAME
                }
            },
            mapping_fixtures.TESTER_GROUP_NAME:
            {
                "name": mapping_fixtures.TESTER_GROUP_NAME,
                "domain": {
                    "id": mapping_fixtures.DEVELOPER_GROUP_DOMAIN_ID
                }
            }
        }
        for rule in mapped_properties['group_names']:
            self.assertDictEqual(reference.get(rule.get('name')), rule)

    def test_rule_engine_whitelist_and_direct_groups_mapping(self):
        """Should return user's groups Developer and Contractor.

        The EMPLOYEE_ASSERTION_MULTIPLE_GROUPS should successfully have a match
        in MAPPING_GROUPS_WHITELIST. It will test the case where 'whitelist'
        correctly filters out Manager and only allows Developer and Contractor.

        """

        mapping = mapping_fixtures.MAPPING_GROUPS_WHITELIST
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION_MULTIPLE_GROUPS
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)

        reference = {
            mapping_fixtures.DEVELOPER_GROUP_NAME:
            {
                "name": mapping_fixtures.DEVELOPER_GROUP_NAME,
                "domain": {
                    "id": mapping_fixtures.DEVELOPER_GROUP_DOMAIN_ID
                }
            },
            mapping_fixtures.CONTRACTOR_GROUP_NAME:
            {
                "name": mapping_fixtures.CONTRACTOR_GROUP_NAME,
                "domain": {
                    "id": mapping_fixtures.DEVELOPER_GROUP_DOMAIN_ID
                }
            }
        }
        for rule in mapped_properties['group_names']:
            self.assertDictEqual(reference.get(rule.get('name')), rule)

        self.assertEqual('tbo', mapped_properties['user']['name'])
        self.assertEqual([], mapped_properties['group_ids'])

    def test_rule_engine_blacklist_and_direct_groups_mapping(self):
        """Should return user's group Developer.

        The EMPLOYEE_ASSERTION_MULTIPLE_GROUPS should successfully have a match
        in MAPPING_GROUPS_BLACKLIST. It will test the case where 'blacklist'
        correctly filters out Manager and Developer and only allows Contractor.

        """

        mapping = mapping_fixtures.MAPPING_GROUPS_BLACKLIST
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION_MULTIPLE_GROUPS
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)

        reference = {
            mapping_fixtures.CONTRACTOR_GROUP_NAME:
            {
                "name": mapping_fixtures.CONTRACTOR_GROUP_NAME,
                "domain": {
                    "id": mapping_fixtures.DEVELOPER_GROUP_DOMAIN_ID
                }
            }
        }
        for rule in mapped_properties['group_names']:
            self.assertDictEqual(reference.get(rule.get('name')), rule)
        self.assertEqual('tbo', mapped_properties['user']['name'])
        self.assertEqual([], mapped_properties['group_ids'])

    def test_rule_engine_blacklist_and_direct_groups_mapping_multiples(self):
        """Tests matching multiple values before the blacklist.

        Verifies that the local indexes are correct when matching multiple
        remote values for a field when the field occurs before the blacklist
        entry in the remote rules.

        """

        mapping = mapping_fixtures.MAPPING_GROUPS_BLACKLIST_MULTIPLES
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION_MULTIPLE_GROUPS
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)

        reference = {
            mapping_fixtures.CONTRACTOR_GROUP_NAME:
            {
                "name": mapping_fixtures.CONTRACTOR_GROUP_NAME,
                "domain": {
                    "id": mapping_fixtures.DEVELOPER_GROUP_DOMAIN_ID
                }
            }
        }
        for rule in mapped_properties['group_names']:
            self.assertDictEqual(reference.get(rule.get('name')), rule)
        self.assertEqual('tbo', mapped_properties['user']['name'])
        self.assertEqual([], mapped_properties['group_ids'])

    def test_rule_engine_whitelist_direct_group_mapping_missing_domain(self):
        """Test if the local rule is rejected upon missing domain value

        This is a variation with a ``whitelist`` filter.

        """
        mapping = mapping_fixtures.MAPPING_GROUPS_WHITELIST_MISSING_DOMAIN
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION_MULTIPLE_GROUPS
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        self.assertRaises(exception.ValidationError, rp.process, assertion)

    def test_rule_engine_blacklist_direct_group_mapping_missing_domain(self):
        """Test if the local rule is rejected upon missing domain value

        This is a variation with a ``blacklist`` filter.

        """
        mapping = mapping_fixtures.MAPPING_GROUPS_BLACKLIST_MISSING_DOMAIN
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION_MULTIPLE_GROUPS
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        self.assertRaises(exception.ValidationError, rp.process, assertion)

    def test_rule_engine_no_groups_allowed(self):
        """Should return user mapped to no groups.

        The EMPLOYEE_ASSERTION should successfully have a match
        in MAPPING_GROUPS_WHITELIST, but 'whitelist' should filter out
        the group values from the assertion and thus map to no groups.

        """
        mapping = mapping_fixtures.MAPPING_GROUPS_WHITELIST
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertListEqual(mapped_properties['group_names'], [])
        self.assertListEqual(mapped_properties['group_ids'], [])
        self.assertEqual('tbo', mapped_properties['user']['name'])

    def test_mapping_federated_domain_specified(self):
        """Test mapping engine when domain 'ephemeral' is explicitely set.

        For that, we use mapping rule MAPPING_EPHEMERAL_USER and assertion
        EMPLOYEE_ASSERTION

        """
        mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(mapped_properties)

    def test_create_user_object_with_bad_mapping(self):
        """Test if user object is created even with bad mapping.

        User objects will be created by mapping engine always as long as there
        is corresponding local rule.  This test shows, that even with assertion
        where no group names nor ids are matched, but there is 'blind' rule for
        mapping user, such object will be created.

        In this test MAPPING_EHPEMERAL_USER expects UserName set to jsmith
        whereas value from assertion is 'tbo'.

        """
        mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        assertion = mapping_fixtures.CONTRACTOR_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(mapped_properties)

        self.assertNotIn('id', mapped_properties['user'])
        self.assertNotIn('name', mapped_properties['user'])

    def test_set_ephemeral_domain_to_ephemeral_users(self):
        """Test auto assigning service domain to ephemeral users.

        Test that ephemeral users will always become members of federated
        service domain. The check depends on ``type`` value which must be set
        to ``ephemeral`` in case of ephemeral user.

        """
        mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER_LOCAL_DOMAIN
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        assertion = mapping_fixtures.CONTRACTOR_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(mapped_properties)

    def test_local_user_local_domain(self):
        """Test that local users can have non-service domains assigned."""
        mapping = mapping_fixtures.MAPPING_LOCAL_USER_LOCAL_DOMAIN
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        assertion = mapping_fixtures.CONTRACTOR_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(
            mapped_properties, user_type='local',
            domain_id=mapping_fixtures.LOCAL_DOMAIN)

    def test_user_identifications_name(self):
        """Test varius mapping options and how users are identified.

        This test calls mapped.setup_username() for propagating user object.

        Test plan:
        - Check if the user has proper domain ('federated') set
        - Check if the user has property type set ('ephemeral')
        - Check if user's name is properly mapped from the assertion
        - Check if user's id is properly set and equal to name, as it was not
        explicitely specified in the mapping.

        """
        mapping = mapping_fixtures.MAPPING_USER_IDS
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        assertion = mapping_fixtures.CONTRACTOR_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(mapped_properties)
        mapped.setup_username({}, mapped_properties)
        self.assertEqual('jsmith', mapped_properties['user']['id'])
        self.assertEqual('jsmith', mapped_properties['user']['name'])

    def test_user_identifications_name_and_federated_domain(self):
        """Test varius mapping options and how users are identified.

        This test calls mapped.setup_username() for propagating user object.

        Test plan:
        - Check if the user has proper domain ('federated') set
        - Check if the user has propert type set ('ephemeral')
        - Check if user's name is properly mapped from the assertion
        - Check if user's id is properly set and equal to name, as it was not
        explicitely specified in the mapping.

        """
        mapping = mapping_fixtures.MAPPING_USER_IDS
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(mapped_properties)
        mapped.setup_username({}, mapped_properties)
        self.assertEqual('tbo', mapped_properties['user']['name'])
        self.assertEqual('abc123%40example.com',
                         mapped_properties['user']['id'])

    def test_user_identification_id(self):
        """Test varius mapping options and how users are identified.

        This test calls mapped.setup_username() for propagating user object.

        Test plan:
        - Check if the user has proper domain ('federated') set
        - Check if the user has propert type set ('ephemeral')
        - Check if user's id is properly mapped from the assertion
        - Check if user's name is properly set and equal to id, as it was not
        explicitely specified in the mapping.

        """
        mapping = mapping_fixtures.MAPPING_USER_IDS
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        assertion = mapping_fixtures.ADMIN_ASSERTION
        mapped_properties = rp.process(assertion)
        context = {'environment': {}}
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(mapped_properties)
        mapped.setup_username(context, mapped_properties)
        self.assertEqual('bob', mapped_properties['user']['name'])
        self.assertEqual('bob', mapped_properties['user']['id'])

    def test_user_identification_id_and_name(self):
        """Test varius mapping options and how users are identified.

        This test calls mapped.setup_username() for propagating user object.

        Test plan:
        - Check if the user has proper domain ('federated') set
        - Check if the user has proper type set ('ephemeral')
        - Check if user's name is properly mapped from the assertion
        - Check if user's id is properly set and and equal to value hardcoded
        in the mapping

        This test does two iterations with different assertions used as input
        for the Mapping Engine.  Different assertions will be matched with
        different rules in the ruleset, effectively issuing different user_id
        (hardcoded values). In the first iteration, the hardcoded user_id is
        not url-safe and we expect Keystone to make it url safe. In the latter
        iteration, provided user_id is already url-safe and we expect server
        not to change it.

        """
        testcases = [(mapping_fixtures.CUSTOMER_ASSERTION, 'bwilliams'),
                     (mapping_fixtures.EMPLOYEE_ASSERTION, 'tbo')]
        for assertion, exp_user_name in testcases:
            mapping = mapping_fixtures.MAPPING_USER_IDS
            rp = mapping_utils.RuleProcessor(mapping['rules'])
            mapped_properties = rp.process(assertion)
            context = {'environment': {}}
            self.assertIsNotNone(mapped_properties)
            self.assertValidMappedUserObject(mapped_properties)
            mapped.setup_username(context, mapped_properties)
            self.assertEqual(exp_user_name, mapped_properties['user']['name'])
            self.assertEqual('abc123%40example.com',
                             mapped_properties['user']['id'])

    def test_whitelist_pass_through(self):
        mapping = mapping_fixtures.MAPPING_GROUPS_WHITELIST_PASS_THROUGH
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        assertion = mapping_fixtures.DEVELOPER_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertValidMappedUserObject(mapped_properties)

        self.assertEqual('developacct', mapped_properties['user']['name'])
        self.assertEqual('Developer',
                         mapped_properties['group_names'][0]['name'])

    def test_type_not_in_assertion(self):
        """Test that if the remote "type" is not in the assertion it fails."""
        mapping = mapping_fixtures.MAPPING_GROUPS_WHITELIST_PASS_THROUGH
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        assertion = {uuid.uuid4().hex: uuid.uuid4().hex}
        mapped_properties = rp.process(assertion)
        self.assertValidMappedUserObject(mapped_properties)

        self.assertNotIn('id', mapped_properties['user'])
        self.assertNotIn('name', mapped_properties['user'])
