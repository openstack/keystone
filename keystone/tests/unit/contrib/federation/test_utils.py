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

import flask
import uuid

from oslo_config import fixture as config_fixture
from oslo_serialization import jsonutils

from keystone.auth.plugins import mapped
import keystone.conf
from keystone import exception
from keystone.federation import utils as mapping_utils
from keystone.tests import unit
from keystone.tests.unit import mapping_fixtures


CONF = keystone.conf.CONF
FAKE_MAPPING_ID = uuid.uuid4().hex


class MappingRuleEngineTests(unit.BaseTestCase):
    """A class for testing the mapping rule engine."""

    def setUp(self):
        super(MappingRuleEngineTests, self).setUp()
        # create dummy app so we can setup a request context for our
        # tests.
        self.flask_app = flask.Flask(__name__)
        self.cleanup_instance('flask_app')

    def assertValidMappedUserObject(self, mapped_properties,
                                    user_type='ephemeral',
                                    domain_id=None):
        """Check whether mapped properties object has 'user' within.

        According to today's rules, RuleProcessor does not have to issue user's
        id or name. What's actually required is user's type.
        """
        self.assertIn('user', mapped_properties,
                      message='Missing user object in mapped properties')
        user = mapped_properties['user']
        self.assertIn('type', user)
        self.assertEqual(user_type, user['type'])

        if domain_id:
            domain = user['domain']
            domain_name_or_id = domain.get('id') or domain.get('name')
            self.assertEqual(domain_id, domain_name_or_id)

    def test_rule_engine_any_one_of_and_direct_mapping(self):
        """Should return user's name and group id EMPLOYEE_GROUP_ID.

        The ADMIN_ASSERTION should successfully have a match in MAPPING_LARGE.
        They will test the case where `any_one_of` is valid, and there is
        a direct mapping for the users name.

        """
        mapping = mapping_fixtures.MAPPING_LARGE
        assertion = mapping_fixtures.ADMIN_ASSERTION
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
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
        RuleProcessor should raise ValidationError.

        """
        mapping = mapping_fixtures.MAPPING_LARGE
        assertion = mapping_fixtures.BAD_TESTER_ASSERTION
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        self.assertRaises(exception.ValidationError,
                          rp.process,
                          assertion)

    def test_rule_engine_regex_many_groups(self):
        """Should return group CONTRACTOR_GROUP_ID.

        The TESTER_ASSERTION should successfully have a match in
        MAPPING_TESTER_REGEX. This will test the case where many groups
        are in the assertion, and a regex value is used to try and find
        a match.

        """
        mapping = mapping_fixtures.MAPPING_TESTER_REGEX
        assertion = mapping_fixtures.TESTER_ASSERTION
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
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
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
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
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
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
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
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
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
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
        RuleProcessor should yield ValidationError.

        """
        mapping = mapping_fixtures.MAPPING_DEVELOPER_REGEX
        assertion = mapping_fixtures.BAD_DEVELOPER_ASSERTION
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        self.assertRaises(exception.ValidationError,
                          rp.process,
                          assertion)

    def _rule_engine_regex_match_and_many_groups(self, assertion):
        """Should return group DEVELOPER_GROUP_ID and TESTER_GROUP_ID.

        A helper function injecting assertion passed as an argument.
        Expect DEVELOPER_GROUP_ID and TESTER_GROUP_ID in the results.

        """
        mapping = mapping_fixtures.MAPPING_LARGE
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
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

    def test_rule_engine_regex_blacklist(self):
        mapping = mapping_fixtures.MAPPING_GROUPS_BLACKLIST_REGEX
        assertion = mapping_fixtures.EMPLOYEE_PARTTIME_ASSERTION
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        mapped = rp.process(assertion)

        expected = {
            'user': {'type': 'ephemeral'},
            'projects': [],
            'group_ids': [],
            'group_names': [
                {'name': 'Manager', 'domain': {
                    'id': mapping_fixtures.FEDERATED_DOMAIN}}
            ]
        }

        self.assertEqual(expected, mapped)

    def test_rule_engine_regex_whitelist(self):
        mapping = mapping_fixtures.MAPPING_GROUPS_WHITELIST_REGEX
        assertion = mapping_fixtures.EMPLOYEE_PARTTIME_ASSERTION
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        mapped = rp.process(assertion)

        expected = {
            'user': {'type': 'ephemeral'},
            'projects': [],
            'group_ids': [],
            'group_names': [
                {'name': 'Employee', 'domain': {
                    'id': mapping_fixtures.FEDERATED_DOMAIN}},
                {'name': 'PartTimeEmployee', 'domain': {
                    'id': mapping_fixtures.FEDERATED_DOMAIN}}
            ]
        }

        self.assertEqual(expected, mapped)

    def test_rule_engine_fails_after_discarding_nonstring(self):
        """Check whether RuleProcessor discards non string objects.

        Expect RuleProcessor to discard non string object, which
        is required for a correct rule match. RuleProcessor will result with
        ValidationError.

        """
        mapping = mapping_fixtures.MAPPING_SMALL
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        assertion = mapping_fixtures.CONTRACTOR_MALFORMED_ASSERTION
        self.assertRaises(exception.ValidationError,
                          rp.process,
                          assertion)

    def test_using_remote_direct_mapping_that_doesnt_exist_fails(self):
        """Test for the correct error when referring to a bad remote match.

        The remote match must exist in a rule when a local section refers to
        a remote matching using the format (e.g. {0} in a local section).
        """
        mapping = mapping_fixtures.MAPPING_DIRECT_MAPPING_THROUGH_KEYWORD
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        assertion = mapping_fixtures.CUSTOMER_ASSERTION

        self.assertRaises(exception.DirectMappingError,
                          rp.process,
                          assertion)

    def test_rule_engine_returns_group_names(self):
        """Check whether RuleProcessor returns group names with their domains.

        RuleProcessor should return 'group_names' entry with a list of
        dictionaries with two entries 'name' and 'domain' identifying group by
        its name and domain.

        """
        mapping = mapping_fixtures.MAPPING_GROUP_NAMES
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
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
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
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
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
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
        """Test matching multiple values before the blacklist.

        Verifies that the local indexes are correct when matching multiple
        remote values for a field when the field occurs before the blacklist
        entry in the remote rules.

        """
        mapping = mapping_fixtures.MAPPING_GROUPS_BLACKLIST_MULTIPLES
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION_MULTIPLE_GROUPS
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
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
        """Test if the local rule is rejected upon missing domain value.

        This is a variation with a ``whitelist`` filter.

        """
        mapping = mapping_fixtures.MAPPING_GROUPS_WHITELIST_MISSING_DOMAIN
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION_MULTIPLE_GROUPS
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        self.assertRaises(exception.ValidationError, rp.process, assertion)

    def test_rule_engine_blacklist_direct_group_mapping_missing_domain(self):
        """Test if the local rule is rejected upon missing domain value.

        This is a variation with a ``blacklist`` filter.

        """
        mapping = mapping_fixtures.MAPPING_GROUPS_BLACKLIST_MISSING_DOMAIN
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION_MULTIPLE_GROUPS
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        self.assertRaises(exception.ValidationError, rp.process, assertion)

    def test_rule_engine_no_groups_allowed(self):
        """Should return user mapped to no groups.

        The EMPLOYEE_ASSERTION should successfully have a match
        in MAPPING_GROUPS_WHITELIST, but 'whitelist' should filter out
        the group values from the assertion and thus map to no groups.

        """
        mapping = mapping_fixtures.MAPPING_GROUPS_WHITELIST
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertListEqual(mapped_properties['group_names'], [])
        self.assertListEqual(mapped_properties['group_ids'], [])
        self.assertEqual('tbo', mapped_properties['user']['name'])

    def test_mapping_federated_domain_specified(self):
        """Test mapping engine when domain 'ephemeral' is explicitly set.

        For that, we use mapping rule MAPPING_EPHEMERAL_USER and assertion
        EMPLOYEE_ASSERTION

        """
        mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(mapped_properties)

    def test_set_ephemeral_domain_to_ephemeral_users(self):
        """Test auto assigning service domain to ephemeral users.

        Test that ephemeral users will always become members of federated
        service domain. The check depends on ``type`` value which must be set
        to ``ephemeral`` in case of ephemeral user.

        """
        mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER_LOCAL_DOMAIN
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        assertion = mapping_fixtures.CONTRACTOR_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(mapped_properties)

    def test_local_user_local_domain(self):
        """Test that local users can have non-service domains assigned."""
        mapping = mapping_fixtures.MAPPING_LOCAL_USER_LOCAL_DOMAIN
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        assertion = mapping_fixtures.CONTRACTOR_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(
            mapped_properties, user_type='local',
            domain_id=mapping_fixtures.LOCAL_DOMAIN)

    def test_user_identifications_name(self):
        """Test various mapping options and how users are identified.

        This test calls mapped.setup_username() for propagating user object.

        Test plan:
        - Check if the user has proper domain ('federated') set
        - Check if the user has property type set ('ephemeral')
        - Check if user's name is properly mapped from the assertion
        - Check if unique_id is properly set and equal to display_name,
        as it was not explicitly specified in the mapping.

        """
        mapping = mapping_fixtures.MAPPING_USER_IDS
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        assertion = mapping_fixtures.CONTRACTOR_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(mapped_properties)
        self.assertEqual('jsmith', mapped_properties['user']['name'])
        unique_id, display_name = mapped.get_user_unique_id_and_display_name(
            mapped_properties)
        self.assertEqual('jsmith', unique_id)
        self.assertEqual('jsmith', display_name)

    def test_user_identifications_name_and_federated_domain(self):
        """Test various mapping options and how users are identified.

        This test calls mapped.setup_username() for propagating user object.

        Test plan:
        - Check if the user has proper domain ('federated') set
        - Check if the user has propert type set ('ephemeral')
        - Check if user's name is properly mapped from the assertion
        - Check if the unique_id and display_name are properly set

        """
        mapping = mapping_fixtures.MAPPING_USER_IDS
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(mapped_properties)
        unique_id, display_name = mapped.get_user_unique_id_and_display_name(
            mapped_properties)
        self.assertEqual('tbo', display_name)
        self.assertEqual('abc123%40example.com', unique_id)

    def test_user_identification_id(self):
        """Test various mapping options and how users are identified.

        This test calls mapped.setup_username() for propagating user object.

        Test plan:
        - Check if the user has proper domain ('federated') set
        - Check if the user has propert type set ('ephemeral')
        - Check if user's display_name is properly set and equal to unique_id,
        as it was not explicitly specified in the mapping.

        """
        mapping = mapping_fixtures.MAPPING_USER_IDS
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        assertion = mapping_fixtures.ADMIN_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(mapped_properties)
        with self.flask_app.test_request_context():
            unique_id, display_name = (
                mapped.get_user_unique_id_and_display_name(mapped_properties))
        self.assertEqual('bob', unique_id)
        self.assertEqual('bob', display_name)

    def test_get_user_unique_id_and_display_name(self):

        mapping = mapping_fixtures.MAPPING_USER_IDS
        assertion = mapping_fixtures.ADMIN_ASSERTION
        FAKE_MAPPING_ID = uuid.uuid4().hex
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertValidMappedUserObject(mapped_properties)
        with self.flask_app.test_request_context(
                environ_base={'REMOTE_USER': 'remote_user'}):
            unique_id, display_name = (
                mapped.get_user_unique_id_and_display_name(mapped_properties))
        self.assertEqual('bob', unique_id)
        self.assertEqual('remote_user', display_name)

    def test_user_identification_id_and_name(self):
        """Test various mapping options and how users are identified.

        This test calls mapped.setup_username() for propagating user object.

        Test plan:
        - Check if the user has proper domain ('federated') set
        - Check if the user has proper type set ('ephemeral')
        - Check if display_name is properly set from the assertion
        - Check if unique_id is properly set and equal to value hardcoded
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
            rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
            mapped_properties = rp.process(assertion)
            self.assertIsNotNone(mapped_properties)
            self.assertValidMappedUserObject(mapped_properties)
            unique_id, display_name = (
                mapped.get_user_unique_id_and_display_name(mapped_properties)
            )
            self.assertEqual(exp_user_name, display_name)
            self.assertEqual('abc123%40example.com', unique_id)

    def test_whitelist_pass_through(self):
        mapping = mapping_fixtures.MAPPING_GROUPS_WHITELIST_PASS_THROUGH
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        assertion = mapping_fixtures.DEVELOPER_ASSERTION
        mapped_properties = rp.process(assertion)
        self.assertValidMappedUserObject(mapped_properties)

        self.assertEqual('developacct', mapped_properties['user']['name'])
        self.assertEqual('Developer',
                         mapped_properties['group_names'][0]['name'])

    def test_mapping_validation_with_incorrect_local_keys(self):
        mapping = mapping_fixtures.MAPPING_BAD_LOCAL_SETUP
        self.assertRaises(exception.ValidationError,
                          mapping_utils.validate_mapping_structure,
                          mapping)

    def test_mapping_validation_with_user_name_and_domain_name(self):
        mapping = mapping_fixtures.MAPPING_WITH_USERNAME_AND_DOMAINNAME
        mapping_utils.validate_mapping_structure(mapping)

    def test_mapping_validation_with_user_name_and_domain_id(self):
        mapping = mapping_fixtures.MAPPING_WITH_USERNAME_AND_DOMAINID
        mapping_utils.validate_mapping_structure(mapping)

    def test_mapping_validation_with_user_id_and_domain_id(self):
        mapping = mapping_fixtures.MAPPING_WITH_USERID_AND_DOMAINID
        mapping_utils.validate_mapping_structure(mapping)

    def test_mapping_validation_with_group_name_and_domain(self):
        mapping = mapping_fixtures.MAPPING_GROUP_NAMES
        mapping_utils.validate_mapping_structure(mapping)

    def test_mapping_validation_bad_domain(self):
        mapping = mapping_fixtures.MAPPING_BAD_DOMAIN
        self.assertRaises(exception.ValidationError,
                          mapping_utils.validate_mapping_structure,
                          mapping)

    def test_mapping_validation_bad_group(self):
        mapping = mapping_fixtures.MAPPING_BAD_GROUP
        self.assertRaises(exception.ValidationError,
                          mapping_utils.validate_mapping_structure,
                          mapping)

    def test_mapping_validation_with_group_name_without_domain(self):
        mapping = mapping_fixtures.MAPPING_GROUP_NAME_WITHOUT_DOMAIN
        self.assertRaises(exception.ValidationError,
                          mapping_utils.validate_mapping_structure,
                          mapping)

    def test_mapping_validation_with_group_id_and_domain(self):
        mapping = mapping_fixtures.MAPPING_GROUP_ID_WITH_DOMAIN
        self.assertRaises(exception.ValidationError,
                          mapping_utils.validate_mapping_structure,
                          mapping)

    def test_mapping_validation_with_bad_local_type_user_in_assertion(self):
        mapping = mapping_fixtures.MAPPING_BAD_LOCAL_TYPE_USER_IN_ASSERTION
        self.assertRaises(exception.ValidationError,
                          mapping_utils.validate_mapping_structure,
                          mapping)

    def test_mapping_validation_no_local(self):
        mapping = mapping_fixtures.MAPPING_MISSING_LOCAL
        self.assertRaises(exception.ValidationError,
                          mapping_utils.validate_mapping_structure,
                          mapping)

    def test_mapping_validataion_no_remote(self):
        mapping = mapping_fixtures.MAPPING_NO_REMOTE
        self.assertRaises(exception.ValidationError,
                          mapping_utils.validate_mapping_structure,
                          mapping)

    def test_mapping_validation_no_type(self):
        mapping = mapping_fixtures.MAPPING_MISSING_TYPE
        self.assertRaises(exception.ValidationError,
                          mapping_utils.validate_mapping_structure,
                          mapping)

    def test_type_not_in_assertion(self):
        """Test that if the remote "type" is not in the assertion it fails."""
        mapping = mapping_fixtures.MAPPING_GROUPS_WHITELIST_PASS_THROUGH
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        assertion = {uuid.uuid4().hex: uuid.uuid4().hex}
        self.assertRaises(exception.ValidationError,
                          rp.process,
                          assertion)

    def test_rule_engine_groups_mapping_only_one_group(self):
        """Test mapping engine when groups is explicitly set.

        If the groups list has only one group,
        test if the transformation is done correctly

        """
        mapping = mapping_fixtures.MAPPING_GROUPS_WITH_EMAIL
        assertion = mapping_fixtures.GROUPS_ASSERTION_ONLY_ONE_GROUP
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertEqual('jsmith', mapped_properties['user']['name'])
        self.assertEqual('jill@example.com',
                         mapped_properties['user']['email'])
        self.assertEqual('ALL USERS',
                         mapped_properties['group_names'][0]['name'])

    def test_rule_engine_group_ids_mapping_whitelist(self):
        """Test mapping engine when group_ids is explicitly set.

        Also test whitelists on group ids

        """
        mapping = mapping_fixtures.MAPPING_GROUPS_IDS_WHITELIST
        assertion = mapping_fixtures.GROUP_IDS_ASSERTION
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertEqual('opilotte', mapped_properties['user']['name'])
        self.assertListEqual([], mapped_properties['group_names'])
        self.assertCountEqual(['abc123', 'ghi789', 'klm012'],
                              mapped_properties['group_ids'])

    def test_rule_engine_group_ids_mapping_blacklist(self):
        """Test mapping engine when group_ids is explicitly set.

        Also test blacklists on group ids

        """
        mapping = mapping_fixtures.MAPPING_GROUPS_IDS_BLACKLIST
        assertion = mapping_fixtures.GROUP_IDS_ASSERTION
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertEqual('opilotte', mapped_properties['user']['name'])
        self.assertListEqual([], mapped_properties['group_names'])
        self.assertCountEqual(['abc123', 'ghi789', 'klm012'],
                              mapped_properties['group_ids'])

    def test_rule_engine_group_ids_mapping_only_one_group(self):
        """Test mapping engine when group_ids is explicitly set.

        If the group ids list has only one group,
        test if the transformation is done correctly

        """
        mapping = mapping_fixtures.MAPPING_GROUPS_IDS_WHITELIST
        assertion = mapping_fixtures.GROUP_IDS_ASSERTION_ONLY_ONE_GROUP
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        mapped_properties = rp.process(assertion)
        self.assertIsNotNone(mapped_properties)
        self.assertEqual('opilotte', mapped_properties['user']['name'])
        self.assertListEqual([], mapped_properties['group_names'])
        self.assertCountEqual(['210mlk', '321cba'],
                              mapped_properties['group_ids'])

    def test_mapping_projects(self):
        mapping = mapping_fixtures.MAPPING_PROJECTS
        assertion = mapping_fixtures.EMPLOYEE_ASSERTION
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        values = rp.process(assertion)

        self.assertValidMappedUserObject(values)
        expected_username = mapping_fixtures.EMPLOYEE_ASSERTION['UserName']
        self.assertEqual(expected_username, values['user']['name'])

        expected_projects = [
            {
                "name": "Production",
                "roles": [{"name": "observer"}]
            },
            {
                "name": "Staging",
                "roles": [{"name": "member"}]
            },
            {
                "name": "Project for %s" % expected_username,
                "roles": [{"name": "admin"}]
            }
        ]
        self.assertEqual(expected_projects, values['projects'])

    def test_rule_engine_for_groups_and_domain(self):
        """Should return user's groups and group domain.

        The GROUP_DOMAIN_ASSERTION should successfully have a match in
        MAPPING_GROUPS_DOMAIN_OF_USER. This will test the case where a groups
        with its domain will exist`, and return user's groups and group domain.

        """
        mapping = mapping_fixtures.MAPPING_GROUPS_DOMAIN_OF_USER
        assertion = mapping_fixtures.GROUPS_DOMAIN_ASSERTION
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        values = rp.process(assertion)

        self.assertValidMappedUserObject(values)
        user_name = assertion.get('openstack_user')
        user_groups = ['group1', 'group2']  # since we know the input assertion
        groups = values.get('group_names', {})
        group_list = [g.get('name') for g in groups]
        group_ids = values.get('group_ids')
        name = values.get('user', {}).get('name')

        self.assertEqual(user_name, name)
        self.assertEqual(user_groups, group_list)
        self.assertEqual([], group_ids, )


class TestUnicodeAssertionData(unit.BaseTestCase):
    """Ensure that unicode data in the assertion headers works.

    Bug #1525250 reported that something was not getting correctly encoded
    and/or decoded when assertion data contained non-ASCII characters.

    This test class mimics what happens in a real HTTP request.
    """

    def setUp(self):
        super(TestUnicodeAssertionData, self).setUp()
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.config_fixture.config(group='federation',
                                   assertion_prefix='PFX')

    def _pull_mapping_rules_from_the_database(self):
        # NOTE(dstanek): In a live system. The rules are dumped into JSON bytes
        # before being # stored in the database. Upon retrieval the bytes are
        # loaded and the resulting dictionary is full of unicode text strings.
        # Most of tests in this file incorrectly assume the mapping fixture
        # dictionary is the same as what it would look like coming out of the
        # database. The string, when coming out of the database, are all text.
        return jsonutils.loads(jsonutils.dumps(
            mapping_fixtures.MAPPING_UNICODE))

    def _pull_assertion_from_the_request_headers(self):
        # NOTE(dstanek): In a live system the bytes for the assertion are
        # pulled from the HTTP headers. These bytes may be decodable as
        # ISO-8859-1 according to Section 3.2.4 of RFC 7230. Let's assume
        # that our web server plugins are correctly encoding the data.
        # Create a dummy application
        app = flask.Flask(__name__)
        with app.test_request_context(
                path='/path',
                environ_overrides=mapping_fixtures.UNICODE_NAME_ASSERTION):
            data = mapping_utils.get_assertion_params_from_env()
            # NOTE(dstanek): keystone.auth.plugins.mapped
            return dict(data)

    def test_unicode(self):
        mapping = self._pull_mapping_rules_from_the_database()
        assertion = self._pull_assertion_from_the_request_headers()

        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, mapping['rules'])
        values = rp.process(assertion)

        fn = assertion.get('PFX_FirstName')
        ln = assertion.get('PFX_LastName')
        full_name = '%s %s' % (fn, ln)
        user_name = values.get('user', {}).get('name')
        self.assertEqual(full_name, user_name)


class TestMappingLocals(unit.BaseTestCase):
    mapping_split = {
        'rules': [
            {
                'local': [
                    {
                        'user': {'name': '{0}'},
                    },
                    {
                        'group': {'id': 'd34db33f'}
                    }
                ],
                'remote': [
                    {'type': 'idp_username'}
                ]
            }
        ]
    }
    mapping_combined = {
        'rules': [
            {
                'local': [
                    {
                        'user': {'name': '{0}'},
                        'group': {'id': 'd34db33f'}
                    }
                ],
                'remote': [
                    {'type': 'idp_username'}
                ]
            }
        ]
    }
    mapping_with_duplicate = {
        'rules': [
            {
                'local': [
                    {'user': {'name': 'test_{0}'}},
                    {'user': {'name': '{0}'}}
                ],
                'remote': [{'type': 'idp_username'}]
            }
        ]
    }
    assertion = {
        'idp_username': 'a_user'
    }

    def process(self, rules):
        rp = mapping_utils.RuleProcessor(FAKE_MAPPING_ID, rules)
        return rp.process(self.assertion)

    def test_local_list_gets_squashed_into_a_single_dictionary(self):
        expected = {
            'user': {
                'name': 'a_user',
                'type': 'ephemeral'
            },
            'projects': [],
            'group_ids': ['d34db33f'],
            'group_names': []
        }

        mapped_split = self.process(self.mapping_split['rules'])
        mapped_combined = self.process(self.mapping_combined['rules'])

        self.assertEqual(expected, mapped_split)
        self.assertEqual(mapped_split, mapped_combined)

    def test_when_local_list_gets_squashed_first_dict_wins(self):
        expected = {
            'user': {
                'name': 'test_a_user',
                'type': 'ephemeral'
            },
            'projects': [],
            'group_ids': [],
            'group_names': []
        }

        mapped = self.process(self.mapping_with_duplicate['rules'])
        self.assertEqual(expected, mapped)
