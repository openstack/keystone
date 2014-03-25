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

import random
import uuid

from keystone.auth import controllers as auth_controllers
from keystone.common import dependency
from keystone.common import serializer
from keystone.common import sql
from keystone.common.sql import migration_helpers
from keystone import config
from keystone import contrib
from keystone.contrib.federation import controllers as federation_controllers
from keystone.contrib.federation import utils as mapping_utils
from keystone import exception
from keystone.openstack.common.db.sqlalchemy import migration
from keystone.openstack.common import importutils
from keystone.openstack.common import jsonutils
from keystone.openstack.common import log
from keystone.tests import mapping_fixtures
from keystone.tests import test_v3


CONF = config.CONF
LOG = log.getLogger(__name__)


def dummy_validator(*args, **kwargs):
    pass


@dependency.requires('federation_api')
class FederationTests(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'federation'
    EXTENSION_TO_ADD = 'federation_extension'

    def setup_database(self):
        super(FederationTests, self).setup_database()
        package_name = '.'.join((contrib.__name__, self.EXTENSION_NAME))
        package = importutils.import_module(package_name)
        abs_path = migration_helpers.find_migrate_repo(package)
        migration.db_version_control(sql.get_engine(), abs_path)
        migration.db_sync(sql.get_engine(), abs_path)


class FederatedIdentityProviderTests(FederationTests):
    """A test class for Identity Providers."""

    idp_keys = ['description', 'enabled']

    default_body = {'description': None, 'enabled': True}

    def base_url(self, suffix=None):
        if suffix is not None:
            return '/OS-FEDERATION/identity_providers/' + str(suffix)
        return '/OS-FEDERATION/identity_providers'

    def _fetch_attribute_from_response(self, resp, parameter,
                                       assert_is_not_none=True):
        """Fetch single attribute from TestResponse object."""
        result = resp.result.get(parameter)
        if assert_is_not_none:
            self.assertIsNotNone(result)
        return result

    def _create_and_decapsulate_response(self, body=None):
        """Create IdP and fetch it's random id along with entity."""
        default_resp = self._create_default_idp(body=body)
        idp = self._fetch_attribute_from_response(default_resp,
                                                  'identity_provider')
        self.assertIsNotNone(idp)
        idp_id = idp.get('id')
        return (idp_id, idp)

    def _get_idp(self, idp_id):
        """Fetch IdP entity based on it's id."""
        url = self.base_url(suffix=idp_id)
        resp = self.get(url)
        return resp

    def _create_default_idp(self, body=None):
        """Create default IdP."""
        url = self.base_url(suffix=uuid.uuid4().hex)
        if body is None:
            body = self._http_idp_input()
        resp = self.put(url, body={'identity_provider': body},
                        expected_status=201)
        return resp

    def _http_idp_input(self, **kwargs):
        """Create default input for IdP data."""
        body = None
        if 'body' not in kwargs:
            body = self.default_body.copy()
            body['description'] = uuid.uuid4().hex
        else:
            body = kwargs['body']
        return body

    def _assign_protocol_to_idp(self, idp_id=None, proto=None, url=None,
                                mapping_id=None, validate=True, **kwargs):
        if url is None:
            url = self.base_url(suffix='%(idp_id)s/protocols/%(protocol_id)s')
        if idp_id is None:
            idp_id, _ = self._create_and_decapsulate_response()
        if proto is None:
            proto = uuid.uuid4().hex
        if mapping_id is None:
            mapping_id = uuid.uuid4().hex
        body = {'mapping_id': mapping_id}
        url = url % {'idp_id': idp_id, 'protocol_id': proto}
        resp = self.put(url, body={'protocol': body}, **kwargs)
        if validate:
            self.assertValidResponse(resp, 'protocol', dummy_validator,
                                     keys_to_check=['id', 'mapping_id'],
                                     ref={'id': proto,
                                          'mapping_id': mapping_id})
        return (resp, idp_id, proto)

    def _get_protocol(self, idp_id, protocol_id):
        url = "%s/protocols/%s" % (idp_id, protocol_id)
        url = self.base_url(suffix=url)
        r = self.get(url)
        return r

    def test_create_idp(self):
        """Creates the IdentityProvider entity."""

        keys_to_check = self.idp_keys
        body = self._http_idp_input()
        resp = self._create_default_idp(body=body)
        self.assertValidResponse(resp, 'identity_provider', dummy_validator,
                                 keys_to_check=keys_to_check,
                                 ref=body)

    def test_list_idps(self, iterations=5):
        """Lists all available IdentityProviders.

        This test collects ids of created IdPs and
        intersects it with the list of all available IdPs.
        List of all IdPs can be a superset of IdPs created in this test,
        because other tests also create IdPs.

        """
        def get_id(resp):
            r = self._fetch_attribute_from_response(resp,
                                                    'identity_provider')
            return r.get('id')

        ids = []
        for _ in range(iterations):
            id = get_id(self._create_default_idp())
            ids.append(id)
        ids = set(ids)

        keys_to_check = self.idp_keys
        url = self.base_url()
        resp = self.get(url)
        self.assertValidListResponse(resp, 'identity_providers',
                                     dummy_validator,
                                     keys_to_check=keys_to_check)
        entities = self._fetch_attribute_from_response(resp,
                                                       'identity_providers')
        entities_ids = set([e['id'] for e in entities])
        ids_intersection = entities_ids.intersection(ids)
        self.assertEqual(ids_intersection, ids)

    def test_check_idp_uniqueness(self):
        """Add same IdP twice.

        Expect HTTP 409 code for the latter call.

        """
        url = self.base_url(suffix=uuid.uuid4().hex)
        body = self._http_idp_input()
        self.put(url, body={'identity_provider': body},
                 expected_status=201)
        self.put(url, body={'identity_provider': body},
                 expected_status=409)

    def test_get_idp(self):
        """Create and later fetch IdP."""
        body = self._http_idp_input()
        default_resp = self._create_default_idp(body=body)
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        url = self.base_url(suffix=idp_id)
        resp = self.get(url)
        self.assertValidResponse(resp, 'identity_provider',
                                 dummy_validator, keys_to_check=body.keys(),
                                 ref=body)

    def test_get_nonexisting_idp(self):
        """Fetch nonexisting IdP entity.

        Expected HTTP 404 status code.

        """
        idp_id = uuid.uuid4().hex
        self.assertIsNotNone(idp_id)

        url = self.base_url(suffix=idp_id)
        self.get(url, expected_status=404)

    def test_delete_existing_idp(self):
        """Create and later delete IdP.

        Expect HTTP 404 for the GET IdP call.
        """
        default_resp = self._create_default_idp()
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        self.assertIsNotNone(idp_id)
        url = self.base_url(suffix=idp_id)
        self.delete(url)
        self.get(url, expected_status=404)

    def test_delete_nonexisting_idp(self):
        """Delete nonexisting IdP.

        Expect HTTP 404 for the GET IdP call.
        """
        idp_id = uuid.uuid4().hex
        url = self.base_url(suffix=idp_id)
        self.delete(url, expected_status=404)

    def test_update_idp_mutable_attributes(self):
        """Update IdP's mutable parameters."""
        default_resp = self._create_default_idp()
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        url = self.base_url(suffix=idp_id)
        self.assertIsNotNone(idp_id)

        _enabled = not default_idp.get('enabled')
        body = {'description': uuid.uuid4().hex, 'enabled': _enabled}

        body = {'identity_provider': body}
        resp = self.patch(url, body=body)
        updated_idp = self._fetch_attribute_from_response(resp,
                                                          'identity_provider')
        body = body['identity_provider']
        for key in body.keys():
            self.assertEqual(body[key], updated_idp.get(key))

        resp = self.get(url)
        updated_idp = self._fetch_attribute_from_response(resp,
                                                          'identity_provider')
        for key in body.keys():
            self.assertEqual(body[key], updated_idp.get(key))

    def test_update_idp_immutable_attributes(self):
        """Update IdP's immutable parameters.

        Expect HTTP 403 code.

        """
        default_resp = self._create_default_idp()
        default_idp = self._fetch_attribute_from_response(default_resp,
                                                          'identity_provider')
        idp_id = default_idp.get('id')
        self.assertIsNotNone(idp_id)

        body = self._http_idp_input()
        body['id'] = uuid.uuid4().hex
        body['protocols'] = [uuid.uuid4().hex, uuid.uuid4().hex]

        url = self.base_url(suffix=idp_id)
        self.patch(url, body={'identity_provider': body}, expected_status=403)

    def test_update_nonexistent_idp(self):
        """Update nonexistent IdP

        Expect HTTP 404 code.

        """
        idp_id = uuid.uuid4().hex
        url = self.base_url(suffix=idp_id)
        body = self._http_idp_input()
        body['enabled'] = False
        body = {'identity_provider': body}

        self.patch(url, body=body, expected_status=404)

    def test_assign_protocol_to_idp(self):
        """Assign a protocol to existing IdP."""

        self._assign_protocol_to_idp(expected_status=201)

    def test_protocol_composite_pk(self):
        """Test whether Keystone let's add two entities with identical
        names, however attached to different IdPs.

        1. Add IdP and assign it protocol with predefined name
        2. Add another IdP and assign it a protocol with same name.

        Expect HTTP 201 code

        """
        url = self.base_url(suffix='%(idp_id)s/protocols/%(protocol_id)s')

        kwargs = {'expected_status': 201}
        self._assign_protocol_to_idp(proto='saml2',
                                     url=url, **kwargs)

        self._assign_protocol_to_idp(proto='saml2',
                                     url=url, **kwargs)

    def test_protocol_idp_pk_uniqueness(self):
        """Test whether Keystone checks for unique idp/protocol values.

        Add same protocol twice, expect Keystone to reject a latter call and
        return HTTP 409 code.

        """
        url = self.base_url(suffix='%(idp_id)s/protocols/%(protocol_id)s')

        kwargs = {'expected_status': 201}
        resp, idp_id, proto = self._assign_protocol_to_idp(proto='saml2',
                                                           url=url, **kwargs)
        kwargs = {'expected_status': 409}
        resp, idp_id, proto = self._assign_protocol_to_idp(idp_id=idp_id,
                                                           proto='saml2',
                                                           validate=False,
                                                           url=url, **kwargs)

    def test_assign_protocol_to_nonexistent_idp(self):
        """Assign protocol to IdP that doesn't exist.

        Expect HTTP 404 code.

        """

        idp_id = uuid.uuid4().hex
        kwargs = {'expected_status': 404}
        self._assign_protocol_to_idp(proto='saml2',
                                     idp_id=idp_id,
                                     validate=False,
                                     **kwargs)

    def test_get_protocol(self):
        """Create and later fetch protocol tied to IdP."""

        resp, idp_id, proto = self._assign_protocol_to_idp(expected_status=201)
        proto_id = self._fetch_attribute_from_response(resp, 'protocol')['id']
        url = "%s/protocols/%s" % (idp_id, proto_id)
        url = self.base_url(suffix=url)

        resp = self.get(url)

        reference = {'id': proto_id}
        self.assertValidResponse(resp, 'protocol',
                                 dummy_validator,
                                 keys_to_check=reference.keys(),
                                 ref=reference)

    def test_list_protocols(self):
        """Create set of protocols and later list them.

        Compare input and output id sets.

        """
        resp, idp_id, proto = self._assign_protocol_to_idp(expected_status=201)
        iterations = random.randint(0, 16)
        protocol_ids = []
        for _ in range(iterations):
            resp, _, proto = self._assign_protocol_to_idp(idp_id=idp_id,
                                                          expected_status=201)
            proto_id = self._fetch_attribute_from_response(resp, 'protocol')
            proto_id = proto_id['id']
            protocol_ids.append(proto_id)

        url = "%s/protocols" % idp_id
        url = self.base_url(suffix=url)
        resp = self.get(url)
        self.assertValidListResponse(resp, 'protocols',
                                     dummy_validator,
                                     keys_to_check=['id'])
        entities = self._fetch_attribute_from_response(resp, 'protocols')
        entities = set([entity['id'] for entity in entities])
        protocols_intersection = entities.intersection(protocol_ids)
        self.assertEqual(protocols_intersection, set(protocol_ids))

    def test_update_protocols_attribute(self):
        """Update protocol's attribute."""

        resp, idp_id, proto = self._assign_protocol_to_idp(expected_status=201)
        new_mapping_id = uuid.uuid4().hex

        url = "%s/protocols/%s" % (idp_id, proto)
        url = self.base_url(suffix=url)
        body = {'mapping_id': new_mapping_id}
        resp = self.patch(url, body={'protocol': body})
        self.assertValidResponse(resp, 'protocol', dummy_validator,
                                 keys_to_check=['id', 'mapping_id'],
                                 ref={'id': proto,
                                      'mapping_id': new_mapping_id}
                                 )

    def test_delete_protocol(self):
        """Delete protocol.

        Expect HTTP 404 code for the GET call after the protocol is deleted.

        """
        url = self.base_url(suffix='/%(idp_id)s/'
                                   'protocols/%(protocol_id)s')
        resp, idp_id, proto = self._assign_protocol_to_idp(expected_status=201)
        url = url % {'idp_id': idp_id,
                     'protocol_id': proto}
        self.delete(url)
        self.get(url, expected_status=404)


class MappingCRUDTests(FederationTests):
    """A class for testing CRUD operations for Mappings."""

    MAPPING_URL = '/OS-FEDERATION/mappings/'

    def assertValidMappingListResponse(self, resp, *args, **kwargs):
        return self.assertValidListResponse(
            resp,
            'mappings',
            self.assertValidMapping,
            keys_to_check=[],
            *args,
            **kwargs)

    def assertValidMappingResponse(self, resp, *args, **kwargs):
        return self.assertValidResponse(
            resp,
            'mapping',
            self.assertValidMapping,
            keys_to_check=[],
            *args,
            **kwargs)

    def assertValidMapping(self, entity, ref=None):
        self.assertIsNotNone(entity.get('id'))
        self.assertIsNotNone(entity.get('rules'))
        if ref:
            self.assertEqual(jsonutils.loads(entity['rules']), ref['rules'])
        return entity

    def _create_default_mapping_entry(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        resp = self.put(url,
                        body={'mapping': mapping_fixtures.MAPPING_LARGE},
                        expected_status=201)
        return resp

    def _get_id_from_response(self, resp):
        r = resp.result.get('mapping')
        return r.get('id')

    def test_mapping_create(self):
        resp = self._create_default_mapping_entry()
        self.assertValidMappingResponse(resp, mapping_fixtures.MAPPING_LARGE)

    def test_mapping_list(self):
        url = self.MAPPING_URL
        self._create_default_mapping_entry()
        resp = self.get(url)
        entities = resp.result.get('mappings')
        self.assertIsNotNone(entities)
        self.assertResponseStatus(resp, 200)
        self.assertValidListLinks(resp.result.get('links'))
        self.assertEqual(len(entities), 1)

    def test_mapping_delete(self):
        url = self.MAPPING_URL + '%(mapping_id)s'
        resp = self._create_default_mapping_entry()
        mapping_id = self._get_id_from_response(resp)
        url = url % {'mapping_id': str(mapping_id)}
        resp = self.delete(url)
        self.assertResponseStatus(resp, 204)
        self.get(url, expected_status=404)

    def test_mapping_get(self):
        url = self.MAPPING_URL + '%(mapping_id)s'
        resp = self._create_default_mapping_entry()
        mapping_id = self._get_id_from_response(resp)
        url = url % {'mapping_id': mapping_id}
        resp = self.get(url)
        self.assertValidMappingResponse(resp, mapping_fixtures.MAPPING_LARGE)

    def test_mapping_update(self):
        url = self.MAPPING_URL + '%(mapping_id)s'
        resp = self._create_default_mapping_entry()
        mapping_id = self._get_id_from_response(resp)
        url = url % {'mapping_id': mapping_id}
        resp = self.patch(url,
                          body={'mapping': mapping_fixtures.MAPPING_SMALL})
        self.assertValidMappingResponse(resp, mapping_fixtures.MAPPING_SMALL)
        resp = self.get(url)
        self.assertValidMappingResponse(resp, mapping_fixtures.MAPPING_SMALL)

    def test_delete_mapping_dne(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.delete(url, expected_status=404)

    def test_get_mapping_dne(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.get(url, expected_status=404)

    def test_create_mapping_bad_requirements(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=400,
                 body={'mapping': mapping_fixtures.MAPPING_BAD_REQ})

    def test_create_mapping_no_rules(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=400,
                 body={'mapping': mapping_fixtures.MAPPING_NO_RULES})

    def test_create_mapping_no_remote_objects(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=400,
                 body={'mapping': mapping_fixtures.MAPPING_NO_REMOTE})

    def test_create_mapping_bad_value(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=400,
                 body={'mapping': mapping_fixtures.MAPPING_BAD_VALUE})

    def test_create_mapping_missing_local(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=400,
                 body={'mapping': mapping_fixtures.MAPPING_MISSING_LOCAL})

    def test_create_mapping_missing_type(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=400,
                 body={'mapping': mapping_fixtures.MAPPING_MISSING_TYPE})

    def test_create_mapping_wrong_type(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=400,
                 body={'mapping': mapping_fixtures.MAPPING_WRONG_TYPE})

    def test_create_mapping_extra_remote_properties_not_any_of(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        mapping = mapping_fixtures.MAPPING_EXTRA_REMOTE_PROPS_NOT_ANY_OF
        self.put(url, expected_status=400, body={'mapping': mapping})

    def test_create_mapping_extra_remote_properties_any_one_of(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        mapping = mapping_fixtures.MAPPING_EXTRA_REMOTE_PROPS_ANY_ONE_OF
        self.put(url, expected_status=400, body={'mapping': mapping})

    def test_create_mapping_extra_remote_properties_just_type(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        mapping = mapping_fixtures.MAPPING_EXTRA_REMOTE_PROPS_JUST_TYPE
        self.put(url, expected_status=400, body={'mapping': mapping})

    def test_create_mapping_empty_map(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=400,
                 body={'mapping': {}})

    def test_create_mapping_extra_rules_properties(self):
        url = self.MAPPING_URL + uuid.uuid4().hex
        self.put(url, expected_status=400,
                 body={'mapping': mapping_fixtures.MAPPING_EXTRA_RULES_PROPS})


class MappingRuleEngineTests(FederationTests):
    """A class for testing the mapping rule engine."""

    def test_rule_engine_any_one_of_and_direct_mapping(self):
        """Should return user's name and group id EMPLOYEE_GROUP_ID.

        The ADMIN_ASSERTION should successfully have a match in MAPPING_LARGE.
        The will test the case where `any_one_of` is valid, and there is
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
        name = values.get('name')

        self.assertIn(mapping_fixtures.EMPLOYEE_GROUP_ID, group_ids)
        self.assertEqual(name, full_name)

    def test_rule_engine_no_regex_match(self):
        """Should deny authorization, the email of the tester won't match.

        This will not match since the email in the assertion will fail
        the regex test. It is set to match any @example.com address.
        But the incoming value is set to eviltester@example.org.
        RuleProcessor should raise exception.Unauthorized exception.

        """

        mapping = mapping_fixtures.MAPPING_LARGE
        assertion = mapping_fixtures.BAD_TESTER_ASSERTION
        rp = mapping_utils.RuleProcessor(mapping['rules'])

        self.assertRaises(exception.Unauthorized,
                          rp.process, assertion)

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

        user_name = assertion.get('UserName')
        group_ids = values.get('group_ids')
        name = values.get('name')

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

        user_name = assertion.get('UserName')
        group_ids = values.get('group_ids')
        name = values.get('name')

        self.assertEqual(name, user_name)
        self.assertEqual(group_ids, [])

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
        user_name = assertion.get('UserName')
        group_ids = values.get('group_ids')
        name = values.get('name')

        self.assertEqual(name, user_name)
        self.assertIn(mapping_fixtures.EMPLOYEE_GROUP_ID, group_ids)

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
        name = values.get('name')

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
        is required for a correct rule match. Since no rules are
        matched expect RuleProcessor to raise exception.Unauthorized
        exception.

        """
        mapping = mapping_fixtures.MAPPING_SMALL
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        assertion = mapping_fixtures.CONTRACTOR_MALFORMED_ASSERTION
        self.assertRaises(exception.Unauthorized,
                          rp.process, assertion)


class FederatedTokenTests(FederationTests):

    IDP = 'ORG_IDP'
    PROTOCOL = 'saml2'
    AUTH_METHOD = 'saml2'
    USER = 'user@ORGANIZATION'
    ASSERTION_PREFIX = 'PREFIX_'

    UNSCOPED_V3_SAML2_REQ = {
        "identity": {
            "methods": [AUTH_METHOD],
            AUTH_METHOD: {
                "identity_provider": IDP,
                "protocol": PROTOCOL
            }
        }
    }

    AUTH_URL = '/auth/tokens'

    def setUp(self):
        super(FederationTests, self).setUp()
        self.load_sample_data()
        self.load_federation_sample_data()

    def idp_ref(self, id=None):
        idp = {
            'id': id or uuid.uuid4().hex,
            'enabled': True,
            'description': uuid.uuid4().hex
        }
        return idp

    def proto_ref(self, mapping_id=None):
        proto = {
            'id': uuid.uuid4().hex,
            'mapping_id': mapping_id or uuid.uuid4().hex
        }
        return proto

    def mapping_ref(self, rules=None):
        return {
            'id': uuid.uuid4().hex,
            'rules': rules or self.rules['rules']
        }

    def _assertSerializeToXML(self, json_body):
        """Serialize JSON body to XML.

        Serialize JSON body to XML, then deserialize to JSON
        again. Expect both JSON dictionaries to be equal.

        """
        xml_body = serializer.to_xml(json_body)
        json_deserialized = serializer.from_xml(xml_body)
        self.assertDictEqual(json_deserialized, json_body)

    def _scope_request(self, unscoped_token_id, scope, scope_id):
        return {
            'auth': {
                'identity': {
                    'methods': [
                        self.AUTH_METHOD
                    ],
                    self.AUTH_METHOD: {
                        'id': unscoped_token_id
                    }
                },
                'scope': {
                    scope: {
                        'id': scope_id
                    }
                }
            }
        }

    def _project(self, project):
        return (project['id'], project['name'])

    def _roles(self, roles):
        return set([(r['id'], r['name']) for r in roles])

    def _check_projects_and_roles(self, token, roles, projects):
        """Check whether the projects and the roles match."""
        token_roles = token.get('roles')
        if token_roles is None:
            raise AssertionError('Roles not found in the token')
        token_roles = self._roles(token_roles)
        roles_ref = self._roles(roles)
        self.assertEqual(token_roles, roles_ref)

        token_projects = token.get('project')
        if token_projects is None:
            raise AssertionError('Projects not found in the token')
        token_projects = self._project(token_projects)
        projects_ref = self._project(projects)
        self.assertEqual(token_projects, projects_ref)

    def _check_scoped_token_attributes(self, token):
        def xor_project_domain(iterable):
            return sum(('project' in iterable, 'domain' in iterable)) % 2

        for obj in ('user', 'catalog', 'expires_at', 'issued_at',
                    'methods', 'roles'):
            self.assertIn(obj, token)
        # Check for either project or domain
        if not xor_project_domain(token.keys()):
            raise AssertionError("You must specify either"
                                 "project or domain.")

    def _issue_unscoped_token(self, assertion='EMPLOYEE_ASSERTION'):
        api = federation_controllers.Auth()
        context = {'environment': {}}
        self._inject_assertion(context, assertion)
        r = api.federated_authentication(context, self.IDP, self.PROTOCOL)
        return r

    def test_issue_unscoped_token(self):
        r = self._issue_unscoped_token()
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))

    def test_issue_unscoped_token_serialize_to_xml(self):
        """Issue unscoped token and serialize to XML.

        Make sure common.serializer doesn't complain about
        the response structure and tag names.

        """
        r = self._issue_unscoped_token()
        token_resp = r.json_body
        # Remove 'extras' if empty or None,
        # as JSON and XML (de)serializers treat
        # them differently, making dictionaries
        # comparisions fail.
        if not token_resp['token'].get('extras'):
            token_resp['token'].pop('extras')
        self._assertSerializeToXML(token_resp)

    def test_issue_unscoped_token_no_groups(self):
        self.assertRaises(exception.Unauthorized,
                          self._issue_unscoped_token,
                          assertion='BAD_TESTER_ASSERTION')

    def test_issue_unscoped_token_malformed_environment(self):
        """Test whether non string objects are filtered out.

        Put non string objects into the environment, inject
        correct assertion and try to get an unscoped token.
        Expect server not to fail on using split() method on
        non string objects and return token id in the HTTP header.

        """
        api = auth_controllers.Auth()
        context = {
            'environment': {
                'malformed_object': object(),
                'another_bad_idea': tuple(xrange(10)),
                'yet_another_bad_param': dict(zip(uuid.uuid4().hex,
                                                  range(32)))
            }
        }
        self._inject_assertion(context, 'EMPLOYEE_ASSERTION')
        r = api.authenticate_for_token(context, self.UNSCOPED_V3_SAML2_REQ)
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))

    def test_scope_to_project_once(self):
        r = self.post(self.AUTH_URL,
                      body=self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_EMPLOYEE)
        token_resp = r.result['token']
        project_id = token_resp['project']['id']
        self.assertEqual(project_id, self.proj_employees['id'])
        self._check_scoped_token_attributes(token_resp)
        roles_ref = [self.role_employee]
        projects_ref = self.proj_employees
        self._check_projects_and_roles(token_resp, roles_ref, projects_ref)

    def test_scope_to_bad_project(self):
        """Scope unscoped token with a project we don't have access to."""

        self.post(self.AUTH_URL,
                  body=self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_CUSTOMER,
                  expected_status=401)

    def test_scope_to_project_multiple_times(self):
        """Try to scope the unscoped token multiple times.

        The new tokens should be scoped to:

        * Customers' project
        * Employees' project

        """

        bodies = (self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_ADMIN,
                  self.TOKEN_SCOPE_PROJECT_CUSTOMER_FROM_ADMIN)
        project_ids = (self.proj_employees['id'],
                       self.proj_customers['id'])
        for body, project_id_ref in zip(bodies, project_ids):
            r = self.post(self.AUTH_URL, body=body)
            token_resp = r.result['token']
            project_id = token_resp['project']['id']
            self.assertEqual(project_id, project_id_ref)
            self._check_scoped_token_attributes(token_resp)

    def test_scope_token_from_nonexistent_unscoped_token(self):
        """Try to scope token from non-existent unscoped token."""
        self.post(self.AUTH_URL,
                  body=self.TOKEN_SCOPE_PROJECT_FROM_NONEXISTENT_TOKEN,
                  expected_status=404)

    def test_issue_token_from_rules_without_user(self):
        api = auth_controllers.Auth()
        context = {'environment': {}}
        self._inject_assertion(context, 'BAD_TESTER_ASSERTION')
        self.assertRaises(exception.Unauthorized,
                          api.authenticate_for_token,
                          context, self.UNSCOPED_V3_SAML2_REQ)

    def test_issue_token_with_nonexistent_group(self):
        """Inject assertion that matches rule issuing bad group id.

        Expect server to find out that some groups are missing in the
        backend and raise exception.MappedGroupNotFound exception.

        """
        self.assertRaises(exception.MappedGroupNotFound,
                          self._issue_unscoped_token,
                          assertion='CONTRACTOR_ASSERTION')

    def test_scope_to_domain_once(self):
        r = self.post(self.AUTH_URL,
                      body=self.TOKEN_SCOPE_DOMAIN_A_FROM_CUSTOMER)
        token_resp = r.result['token']
        domain_id = token_resp['domain']['id']
        self.assertEqual(domain_id, self.domainA['id'])
        self._check_scoped_token_attributes(token_resp)

    def test_scope_to_domain_multiple_tokens(self):
        """Issue multiple tokens scoping to different domains.

        The new tokens should be scoped to:

        * domainA
        * domainB
        * domainC

        """
        bodies = (self.TOKEN_SCOPE_DOMAIN_A_FROM_ADMIN,
                  self.TOKEN_SCOPE_DOMAIN_B_FROM_ADMIN,
                  self.TOKEN_SCOPE_DOMAIN_C_FROM_ADMIN)
        domain_ids = (self.domainA['id'],
                      self.domainB['id'],
                      self.domainC['id'])

        for body, domain_id_ref in zip(bodies, domain_ids):
            r = self.post(self.AUTH_URL, body=body)
            token_resp = r.result['token']
            domain_id = token_resp['domain']['id']
            self.assertEqual(domain_id, domain_id_ref)
            self._check_scoped_token_attributes(token_resp)

    def test_list_projects(self):
        url = '/OS-FEDERATION/projects'

        token = (self.tokens['CUSTOMER_ASSERTION'],
                 self.tokens['EMPLOYEE_ASSERTION'],
                 self.tokens['ADMIN_ASSERTION'])

        projects_refs = (set([self.proj_customers['id']]),
                         set([self.proj_employees['id'],
                              self.project_all['id']]),
                         set([self.proj_employees['id'],
                              self.project_all['id'],
                              self.proj_customers['id']]))

        for token, projects_ref in zip(token, projects_refs):
            r = self.get(url, token=token)
            projects_resp = r.result['projects']
            projects = set(p['id'] for p in projects_resp)
            self.assertEqual(projects, projects_ref)

    def test_list_domains(self):
        url = '/OS-FEDERATION/domains'

        tokens = (self.tokens['CUSTOMER_ASSERTION'],
                  self.tokens['EMPLOYEE_ASSERTION'],
                  self.tokens['ADMIN_ASSERTION'])

        domain_refs = (set([self.domainA['id']]),
                       set([self.domainA['id'],
                            self.domainB['id']]),
                       set([self.domainA['id'],
                            self.domainB['id'],
                            self.domainC['id']]))

        for token, domains_ref in zip(tokens, domain_refs):
            r = self.get(url, token=token)
            domains_resp = r.result['domains']
            domains = set(p['id'] for p in domains_resp)
            self.assertEqual(domains, domains_ref)

    def test_full_workflow(self):
        """Test 'standard' workflow for granting access tokens.

        * Issue unscoped token
        * List available projects based on groups
        * Scope token to a one of available projects

        """

        r = self._issue_unscoped_token()
        employee_unscoped_token_id = r.headers.get('X-Subject-Token')
        r = self.get('/OS-FEDERATION/projects',
                     token=employee_unscoped_token_id)
        projects = r.result['projects']
        random_project = random.randint(0, len(projects)) - 1
        project = projects[random_project]

        v3_scope_request = self._scope_request(employee_unscoped_token_id,
                                               'project', project['id'])

        r = self.post(self.AUTH_URL, body=v3_scope_request)
        token_resp = r.result['token']
        project_id = token_resp['project']['id']
        self.assertEqual(project_id, project['id'])
        self._check_scoped_token_attributes(token_resp)

    def test_workflow_with_groups_deletion(self):
        """Test full workflow with groups deletion before token scoping.

        The test scenario is as follows:
         - Create group ``group``
         - Create and assign roles to ``group`` and ``project_all``
         - Patch mapping rules for existing IdP so it issues group id
         - Issue unscoped token with ``group``'s id
         - Delete group ``group``
         - Scope token to ``project_all``
         - Expect HTTP 500 response

        """
        # create group and role
        group = self.new_group_ref(
            domain_id=self.domainA['id'])
        self.identity_api.create_group(group['id'],
                                       group)
        role = self.new_role_ref()
        self.assignment_api.create_role(role['id'],
                                        role)

        # assign role to group and project_admins
        self.assignment_api.create_grant(role['id'],
                                         group_id=group['id'],
                                         project_id=self.project_all['id'])

        rules = {
            'rules': [
                {
                    'local': [
                        {
                            'group': {
                                'id': group['id']
                            }
                        },
                        {
                            'user': {
                                'name': '{0}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': 'UserName'
                        },
                        {
                            'type': 'LastName',
                            'any_one_of': [
                                'Account'
                            ]
                        }
                    ]
                }
            ]
        }

        self.federation_api.update_mapping(self.mapping['id'], rules)

        r = self._issue_unscoped_token(assertion='TESTER_ASSERTION')
        token_id = r.headers.get('X-Subject-Token')

        # delete group
        self.identity_api.delete_group(group['id'])

        # scope token to project_all, expect HTTP 500
        scoped_token = self._scope_request(
            token_id, 'project',
            self.project_all['id'])

        self.post(self.AUTH_URL,
                  body=scoped_token,
                  expected_status=500)

    def test_assertion_prefix_parameter(self):
        """Test parameters filtering based on the prefix.

        With ``assertion_prefix`` set to fixed, non defailt value,
        issue an unscoped token from assertion EMPLOYEE_ASSERTION_PREFIXED.
        Expect server to return unscoped token.

        """
        self.config_fixture.config(group='federation',
                                   assertion_prefix=self.ASSERTION_PREFIX)
        r = self._issue_unscoped_token(assertion='EMPLOYEE_ASSERTION_PREFIXED')
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))

    def test_assertion_prefix_parameter_expect_fail(self):
        """Test parameters filtering based on the prefix.

        With ``assertion_prefix`` default value set to empty string
        issue an unscoped token from assertion EMPLOYEE_ASSERTION.
        Next, configure ``assertion_prefix`` to value ``UserName``.
        Try issuing unscoped token with EMPLOYEE_ASSERTION.
        Expect server to raise exception.Unathorized exception.

        """
        r = self._issue_unscoped_token()
        self.assertIsNotNone(r.headers.get('X-Subject-Token'))
        self.config_fixture.config(group='federation',
                                   assertion_prefix='UserName')

        self.assertRaises(exception.Unauthorized,
                          self._issue_unscoped_token)

    def load_federation_sample_data(self):
        """Inject additional data."""

        # Create and add domains
        self.domainA = self.new_domain_ref()
        self.assignment_api.create_domain(self.domainA['id'],
                                          self.domainA)

        self.domainB = self.new_domain_ref()
        self.assignment_api.create_domain(self.domainB['id'],
                                          self.domainB)

        self.domainC = self.new_domain_ref()
        self.assignment_api.create_domain(self.domainC['id'],
                                          self.domainC)

        # Create and add projects
        self.proj_employees = self.new_project_ref(
            domain_id=self.domainA['id'])
        self.assignment_api.create_project(self.proj_employees['id'],
                                           self.proj_employees)
        self.proj_customers = self.new_project_ref(
            domain_id=self.domainA['id'])
        self.assignment_api.create_project(self.proj_customers['id'],
                                           self.proj_customers)

        self.project_all = self.new_project_ref(
            domain_id=self.domainA['id'])
        self.assignment_api.create_project(self.project_all['id'],
                                           self.project_all)

        # Create and add groups
        self.group_employees = self.new_group_ref(
            domain_id=self.domainA['id'])
        self.identity_api.create_group(self.group_employees['id'],
                                       self.group_employees)

        self.group_customers = self.new_group_ref(
            domain_id=self.domainA['id'])
        self.identity_api.create_group(self.group_customers['id'],
                                       self.group_customers)

        self.group_admins = self.new_group_ref(
            domain_id=self.domainA['id'])
        self.identity_api.create_group(self.group_admins['id'],
                                       self.group_admins)

        # Create and add roles
        self.role_employee = self.new_role_ref()
        self.assignment_api.create_role(self.role_employee['id'],
                                        self.role_employee)
        self.role_customer = self.new_role_ref()
        self.assignment_api.create_role(self.role_customer['id'],
                                        self.role_customer)

        self.role_admin = self.new_role_ref()
        self.assignment_api.create_role(self.role_admin['id'],
                                        self.role_admin)

        # Employees can access
        # * proj_employees
        # * project_all
        self.assignment_api.create_grant(self.role_employee['id'],
                                         group_id=self.group_employees['id'],
                                         project_id=self.proj_employees['id'])
        self.assignment_api.create_grant(self.role_employee['id'],
                                         group_id=self.group_employees['id'],
                                         project_id=self.project_all['id'])
        # Customers can access
        # * proj_customers
        self.assignment_api.create_grant(self.role_customer['id'],
                                         group_id=self.group_customers['id'],
                                         project_id=self.proj_customers['id'])

        # Admins can access:
        # * proj_customers
        # * proj_employees
        # * project_all
        self.assignment_api.create_grant(self.role_admin['id'],
                                         group_id=self.group_admins['id'],
                                         project_id=self.proj_customers['id'])
        self.assignment_api.create_grant(self.role_admin['id'],
                                         group_id=self.group_admins['id'],
                                         project_id=self.proj_employees['id'])
        self.assignment_api.create_grant(self.role_admin['id'],
                                         group_id=self.group_admins['id'],
                                         project_id=self.project_all['id'])

        self.assignment_api.create_grant(self.role_customer['id'],
                                         group_id=self.group_customers['id'],
                                         domain_id=self.domainA['id'])

        # Customers can access:
        # * domain A
        self.assignment_api.create_grant(self.role_customer['id'],
                                         group_id=self.group_customers['id'],
                                         domain_id=self.domainA['id'])

        # Employees can access:
        # * domain A
        # * domain B

        self.assignment_api.create_grant(self.role_employee['id'],
                                         group_id=self.group_employees['id'],
                                         domain_id=self.domainA['id'])
        self.assignment_api.create_grant(self.role_employee['id'],
                                         group_id=self.group_employees['id'],
                                         domain_id=self.domainB['id'])

        # Admins can access:
        # * domain A
        # * domain B
        # * domain C
        self.assignment_api.create_grant(self.role_admin['id'],
                                         group_id=self.group_admins['id'],
                                         domain_id=self.domainA['id'])
        self.assignment_api.create_grant(self.role_admin['id'],
                                         group_id=self.group_admins['id'],
                                         domain_id=self.domainB['id'])

        self.assignment_api.create_grant(self.role_admin['id'],
                                         group_id=self.group_admins['id'],
                                         domain_id=self.domainC['id'])
        self.rules = {
            'rules': [
                {
                    'local': [
                        {
                            'group': {
                                'id': self.group_employees['id']
                            }
                        },
                        {
                            'user': {
                                'name': '{0}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': 'UserName'
                        },
                        {
                            'type': 'orgPersonType',
                            'any_one_of': [
                                'Employee'
                            ]
                        }
                    ]
                },
                {
                    'local': [
                        {
                            'group': {
                                'id': self.group_employees['id']
                            }
                        },
                        {
                            'user': {
                                'name': '{0}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': self.ASSERTION_PREFIX + 'UserName'
                        },
                        {
                            'type': self.ASSERTION_PREFIX + 'orgPersonType',
                            'any_one_of': [
                                'SuperEmployee'
                            ]
                        }
                    ]
                },
                {
                    'local': [
                        {
                            'group': {
                                'id': self.group_customers['id']
                            }
                        },
                        {
                            'user': {
                                'name': '{0}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': 'UserName'
                        },
                        {
                            'type': 'orgPersonType',
                            'any_one_of': [
                                'Customer'
                            ]
                        }
                    ]
                },
                {
                    'local': [
                        {
                            'group': {
                                'id': self.group_admins['id']
                            }
                        },
                        {
                            'group': {
                                'id': self.group_employees['id']
                            }
                        },
                        {
                            'group': {
                                'id': self.group_customers['id']
                            }
                        },

                        {
                            'user': {
                                'name': '{0}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': 'UserName'
                        },
                        {
                            'type': 'orgPersonType',
                            'any_one_of': [
                                'Admin',
                                'Chief'
                            ]
                        }
                    ]
                },
                {
                    'local': [
                        {
                            'group': {
                                'id': uuid.uuid4().hex
                            }
                        },
                        {
                            'group': {
                                'id': self.group_customers['id']
                            }
                        },
                        {
                            'user': {
                                'name': '{0}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': 'UserName',
                        },
                        {
                            'type': 'FirstName',
                            'any_one_of': [
                                'Jill'
                            ]
                        },
                        {
                            'type': 'LastName',
                            'any_one_of': [
                                'Smith'
                            ]
                        }
                    ]
                },
                {
                    'local': [
                        {
                            'group': {
                                'id': 'this_group_no_longer_exists'
                            }
                        },
                        {
                            'user': {
                                'name': '{0}'
                            }
                        }
                    ],
                    'remote': [
                        {
                            'type': 'UserName',
                        },
                        {
                            'type': 'Email',
                            'any_one_of': [
                                'testacct@example.com'
                            ]
                        },
                        {
                            'type': 'orgPersonType',
                            'any_one_of': [
                                'Tester'
                            ]
                        }
                    ]
                },


            ]
        }

        # Add IDP
        self.idp = self.idp_ref(id=self.IDP)
        self.federation_api.create_idp(self.idp['id'],
                                       self.idp)

        # Add a mapping
        self.mapping = self.mapping_ref()
        self.federation_api.create_mapping(self.mapping['id'],
                                           self.mapping)
        # Add protocols
        self.proto_saml = self.proto_ref(mapping_id=self.mapping['id'])
        self.proto_saml['id'] = self.PROTOCOL
        self.federation_api.create_protocol(self.idp['id'],
                                            self.proto_saml['id'],
                                            self.proto_saml)
        # Generate fake tokens
        context = {'environment': {}}

        self.tokens = {}
        VARIANTS = ('EMPLOYEE_ASSERTION', 'CUSTOMER_ASSERTION',
                    'ADMIN_ASSERTION')
        api = auth_controllers.Auth()
        for variant in VARIANTS:
            self._inject_assertion(context, variant)
            r = api.authenticate_for_token(context, self.UNSCOPED_V3_SAML2_REQ)
            self.tokens[variant] = r.headers.get('X-Subject-Token')

        self.TOKEN_SCOPE_PROJECT_FROM_NONEXISTENT_TOKEN = self._scope_request(
            uuid.uuid4().hex, 'project', self.proj_customers['id'])

        self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_EMPLOYEE = self._scope_request(
            self.tokens['EMPLOYEE_ASSERTION'], 'project',
            self.proj_employees['id'])

        self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_ADMIN = self._scope_request(
            self.tokens['ADMIN_ASSERTION'], 'project',
            self.proj_employees['id'])

        self.TOKEN_SCOPE_PROJECT_CUSTOMER_FROM_ADMIN = self._scope_request(
            self.tokens['ADMIN_ASSERTION'], 'project',
            self.proj_customers['id'])

        self.TOKEN_SCOPE_PROJECT_EMPLOYEE_FROM_CUSTOMER = self._scope_request(
            self.tokens['CUSTOMER_ASSERTION'], 'project',
            self.proj_employees['id'])

        self.TOKEN_SCOPE_DOMAIN_A_FROM_CUSTOMER = self._scope_request(
            self.tokens['CUSTOMER_ASSERTION'], 'domain', self.domainA['id'])

        self.TOKEN_SCOPE_DOMAIN_B_FROM_CUSTOMER = self._scope_request(
            self.tokens['CUSTOMER_ASSERTION'], 'domain', self.domainB['id'])

        self.TOKEN_SCOPE_DOMAIN_B_FROM_CUSTOMER = self._scope_request(
            self.tokens['CUSTOMER_ASSERTION'], 'domain',
            self.domainB['id'])

        self.TOKEN_SCOPE_DOMAIN_A_FROM_ADMIN = self._scope_request(
            self.tokens['ADMIN_ASSERTION'], 'domain', self.domainA['id'])

        self.TOKEN_SCOPE_DOMAIN_B_FROM_ADMIN = self._scope_request(
            self.tokens['ADMIN_ASSERTION'], 'domain', self.domainB['id'])

        self.TOKEN_SCOPE_DOMAIN_C_FROM_ADMIN = self._scope_request(
            self.tokens['ADMIN_ASSERTION'], 'domain',
            self.domainC['id'])

    def _inject_assertion(self, context, variant):
        assertion = getattr(mapping_fixtures, variant)
        context['environment'].update(assertion)
        context['query_string'] = []
