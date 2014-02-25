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

from keystone.common.sql import migration_helpers
from keystone import config
from keystone import contrib
from keystone.contrib.federation import utils as mapping_utils
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


class FederationTests(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'federation'
    EXTENSION_TO_ADD = 'federation_extension'

    def setup_database(self):
        super(FederationTests, self).setup_database()
        package_name = '.'.join((contrib.__name__, self.EXTENSION_NAME))
        package = importutils.import_module(package_name)
        abs_path = migration_helpers.find_migrate_repo(package)
        migration.db_version_control(abs_path)
        migration.db_sync(abs_path)


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

    def _fetch_attributes_from_response(self, resp, parameters=[],
                                        assert_is_not_none=True):
        """Fetch parameters from the TestResponse object."""

        result = dict()
        kwargs = {'assert_is_not_none': assert_is_not_none}
        for parameter in parameters:
            value = self._fetch_attribute_from_response(resp, parameter,
                                                        **kwargs)
            result[parameter] = value
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

        fn = mapping_fixtures.ADMIN_ASSERTION.get('FirstName')
        ln = mapping_fixtures.ADMIN_ASSERTION.get('LastName')
        full_name = '%s %s' % (fn, ln)

        group_ids = values.get('group_ids')
        name = values.get('name')

        self.assertIn(mapping_fixtures.EMPLOYEE_GROUP_ID, group_ids)
        self.assertEqual(name, full_name)

    def test_rule_engine_no_regex_match(self):
        """Should return no values, the email of the tester won't match.

        This will not match since the email in the assertion will fail
        the regex test. It is set to match any @example.com address.
        But the incoming value is set to eviltester@example.org.

        """

        mapping = mapping_fixtures.MAPPING_LARGE
        assertion = mapping_fixtures.BAD_TESTER_ASSERTION
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        values = rp.process(assertion)

        group_ids = values.get('group_ids')
        name = values.get('name')

        self.assertIsNone(name)
        self.assertEqual(group_ids, [])

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

        group_ids = values.get('group_ids')
        name = values.get('name')

        self.assertIsNone(name)
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

        user_name = mapping_fixtures.CUSTOMER_ASSERTION.get('UserName')
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

        group_ids = values.get('group_ids')
        name = values.get('name')

        self.assertIsNone(name)
        self.assertIn(mapping_fixtures.EMPLOYEE_GROUP_ID, group_ids)

    def test_rule_engine_regex_match_and_many_groups(self):
        """Should return group DEVELOPER_GROUP_ID and TESTER_GROUP_ID.

        The TESTER_ASSERTION should successfully have a match in
        MAPPING_LARGE. This will test a successful regex match
        for an `any_one_of` evaluation type, and will have many
        groups returned.

        """

        mapping = mapping_fixtures.MAPPING_LARGE
        assertion = mapping_fixtures.TESTER_ASSERTION
        rp = mapping_utils.RuleProcessor(mapping['rules'])
        values = rp.process(assertion)

        group_ids = values.get('group_ids')
        name = values.get('name')

        self.assertIsNone(name)
        self.assertIn(mapping_fixtures.DEVELOPER_GROUP_ID, group_ids)
        self.assertIn(mapping_fixtures.TESTER_GROUP_ID, group_ids)
