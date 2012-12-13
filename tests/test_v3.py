import uuid

from keystone.common.sql import util as sql_util
from keystone import test

import test_content_types


BASE_URL = 'http://127.0.0.1:35357/v3'


class RestfulTestCase(test_content_types.RestfulTestCase):
    def setUp(self):
        self.config([
            test.etcdir('keystone.conf.sample'),
            test.testsdir('test_overrides.conf'),
            test.testsdir('backend_sql.conf'),
            test.testsdir('backend_sql_disk.conf')])
        sql_util.setup_test_database()
        self.load_backends()
        self.public_server = self.serveapp('keystone', name='main')
        self.admin_server = self.serveapp('keystone', name='admin')

    def tearDown(self):
        self.public_server.kill()
        self.admin_server.kill()
        self.public_server = None
        self.admin_server = None

    def new_ref(self):
        """Populates a ref with attributes common to all API entities."""
        return {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'enabled': True}

    def new_service_ref(self):
        ref = self.new_ref()
        ref['type'] = uuid.uuid4().hex
        return ref

    def new_endpoint_ref(self, service_id):
        ref = self.new_ref()
        ref['interface'] = uuid.uuid4().hex
        ref['service_id'] = service_id
        ref['url'] = uuid.uuid4().hex
        return ref

    def new_domain_ref(self):
        ref = self.new_ref()
        return ref

    def new_project_ref(self, domain_id):
        ref = self.new_ref()
        ref['domain_id'] = domain_id
        return ref

    def new_user_ref(self, domain_id, project_id=None):
        ref = self.new_ref()
        ref['domain_id'] = domain_id
        ref['email'] = uuid.uuid4().hex
        if project_id:
            ref['project_id'] = project_id
        return ref

    def new_group_ref(self, domain_id):
        ref = self.new_ref()
        ref['domain_id'] = domain_id
        return ref

    def new_credential_ref(self, user_id, project_id=None):
        ref = self.new_ref()
        ref['user_id'] = user_id
        ref['blob'] = uuid.uuid4().hex
        ref['type'] = uuid.uuid4().hex
        if project_id:
            ref['project_id'] = project_id
        return ref

    def new_role_ref(self):
        ref = self.new_ref()
        return ref

    def new_policy_ref(self):
        ref = self.new_ref()
        ref['blob'] = uuid.uuid4().hex
        ref['type'] = uuid.uuid4().hex
        return ref

    def get_scoped_token(self):
        """Convenience method so that we can test authenticated requests."""
        # FIXME(dolph): should use real auth
        return 'ADMIN'

        r = self.admin_request(
            method='POST',
            path='/v3/tokens',
            body={
                'auth': {
                    'passwordCredentials': {
                        'username': self.user_foo['name'],
                        'password': self.user_foo['password'],
                    },
                    'tenantId': self.tenant_bar['id'],
                },
            })
        return r.body['access']['token']['id']

    def v3_request(self, path, **kwargs):
        path = '/v3' + path
        return self.admin_request(
            path=path,
            token=self.get_scoped_token(),
            **kwargs)

    def get(self, path, **kwargs):
        return self.v3_request(method='GET', path=path, **kwargs)

    def head(self, path, **kwargs):
        return self.v3_request(method='HEAD', path=path, **kwargs)

    def post(self, path, **kwargs):
        return self.v3_request(method='POST', path=path, **kwargs)

    def put(self, path, **kwargs):
        return self.v3_request(method='PUT', path=path, **kwargs)

    def patch(self, path, **kwargs):
        return self.v3_request(method='PATCH', path=path, **kwargs)

    def delete(self, path, **kwargs):
        return self.v3_request(method='DELETE', path=path, **kwargs)

    def assertValidListResponse(self, resp, key, entity_validator, ref=None):
        """Make assertions common to all API list responses.

        If a reference is provided, it's ID will be searched for in the
        response, and asserted to be equal.

        """
        entities = resp.body.get(key)
        self.assertIsNotNone(entities)
        self.assertTrue(len(entities))
        for entity in entities:
            self.assertIsNotNone(entity)
            self.assertValidEntity(entity)
            entity_validator(entity)
        if ref:
            entity = [x for x in entities if x['id'] == ref['id']][0]
            self.assertValidEntity(entity, ref)
            entity_validator(entity, ref)
        return entities

    def assertValidResponse(self, resp, key, entity_validator, ref):
        """Make assertions common to all API responses."""
        entity = resp.body.get(key)
        self.assertIsNotNone(entity)
        self.assertValidEntity(entity, ref)
        entity_validator(entity, ref)
        return entity

    def assertValidEntity(self, entity, ref=None):
        """Make assertions common to all API entities.

        If a reference is provided, the entity will also be compared against
        the reference.
        """
        keys = ['name', 'description', 'enabled']

        for k in ['id'] + keys:
            msg = '%s unnexpectedly None in %s' % (k, entity)
            self.assertIsNotNone(entity.get(k), msg)

        # FIXME(dolph): need to test this in v3
        # self.assertIsNotNone(entity.get('link'))
        # self.assertIsNotNone(entity['link'].get('href'))
        # self.assertEquals(entity['link'].get('rel'), 'self')

        if ref:
            for k in keys:
                msg = '%s not equal: %s != %s' % (k, ref[k], entity[k])
                self.assertEquals(ref[k], entity[k])

        return entity


class VersionTestCase(RestfulTestCase):
    def test_get_version(self):
        pass
