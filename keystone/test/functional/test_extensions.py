import unittest2 as unittest
from keystone.test.functional import common


class TestHPIDMTokensExtension(common.FunctionalTestCase):
    """Test HP-IDM token validation extension"""

    def setUp(self):
        super(TestHPIDMTokensExtension, self).setUp()
        password = common.unique_str()
        self.user = self.create_user(user_password=password).json['user']
        self.user['password'] = password
        self.tenant = self.create_tenant().json['tenant']
        self.service = self.create_service().json['OS-KSADM:service']
        r = self.create_role(service_name=self.service['name'])
        self.role = r.json['role']
        self.another_service = self.create_service().json['OS-KSADM:service']
        self.service_with_no_users = self.create_service().\
                json['OS-KSADM:service']
        ar = self.create_role(service_name=self.another_service['name'])
        self.another_role = ar.json['role']
        rnu = self.create_role(service_name=self.service_with_no_users['name'])
        self.role_with_no_users = rnu.json['role']
        rns = self.create_role()
        self.role_with_no_service = rns.json['role']
        self.grant_role_to_user(self.user['id'],
                                self.role['id'], self.tenant['id'])
        self.grant_role_to_user(self.user['id'],
                                self.role_with_no_service['id'],
                                self.tenant['id'])
        self.grant_role_to_user(self.user['id'],
                                self.another_role['id'], self.tenant['id'])
        self.global_role = self.create_role().json['role']
        # crete a global role
        self.put_user_role(self.user['id'], self.global_role['id'], None)

    def get_token_belongsto(self, token_id, tenant_id, service_ids, **kwargs):
        """GET /tokens/{token_id}?belongsTo={tenant_id}
                                  [&HP-IDM-serviceId={service_ids}]"""
        serviceId_qs = ""
        if service_ids:
            serviceId_qs = "&HP-IDM-serviceId=%s" % (service_ids)
        return self.admin_request(method='GET',
            path='/tokens/%s?belongsTo=%s%s' % (token_id, tenant_id,
                serviceId_qs), **kwargs)

    def check_token_belongs_to(self, token_id, tenant_id, service_ids,
                               **kwargs):
        """HEAD /tokens/{token_id}?belongsTo={tenant_id}
                                   [&HP-IDM-serviceId={service_ids}]"""
        serviceId_qs = ""
        if service_ids:
            serviceId_qs = "&HP-IDM-serviceId=%s" % (service_ids)
        return self.admin_request(method='HEAD',
            path='/tokens/%s?belongsTo=%s%s' % (token_id, tenant_id,
                serviceId_qs), **kwargs)

    @unittest.skipIf(common.isSsl(),
                     "Skipping SSL tests")
    def test_token_validation_with_serviceId(self):
        scoped = self.post_token(as_json={
            'auth': {
                'passwordCredentials': {
                    'username': self.user['name'],
                    'password': self.user['password']},
                'tenantName': self.tenant['name']}}).json['access']

        self.assertEqual(scoped['token']['tenant']['id'], self.tenant['id'])
        self.assertEqual(scoped['token']['tenant']['name'],
                         self.tenant['name'])
        # And an admin should be able to validate that our new token is scoped
        r = self.get_token_belongsto(token_id=scoped['token']['id'],
                tenant_id=self.tenant['id'], service_ids=self.service['id'])
        access = r.json['access']

        self.assertEqual(access['user']['id'], self.user['id'])
        self.assertEqual(access['user']['name'], self.user['name'])
        self.assertEqual(access['token']['tenant']['id'], self.tenant['id'])
        self.assertEqual(access['token']['tenant']['name'],
                         self.tenant['name'])

        # make sure only the service roles are returned
        self.assertIsNotNone(access['user'].get('roles'))
        self.assertEqual(len(access['user']['roles']), 1)
        self.assertEqual(access['user']['roles'][0]['name'],
                         self.role['name'])

        # make sure check token also works
        self.check_token_belongs_to(token_id=scoped['token']['id'],
            tenant_id=self.tenant['id'], service_ids=self.service['id'],
            assert_status=200)

    @unittest.skipIf(common.isSsl(),
                     "Skipping SSL tests")
    def test_token_validation_with_all_serviceId(self):
        scoped = self.post_token(as_json={
            'auth': {
                'passwordCredentials': {
                    'username': self.user['name'],
                    'password': self.user['password']},
                'tenantName': self.tenant['name']}}).json['access']

        self.assertEqual(scoped['token']['tenant']['id'], self.tenant['id'])
        self.assertEqual(scoped['token']['tenant']['name'],
                         self.tenant['name'])
        # And an admin should be able to validate that our new token is scoped
        service_ids = "%s,%s" % \
                      (self.service['id'], self.another_service['id'])
        r = self.get_token_belongsto(token_id=scoped['token']['id'],
                tenant_id=self.tenant['id'], service_ids=service_ids)
        access = r.json['access']

        self.assertEqual(access['user']['id'], self.user['id'])
        self.assertEqual(access['user']['name'], self.user['name'])
        self.assertEqual(access['token']['tenant']['id'], self.tenant['id'])
        self.assertEqual(access['token']['tenant']['name'],
                         self.tenant['name'])

        # make sure only the service roles are returned
        self.assertIsNotNone(access['user'].get('roles'))
        self.assertEqual(len(access['user']['roles']), 2)
        role_names = map(lambda x: x['name'], access['user']['roles'])
        self.assertTrue(self.role['name'] in role_names)
        self.assertTrue(self.another_role['name'] in role_names)

    @unittest.skipIf(common.isSsl(),
                     "Skipping SSL tests")
    def test_token_validation_with_no_user_service(self):
        scoped = self.post_token(as_json={
            'auth': {
                'passwordCredentials': {
                    'username': self.user['name'],
                    'password': self.user['password']},
                'tenantName': self.tenant['name']}}).json['access']

        self.assertEqual(scoped['token']['tenant']['id'], self.tenant['id'])
        self.assertEqual(scoped['token']['tenant']['name'],
                         self.tenant['name'])
        # And an admin should be able to validate that our new token is scoped
        service_ids = "%s,%s,%s" % (self.service['id'],
                                  self.another_service['id'],
                                  self.service_with_no_users['id'])
        r = self.get_token_belongsto(token_id=scoped['token']['id'],
                tenant_id=self.tenant['id'], service_ids=service_ids)
        access = r.json['access']

        self.assertEqual(access['user']['id'], self.user['id'])
        self.assertEqual(access['user']['name'], self.user['name'])
        self.assertEqual(access['token']['tenant']['id'], self.tenant['id'])
        self.assertEqual(access['token']['tenant']['name'],
                         self.tenant['name'])

        # make sure only the service roles are returned, excluding the one
        # with no users
        self.assertIsNotNone(access['user'].get('roles'))
        self.assertEqual(len(access['user']['roles']), 2)
        role_names = map(lambda x: x['name'], access['user']['roles'])
        self.assertTrue(self.role['name'] in role_names)
        self.assertTrue(self.another_role['name'] in role_names)

        # make sure check token also works
        self.check_token_belongs_to(token_id=scoped['token']['id'],
            tenant_id=self.tenant['id'], service_ids=service_ids,
            assert_status=200)

    @unittest.skipIf(common.isSsl(),
                     "Skipping SSL tests")
    def test_token_validation_without_serviceId(self):
        scoped = self.post_token(as_json={
            'auth': {
                'passwordCredentials': {
                    'username': self.user['name'],
                    'password': self.user['password']},
                'tenantName': self.tenant['name']}}).json['access']

        self.assertEqual(scoped['token']['tenant']['id'], self.tenant['id'])
        self.assertEqual(scoped['token']['tenant']['name'],
                         self.tenant['name'])
         # And an admin should be able to validate that our new token is scoped
        r = self.get_token_belongsto(token_id=scoped['token']['id'],
                tenant_id=self.tenant['id'], service_ids=None)
        access = r.json['access']

        self.assertEqual(access['user']['id'], self.user['id'])
        self.assertEqual(access['user']['name'], self.user['name'])
        self.assertEqual(access['token']['tenant']['id'], self.tenant['id'])
        self.assertEqual(access['token']['tenant']['name'],
                         self.tenant['name'])

        # make sure all the roles are returned
        self.assertIsNotNone(access['user'].get('roles'))
        self.assertEqual(len(access['user']['roles']), 4)
        role_names = map(lambda x: x['name'], access['user']['roles'])
        self.assertTrue(self.role['name'] in role_names)
        self.assertTrue(self.another_role['name'] in role_names)
        self.assertTrue(self.global_role['name'] in role_names)
        self.assertTrue(self.role_with_no_service['name'] in role_names)

    @unittest.skipIf(common.isSsl(),
                     "Skipping SSL tests")
    def test_token_validation_with_global_service_id(self):
        scoped = self.post_token(as_json={
            'auth': {
                'passwordCredentials': {
                    'username': self.user['name'],
                    'password': self.user['password']},
                'tenantName': self.tenant['name']}}).json['access']

        self.assertEqual(scoped['token']['tenant']['id'], self.tenant['id'])
        self.assertEqual(scoped['token']['tenant']['name'],
                         self.tenant['name'])
        service_ids = "%s,%s,global" % (self.service['id'],
                                      self.another_service['id'])
        r = self.get_token_belongsto(token_id=scoped['token']['id'],
                tenant_id=self.tenant['id'], service_ids=service_ids)
        access = r.json['access']

        self.assertEqual(access['user']['id'], self.user['id'])
        self.assertEqual(access['user']['name'], self.user['name'])
        self.assertEqual(access['token']['tenant']['id'], self.tenant['id'])
        self.assertEqual(access['token']['tenant']['name'],
                         self.tenant['name'])

        # make sure only the service roles are returned
        self.assertIsNotNone(access['user'].get('roles'))
        self.assertEqual(len(access['user']['roles']), 3)
        role_names = map(lambda x: x['name'], access['user']['roles'])
        self.assertTrue(self.role['name'] in role_names)
        self.assertTrue(self.another_role['name'] in role_names)
        self.assertTrue(self.global_role['name'] in role_names)

    @unittest.skipIf(common.isSsl(),
                     "Skipping SSL tests")
    def test_token_validation_with_bogus_service_id(self):
        scoped = self.post_token(as_json={
            'auth': {
                'passwordCredentials': {
                    'username': self.user['name'],
                    'password': self.user['password']},
                'tenantName': self.tenant['name']}}).json['access']

        self.assertEqual(scoped['token']['tenant']['id'], self.tenant['id'])
        self.assertEqual(scoped['token']['tenant']['name'],
                         self.tenant['name'])
        service_ids = "%s,%s,boguzzz" % (self.service['id'],
                                       self.another_service['id'])
        self.get_token_belongsto(token_id=scoped['token']['id'],
                tenant_id=self.tenant['id'], service_ids=service_ids,
                assert_status=401)

        # make sure check token also works
        self.check_token_belongs_to(token_id=scoped['token']['id'],
            tenant_id=self.tenant['id'], service_ids=service_ids,
            assert_status=401)


if __name__ == '__main__':
    unittest.main()
