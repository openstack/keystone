import unittest2 as unittest
from keystone.test.functional import common


class LegacyAuthenticationTest(common.FunctionalTestCase):
    use_server = True

    def setUp(self, *args, **kwargs):
        super(LegacyAuthenticationTest, self).setUp(*args, **kwargs)

        password = common.unique_str()
        self.tenant = self.create_tenant().json['tenant']
        self.user = self.create_user(user_password=password,
            tenant_id=self.tenant['id']).json['user']
        self.user['password'] = password

        self.services = {}
        self.endpoint_templates = {}
        for x in range(5):
            self.services[x] = self.create_service().json['OS-KSADM:service']
            self.endpoint_templates[x] = self.create_endpoint_template(
                name=self.services[x]['name'], \
                type=self.services[x]['type']).\
                json['OS-KSCATALOG:endpointTemplate']
            self.create_endpoint_for_tenant(self.tenant['id'],
                self.endpoint_templates[x]['id'])

    def test_authenticate_legacy(self):
        r = self.service_request(version='1.0', assert_status=204, headers={
            "X-Auth-User": self.user['name'],
            "X-Auth-Key": self.user['password']})

        self.assertIsNotNone(r.getheader('x-auth-token'))
        for service in self.services.values():
            self.assertIsNotNone(r.getheader('x-' + service['name']))

if __name__ == '__main__':
    unittest.main()
