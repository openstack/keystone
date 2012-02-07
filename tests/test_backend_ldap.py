# vim: tabstop=4 shiftwidth=4 softtabstop=4

from keystone import config
from keystone import test
from keystone.common.ldap import fakeldap
from keystone.identity.backends import ldap as identity_ldap

import default_fixtures
import test_backend


CONF = config.CONF


def clear_database():
    db = fakeldap.FakeShelve().get_instance()
    db.clear()


class LDAPIdentity(test.TestCase, test_backend.IdentityTests):
    def setUp(self):
        super(LDAPIdentity, self).setUp()
        CONF(config_files=[test.etcdir('keystone.conf'),
                           test.testsdir('test_overrides.conf'),
                           test.testsdir('backend_ldap.conf')])
        clear_database()
        self.identity_api = identity_ldap.Identity()
        self.load_fixtures(default_fixtures)
        self.user_foo = {'id': 'foo',
                         'name': 'FOO',
                         'password': 'foo2',
                         'tenants': ['bar']}

    def tearDown(self):
        test.TestCase.tearDown(self)
