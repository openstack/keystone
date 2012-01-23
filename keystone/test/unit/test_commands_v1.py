import datetime
import unittest2 as unittest

from keystone import backends
import keystone.backends.sqlalchemy as db
import keystone.backends.api as db_api
import keystone.manage.api as manage_api
from keystone import utils


class TestCommandsV1(unittest.TestCase):
    """Tests for keystone-manage version 1 commands"""

    def __init__(self, *args, **kwargs):
        super(TestCommandsV1, self).__init__(*args, **kwargs)
        self.options = {
            'backends': 'keystone.backends.sqlalchemy',
            'keystone.backends.sqlalchemy': {
                # in-memory db
                'sql_connection': 'sqlite://',
                'backend_entities':
                    "['UserRoleAssociation', 'Endpoints', 'Role', 'Tenant', "
                    "'Tenant', 'User', 'Credentials', 'EndpointTemplates', "
                    "'Token', 'Service']",
            },
        }
        # Need to populate the CONF module with these options
        utils.set_configuration(self.options)

    def setUp(self):
        self.clear_all_data()
        manage_api.add_tenant('Test tenant')
        self.user = manage_api.add_user('Test user', 'Test password',
                                        'Test tenant')

    def tearDown(self):
        self.clear_all_data()

    @staticmethod
    def clear_all_data():
        """
        Purges the database of all data
        """
        db.unregister_models()
        reload(db)
        backends.configure_backends()

    def test_service_list(self):
        result = manage_api.list_services()
        self.assertEqual(result, [])

    def test_add_service(self):
        data = {
            'name': 'Test name',
            'type': 'Test type',
            'desc': 'Test description',
            'owner_id': self.user.id,
            }
        manage_api.add_service(**data)
        result = manage_api.list_services()
        self.assertEqual(result, [['1', data['name'], data['type'],
                                   data['owner_id'], data['desc']]])

    def test_add_token(self):
        data = {
            'token': 'Test token',
            'user': 'Test user',
            'tenant': 'Test tenant',
            'expires': '20120104T18:30',
            }
        manage_api.add_token(**data)
        result = manage_api.list_tokens()
        user = db_api.USER.get_by_name(data['user'])
        tenant = db_api.TENANT.get_by_name(data['tenant'])
        self.assertEqual(result, [[data['token'], user['id'],
                                   datetime.datetime(2012, 1, 4, 18, 30),
                                   tenant['id']]])
