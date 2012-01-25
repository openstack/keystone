import argparse
import datetime
import logging
import unittest2 as unittest
import uuid

from keystone import backends
import keystone.backends.sqlalchemy as db
from keystone.manage2 import base
from keystone.manage2 import common
from keystone.manage2.commands import create_credential
from keystone.manage2.commands import create_endpoint_template
from keystone.manage2.commands import create_role
from keystone.manage2.commands import create_service
from keystone.manage2.commands import create_tenant
from keystone.manage2.commands import create_token
from keystone.manage2.commands import create_user
from keystone.manage2.commands import delete_credential
from keystone.manage2.commands import delete_endpoint_template
from keystone.manage2.commands import delete_role
from keystone.manage2.commands import delete_service
from keystone.manage2.commands import delete_tenant
from keystone.manage2.commands import delete_token
from keystone.manage2.commands import delete_user
from keystone.manage2.commands import grant_role
from keystone.manage2.commands import list_credentials
from keystone.manage2.commands import list_endpoint_templates
from keystone.manage2.commands import list_endpoints
from keystone.manage2.commands import list_roles
from keystone.manage2.commands import list_services
from keystone.manage2.commands import list_tenants
from keystone.manage2.commands import list_tokens
from keystone.manage2.commands import list_users
from keystone.manage2.commands import map_endpoint
from keystone.manage2.commands import revoke_role
from keystone.manage2.commands import unmap_endpoint
from keystone.manage2.commands import update_credential
from keystone.manage2.commands import update_endpoint_template
from keystone.manage2.commands import update_role
from keystone.manage2.commands import update_service
from keystone.manage2.commands import update_tenant
from keystone.manage2.commands import update_token
from keystone.manage2.commands import update_user
from keystone.manage2.commands import version
from keystone.tools import buffout
from keystone import utils


LOGGER = logging.getLogger(__name__)

OPTIONS = {
    "keystone-service-admin-role": "KeystoneServiceAdmin",
    "keystone-admin-role": "KeystoneAdmin",
    "hash-password": "False",
    'backends': 'keystone.backends.sqlalchemy',
    'keystone.backends.sqlalchemy': {
        "sql_connection": "sqlite://",
        "backend_entities": "['UserRoleAssociation', "
            "'Endpoints', 'Role', 'Tenant', 'User', "
            "'Credentials', 'EndpointTemplates', 'Token', "
            "'Service']",
        "sql_idle_timeout": "30"}}
# Configure the CONF module to match
utils.set_configuration(OPTIONS)


class CommandTestCase(unittest.TestCase):
    """Buffers stdout to test keystone-manage commands"""

    def run_cmd(self, module, args=None, use_managers=True):
        """Runs the Command in the given module using the provided args"""
        args = args if args is not None else []

        managers = self.managers if use_managers else None

        cmd = module.Command(managers=managers)
        parsed_args = cmd.parser.parse_args(args)
        return cmd.run(parsed_args)

    def setUp(self):
        self.managers = common.init_managers()

        # buffer stdout so we can assert what's printed
        self.ob = buffout.OutputBuffer()
        self.ob.start()

    def tearDown(self):
        self.ob.stop()

        self.clear_all_data()

    def clear_all_data(self):
        """
        Purges the database of all data
        """
        db.unregister_models()
        reload(db)
        backends.configure_backends()

    def assertTableContainsRow(self, table, row):
        """Assumes that row[0] is a unique identifier for the row"""
        # ensure we're comparing str to str
        row = [str(col) for col in row]

        # ensure the data we're looking for is *somewhere* in the table
        self.assertIn(row[0], table)

        # find the matching row
        matching_row = [r for r in table.split("\n") if row[0] in r][0]
        matching_row = [c for c in matching_row.split() if c.strip() != '|']

        self.assertEquals(row, matching_row)

    def _create_user(self):
        # TODO(dolph): these ob.clear()'s need to be cleaned up
        self.ob.clear()
        self.run_cmd(create_user, [
            '--name', uuid.uuid4().hex,
            '--password', uuid.uuid4().hex])
        obj_id = self.ob.read_lines()[0]
        self.ob.clear()
        return obj_id

    def _create_tenant(self):
        self.ob.clear()
        self.run_cmd(create_tenant, [
            '--name', uuid.uuid4().hex])
        obj_id = self.ob.read_lines()[0]
        self.ob.clear()
        return obj_id

    def _create_token(self, user_id):
        self.ob.clear()
        self.run_cmd(create_token, [
            '--user-id', user_id])
        obj_id = self.ob.read_lines()[0]
        self.ob.clear()
        return obj_id

    def _create_credential(self, user_id):
        self.ob.clear()
        cred_type = uuid.uuid4().hex
        key = uuid.uuid4().hex
        secret = uuid.uuid4().hex
        self.run_cmd(create_credential, [
            '--user-id', user_id,
            '--type', cred_type,
            '--key', key,
            '--secret', secret])
        obj_id = self.ob.read_lines()[0]
        self.ob.clear()
        return obj_id

    def _create_service(self):
        self.ob.clear()
        self.run_cmd(create_service, [
            '--name', uuid.uuid4().hex,
            '--type', uuid.uuid4().hex])
        obj_id = self.ob.read_lines()[0]
        self.ob.clear()
        return obj_id

    def _create_role(self):
        self.ob.clear()
        self.run_cmd(create_role, [
            '--name', uuid.uuid4().hex])
        obj_id = self.ob.read_lines()[0]
        self.ob.clear()
        return obj_id

    def _create_endpoint_template(self, service_id):
        self.ob.clear()
        self.run_cmd(create_endpoint_template, [
            '--region', uuid.uuid4().hex,
            '--service-id', service_id,
            '--public-url', 'http://%s' % (uuid.uuid4().hex),
            '--admin-url', 'http://%s' % (uuid.uuid4().hex),
            '--internal-url', 'http://%s' % (uuid.uuid4().hex)])
        obj_id = self.ob.read_lines()[0]
        self.ob.clear()
        return obj_id

    def _map_endpoint(self, endpoint_template_id, tenant_id):
        self.ob.clear()
        self.run_cmd(map_endpoint, [
            '--endpoint-template-id', endpoint_template_id,
            '--tenant-id', tenant_id])
        self.ob.clear()


class TestCommon(unittest.TestCase):
    def test_enable_disable(self):
        """$ manage [command] --enable --disable"""
        args = argparse.Namespace(enable=True, disable=True)
        with self.assertRaises(SystemExit):
            cmd = base.BaseCommand()
            cmd.true_or_false(args, 'enable', 'disable')

        "Unable to apply both: --enable and --disable"

    def test_enable(self):
        """$ manage [command] --enable"""
        args = argparse.Namespace(enable=True, disable=False)
        cmd = base.BaseCommand()
        self.assertTrue(cmd.true_or_false(args, 'enable', 'disable'))

    def test_disable(self):
        """$ manage [command] --disable"""
        args = argparse.Namespace(enable=False, disable=True)
        cmd = base.BaseCommand()
        self.assertFalse(cmd.true_or_false(args, 'enable', 'disable'))

    def test_no_args(self):
        """$ manage [command]"""
        args = argparse.Namespace(enable=False, disable=False)
        cmd = base.BaseCommand()
        self.assertFalse(cmd.true_or_false(args, 'enable', 'disable'))


class TestVersionCommand(CommandTestCase):
    """Tests for ./bin/keystone-manage version"""
    API_VERSION = '2.0 beta'
    IMPLEMENTATION_VERSION = '2012.1-dev'
    DATABASE_VERSION = 'not under version control'

    def test_api_version(self):
        v = version.Command.get_api_version()
        self.assertEqual(v, self.API_VERSION)

    def test_implementation_version(self):
        v = version.Command.get_implementation_version()
        self.assertEqual(v, self.IMPLEMENTATION_VERSION)

    def test_all_version_responses(self):
        self.run_cmd(version, [], use_managers=False)
        lines = self.ob.read_lines()
        self.assertEqual(len(lines), 3, lines)
        self.assertIn(self.API_VERSION, lines[0])
        self.assertIn(self.IMPLEMENTATION_VERSION, lines[1])
        self.assertIn(self.DATABASE_VERSION, lines[2])

    def test_api_version_arg(self):
        self.run_cmd(version, ['--api'], use_managers=False)
        lines = self.ob.read_lines()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn(self.API_VERSION, lines[0])

    def test_implementation_version_arg(self):
        self.run_cmd(version, ['--implementation'], use_managers=False)
        lines = self.ob.read_lines()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn(self.IMPLEMENTATION_VERSION, lines[0])

    def test_database_version_arg(self):
        self.run_cmd(version, ['--database'], use_managers=False)
        lines = self.ob.read_lines()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn(self.DATABASE_VERSION, lines[0])


class TestCreateUserCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(create_user)

    def test_create_user_min_fields(self):
        name = uuid.uuid4().hex
        password = uuid.uuid4().hex
        self.run_cmd(create_user, [
            '--name', name,
            '--password', password])
        user_id = self.ob.read_lines()[0]
        self.assertEqual(len(user_id), 32)

        self.ob.clear()

        self.run_cmd(list_users)
        output = self.ob.read()
        self.assertIn(user_id, output)
        self.assertIn(name, output)
        self.assertNotIn(password, output)

    def test_create_user_all_fields(self):
        user_id = uuid.uuid4().hex
        name = uuid.uuid4().hex
        password = uuid.uuid4().hex
        email = uuid.uuid4().hex
        self.run_cmd(create_user, [
            '--id', user_id,
            '--name', name,
            '--password', password,
            '--email', email,
            '--disable'])
        output = self.ob.read_lines()
        self.assertEquals(user_id, output[0])

        self.ob.clear()

        self.run_cmd(list_users)
        self.assertTableContainsRow(self.ob.read(), [user_id, name, email,
            str(None), str(False)])


class TestListUsersCommand(CommandTestCase):
    def test_no_args(self):
        self.run_cmd(list_users)
        lines = self.ob.read_lines()
        row = [col.strip() for col in lines[1].split('|') if col.strip()]
        self.assertEquals('ID', row[0])
        self.assertEquals('Name', row[1])
        self.assertEquals('Email', row[2])
        self.assertEquals('Default Tenant ID', row[3])
        self.assertEquals('Enabled', row[4])


class TestUpdateUserCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(update_user)

    def test_invalid_id(self):
        with self.assertRaises(KeyError):
            self.run_cmd(update_user, [
                '--where-id', uuid.uuid4().hex])

    def test_create_update_list(self):
        user_id = uuid.uuid4().hex
        self.run_cmd(create_user, [
            '--id', user_id,
            '--name', uuid.uuid4().hex,
            '--password', uuid.uuid4().hex,
            '--email', uuid.uuid4().hex])

        name = uuid.uuid4().hex
        password = uuid.uuid4().hex
        email = uuid.uuid4().hex
        self.run_cmd(update_user, [
            '--where-id', user_id,
            '--name', name,
            '--password', password,
            '--email', email,
            '--disable'])

        self.ob.clear()

        self.run_cmd(list_users)
        output = self.ob.read()
        self.assertIn(user_id, output)

        lines = self.ob.read_lines()
        row = [row for row in lines if user_id in row][0]
        row = [col for col in row.split() if col.strip() != '|']
        self.assertEquals(user_id, row[0])
        self.assertEquals(name, row[1])
        self.assertEquals(email, row[2])
        self.assertEquals(str(None), row[3])
        self.assertEquals(str(False), row[4])


class TestDeleteUserCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(delete_user)

    def test_invalid_id(self):
        with self.assertRaises(KeyError):
            self.run_cmd(delete_user, [
                '--where-id', uuid.uuid4().hex])

    def test_create_delete_list(self):
        user_id = uuid.uuid4().hex
        self.run_cmd(create_user, [
            '--id', user_id,
            '--name', uuid.uuid4().hex,
            '--password', uuid.uuid4().hex,
            '--email', uuid.uuid4().hex])

        self.run_cmd(delete_user, [
            '--where-id', user_id])

        self.ob.clear()

        self.run_cmd(list_users)
        self.assertNotIn(user_id, self.ob.read())


class TestCreateTenantCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(create_tenant)

    def test_create_enabled_tenant(self):
        name = uuid.uuid4().hex
        self.run_cmd(create_tenant, [
            '--name', name])
        tenant_id = self.ob.read_lines()[0]
        self.assertEqual(len(tenant_id), 32)

        self.ob.clear()

        self.run_cmd(list_tenants)
        output = self.ob.read()
        self.assertIn(tenant_id, output)
        self.assertIn(name, output)

    def test_create_disabled_tenant(self):
        name = uuid.uuid4().hex
        self.run_cmd(create_tenant, [
            '--name', name,
            '--disabled'])
        tenant_id = self.ob.read_lines()[0]
        self.assertEqual(len(tenant_id), 32)

        self.ob.clear()

        self.run_cmd(list_tenants)
        output = self.ob.read()
        self.assertIn(tenant_id, output)

        lines = self.ob.read_lines()
        row = [row for row in lines if tenant_id in row][0]
        row = [col for col in row.split() if col.strip() != '|']
        self.assertEquals(tenant_id, row[0])
        self.assertEquals(name, row[1])
        self.assertEquals(str(False), row[2])


class TestListTenantsCommand(CommandTestCase):
    def test_no_args(self):
        self.run_cmd(list_tenants)
        lines = self.ob.read_lines()
        row = [col.strip() for col in lines[1].split('|') if col.strip()]
        self.assertEquals('ID', row[0])
        self.assertEquals('Name', row[1])
        self.assertEquals('Enabled', row[2])


class TestUpdateTenantCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(update_tenant)

    def test_invalid_id(self):
        with self.assertRaises(KeyError):
            self.run_cmd(update_tenant, [
                '--where-id', uuid.uuid4().hex])

    def test_create_update_list(self):
        tenant_id = uuid.uuid4().hex
        self.run_cmd(create_tenant, [
            '--id', tenant_id,
            '--name', uuid.uuid4().hex])

        name = uuid.uuid4().hex
        self.run_cmd(update_tenant, [
            '--where-id', tenant_id,
            '--name', name,
            '--disable'])

        self.ob.clear()

        self.run_cmd(list_tenants)
        output = self.ob.read()
        self.assertIn(tenant_id, output)

        lines = self.ob.read_lines()
        row = [row for row in lines if tenant_id in row][0]
        row = [col for col in row.split() if col.strip() != '|']
        self.assertEquals(tenant_id, row[0])
        self.assertEquals(name, row[1])
        self.assertEquals(str(False), row[2])


class TestDeleteTenantCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(delete_tenant)

    def test_invalid_id(self):
        with self.assertRaises(KeyError):
            self.run_cmd(delete_tenant, [
                '--where-id', uuid.uuid4().hex])

    def test_create_delete_list(self):
        tenant_id = uuid.uuid4().hex
        self.run_cmd(create_tenant, [
            '--id', tenant_id,
            '--name', uuid.uuid4().hex])

        self.run_cmd(delete_tenant, [
            '--where-id', tenant_id])

        self.ob.clear()

        self.run_cmd(list_tenants)
        self.assertNotIn(tenant_id, self.ob.read())


class TestCreateRoleCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(create_role)

    def test_create_role(self):
        name = uuid.uuid4().hex
        self.run_cmd(create_role, [
            '--name', name])
        role_id = self.ob.read_lines()[0]
        self.assertTrue(int(role_id))

        self.ob.clear()

        self.run_cmd(list_roles)
        output = self.ob.read()
        self.assertIn(role_id, output)
        self.assertIn(name, output)

    def test_create_role_with_description(self):
        name = uuid.uuid4().hex
        description = uuid.uuid4().hex
        self.run_cmd(create_role, [
            '--name', name,
            '--description', description])
        role_id = self.ob.read_lines()[0]
        self.assertTrue(int(role_id))

        self.ob.clear()

        self.run_cmd(list_roles)
        output = self.ob.read()
        self.assertIn(role_id, output)

        lines = self.ob.read_lines()
        row = [row for row in lines if role_id in row][0]
        row = [col for col in row.split() if col.strip() != '|']
        self.assertEquals(role_id, row[0])
        self.assertEquals(name, row[1])
        self.assertEquals(str(None), row[2])
        self.assertEquals(description, row[3])

    def test_create_role_owned_by_service(self):
        self.run_cmd(create_service, [
            '--name', uuid.uuid4().hex,
            '--type', uuid.uuid4().hex])
        service_id = self.ob.read_lines()[0]

        name = uuid.uuid4().hex
        self.run_cmd(create_role, [
            '--name', name,
            '--service-id', service_id])
        role_id = self.ob.read_lines()[0]

        self.ob.clear()

        self.run_cmd(list_roles)
        output = self.ob.read()
        self.assertIn(role_id, output)

        lines = self.ob.read_lines()
        row = [row for row in lines if role_id in row][0]
        row = [col for col in row.split() if col.strip() != '|']
        self.assertEquals(role_id, row[0])
        self.assertEquals(name, row[1])
        self.assertEquals(service_id, row[2])
        self.assertEquals(str(None), row[3])


class TestUpdateRoleCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(update_role)

    def test_update_role(self):
        old_name = uuid.uuid4().hex
        old_description = uuid.uuid4().hex
        old_service_id = self._create_service()
        self.run_cmd(create_role, [
            '--name', old_name,
            '--description', old_description,
            '--service-id', old_service_id])
        role_id = self.ob.read_lines()[0]

        # update the role
        name = uuid.uuid4().hex
        description = uuid.uuid4().hex
        service_id = self._create_service()
        self.run_cmd(update_role, [
            '--where-id', role_id,
            '--name', name,
            '--description', description,
            '--service-id', service_id])

        self.ob.clear()

        self.run_cmd(list_roles)
        self.assertTableContainsRow(self.ob.read(), [role_id, name,
            service_id, description])


class TestListRolesCommand(CommandTestCase):
    def test_no_args(self):
        self.run_cmd(list_roles)
        lines = self.ob.read_lines()
        row = [col.strip() for col in lines[1].split('|') if col.strip()]
        self.assertEquals('ID', row[0])
        self.assertEquals('Name', row[1])
        self.assertEquals('Service ID', row[2])
        self.assertEquals('Description', row[3])


class TestDeleteRoleCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(delete_role)

    def test_invalid_id(self):
        with self.assertRaises(KeyError):
            self.run_cmd(delete_role, [
                '--where-id', uuid.uuid4().hex])

    def test_delete_role(self):
        role_id = self._create_role()

        # delete it
        self.run_cmd(delete_role, [
            '--where-id', role_id])

        self.ob.clear()

        # ensure it's not returned
        self.run_cmd(list_roles)
        output = self.ob.read()
        self.assertNotIn(role_id, output)


class TestGrantRoleCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(grant_role)

    def test_invalid_ids(self):
        with self.assertRaises(KeyError):
            self.run_cmd(grant_role, [
                '--user-id', uuid.uuid4().hex,
                '--role-id', uuid.uuid4().hex])

    def test_grant_global_role(self):
        user_id = self._create_user()
        role_id = self._create_role()

        self.run_cmd(grant_role, [
            '--user-id', user_id,
            '--role-id', role_id])

        # granting again should fail
        # TODO(dolph): this should be an IntegrityError
        with self.assertRaises(KeyError):
            self.run_cmd(grant_role, [
                '--user-id', user_id,
                '--role-id', role_id])

    def test_grant_tenant_role(self):
        user_id = self._create_user()
        role_id = self._create_role()
        tenant_id = self._create_tenant()

        self.run_cmd(grant_role, [
            '--user-id', user_id,
            '--role-id', role_id,
            '--tenant-id', tenant_id])

        # granting again should fail
        # TODO(dolph): this should be an IntegrityError
        with self.assertRaises(KeyError):
            self.run_cmd(grant_role, [
                '--user-id', user_id,
                '--role-id', role_id,
                '--tenant-id', tenant_id])


class TestRevokeRoleCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(revoke_role)

    def test_revoke_global_role(self):
        user_id = self._create_user()
        role_id = self._create_role()

        self.run_cmd(grant_role, [
            '--user-id', user_id,
            '--role-id', role_id])

        self.run_cmd(revoke_role, [
            '--user-id', user_id,
            '--role-id', role_id])

    def test_revoke_tenant_role(self):
        user_id = self._create_user()
        role_id = self._create_role()
        tenant_id = self._create_tenant()

        self.run_cmd(grant_role, [
            '--user-id', user_id,
            '--role-id', role_id,
            '--tenant-id', tenant_id])

        self.run_cmd(revoke_role, [
            '--user-id', user_id,
            '--role-id', role_id,
            '--tenant-id', tenant_id])


class TestCreateServiceCommand(CommandTestCase):
    def test_create_service(self):
        name = uuid.uuid4().hex
        service_type = uuid.uuid4().hex
        description = uuid.uuid4().hex
        owner_id = self._create_user()
        self.run_cmd(create_service, [
            '--name', name,
            '--type', service_type,
            '--description', description,
            '--owner-id', owner_id])
        service_id = self.ob.read_lines()[0]
        self.assertTrue(int(service_id))

        self.ob.clear()

        self.run_cmd(list_services)
        output = self.ob.read()
        self.assertIn(service_id, output)

        lines = self.ob.read_lines()
        row = [row for row in lines if service_id in row][0]
        row = [col for col in row.split() if col.strip() != '|']
        self.assertEquals(service_id, row[0])
        self.assertEquals(name, row[1])
        self.assertEquals(service_type, row[2])
        self.assertEquals(owner_id, row[3])
        self.assertEquals(description, row[4])


class TestUpdateServiceCommand(CommandTestCase):
    def test_update_service(self):
        old_name = uuid.uuid4().hex
        old_type = uuid.uuid4().hex
        old_description = uuid.uuid4().hex
        old_owner_id = self._create_user()
        self.run_cmd(create_service, [
            '--name', old_name,
            '--type', old_type,
            '--description', old_description,
            '--owner-id', old_owner_id])
        service_id = self.ob.read_lines()[0]

        # update the service
        name = uuid.uuid4().hex
        service_type = uuid.uuid4().hex
        description = uuid.uuid4().hex
        owner_id = self._create_user()
        self.run_cmd(update_service, [
            '--where-id', service_id,
            '--name', name,
            '--type', service_type,
            '--description', description,
            '--owner-id', owner_id])

        self.ob.clear()

        self.run_cmd(list_services)
        output = self.ob.read()
        self.assertIn(service_id, output)

        lines = self.ob.read_lines()
        row = [row for row in lines if service_id in row][0]
        row = [col for col in row.split() if col.strip() != '|']
        self.assertEquals(service_id, row[0])
        self.assertEquals(name, row[1])
        self.assertEquals(service_type, row[2])
        self.assertEquals(owner_id, row[3])
        self.assertEquals(description, row[4])


class TestListServicesCommand(CommandTestCase):
    def test_no_args(self):
        self.run_cmd(list_services)
        lines = self.ob.read_lines()
        row = [col.strip() for col in lines[1].split('|') if col.strip()]
        self.assertEquals('ID', row[0])
        self.assertEquals('Name', row[1])
        self.assertEquals('Type', row[2])
        self.assertEquals('Owner ID', row[3])
        self.assertEquals('Description', row[4])


class TestDeleteServiceCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(delete_service)

    def test_invalid_id(self):
        with self.assertRaises(KeyError):
            self.run_cmd(delete_service, [
                '--where-id', uuid.uuid4().hex])

    def test_delete_service(self):
        service_id = self._create_service()

        self.run_cmd(delete_service, [
            '--where-id', service_id])

        self.ob.clear()

        self.run_cmd(list_services)
        output = self.ob.read()
        self.assertNotIn(service_id, output)


class TestCreateTokenCommand(CommandTestCase):
    """Creates tokens and validates their attributes.

    This class has a known potential race condition, due to the expected
    token expiration being 24 hours after token creation. If the
    'create_token' command runs immediately before the minute rolls over,
    and the test class produces a timestamp for the subsequent minute, the
    test will fail.

    """

    @staticmethod
    def _get_tomorrow_str():
        return (datetime.datetime.utcnow() +
                datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M')

    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(create_token)

    def test_create_unscoped_token(self):
        user_id = self._create_user()
        self.run_cmd(create_token, [
            '--user-id', user_id])
        tomorrow = TestCreateTokenCommand._get_tomorrow_str()
        token_id = self.ob.read_lines()[0]
        self.assertEqual(len(token_id), 32)

        self.ob.clear()

        self.run_cmd(list_tokens)
        self.assertTableContainsRow(self.ob.read(), [token_id, user_id,
            str(None), tomorrow])

    def test_create_scoped_token(self):
        user_id = self._create_user()
        tenant_id = self._create_tenant()
        self.run_cmd(create_token, [
            '--user-id', user_id,
            '--tenant-id', tenant_id])
        tomorrow = TestCreateTokenCommand._get_tomorrow_str()
        token_id = self.ob.read_lines()[0]
        self.assertEqual(len(token_id), 32)

        self.ob.clear()

        self.run_cmd(list_tokens)
        self.assertTableContainsRow(self.ob.read(), [token_id, user_id,
            tenant_id, tomorrow])

    def test_create_expired_token(self):
        user_id = self._create_user()
        expiration = '1999-12-31T23:59'
        self.run_cmd(create_token, [
            '--user-id', user_id,
            '--expires', expiration])
        token_id = self.ob.read_lines()[0]
        self.assertEqual(len(token_id), 32)

        self.ob.clear()

        self.run_cmd(list_tokens)
        self.assertTableContainsRow(self.ob.read(), [token_id, user_id,
            str(None), expiration])

    def test_create_specific_token_id(self):
        token_id = uuid.uuid4().hex
        user_id = self._create_user()
        self.run_cmd(create_token, [
            '--id', token_id,
            '--user-id', user_id])
        tomorrow = TestCreateTokenCommand._get_tomorrow_str()
        self.assertEqual(token_id, self.ob.read_lines()[0])

        self.ob.clear()

        self.run_cmd(list_tokens)
        self.assertTableContainsRow(self.ob.read(), [token_id, user_id,
            str(None), tomorrow])


class TestUpdateTokenCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(update_token)

    def test_update_token(self):
        token_id = self._create_token(self._create_user())

        user_id = self._create_user()
        tenant_id = self._create_tenant()
        expiration = '1999-12-31T23:59'
        self.run_cmd(update_token, [
            '--where-id', token_id,
            '--user-id', user_id,
            '--tenant-id', tenant_id,
            '--expires', expiration])

        self.ob.clear()

        self.run_cmd(list_tokens)
        self.assertTableContainsRow(self.ob.read(), [token_id, user_id,
            tenant_id, expiration])


class TestListTokensCommand(CommandTestCase):
    def test_no_args(self):
        self.run_cmd(list_tokens)
        lines = self.ob.read_lines()
        row = [col.strip() for col in lines[1].split('|') if col.strip()]
        self.assertEquals(['ID', 'User ID', 'Tenant ID', 'Expiration'],
                row)


class TestDeleteTokenCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(delete_token)

    def test_delete_token(self):
        token_id = self._create_token(self._create_user())

        self.run_cmd(delete_token, [
            '--where-id', token_id])

        self.ob.clear()

        # ensure it's not returned
        self.run_cmd(list_tokens)
        output = self.ob.read()
        self.assertNotIn(token_id, output)


class TestCreateCredentialCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(create_credential)

    def test_create_credential(self):
        user_id = self._create_user()
        cred_type = uuid.uuid4().hex
        key = uuid.uuid4().hex
        secret = uuid.uuid4().hex
        self.run_cmd(create_credential, [
            '--user-id', user_id,
            '--type', cred_type,
            '--key', key,
            '--secret', secret])
        credential_id = self.ob.read_lines()[0]
        self.assertTrue(int(credential_id))

        self.ob.clear()

        self.run_cmd(list_credentials)
        self.assertTableContainsRow(self.ob.read(), [credential_id,
            user_id, str(None), cred_type, key, secret])

    def test_create_credential_with_tenant(self):
        user_id = self._create_user()
        tenant_id = self._create_tenant()
        cred_type = uuid.uuid4().hex
        key = uuid.uuid4().hex
        secret = uuid.uuid4().hex
        self.run_cmd(create_credential, [
            '--user-id', user_id,
            '--tenant-id', tenant_id,
            '--type', cred_type,
            '--key', key,
            '--secret', secret])
        credential_id = self.ob.read_lines()[0]
        self.assertTrue(int(credential_id))

        self.ob.clear()

        self.run_cmd(list_credentials)
        self.assertTableContainsRow(self.ob.read(), [credential_id,
            user_id, tenant_id, cred_type, key, secret])


class TestUpdateCredentialCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(update_credential)

    def test_update_credential(self):
        credential_id = self._create_credential(self._create_user())

        user_id = self._create_user()
        tenant_id = self._create_tenant()
        cred_type = uuid.uuid4().hex
        key = uuid.uuid4().hex
        secret = uuid.uuid4().hex
        self.run_cmd(update_credential, [
            '--where-id', credential_id,
            '--user-id', user_id,
            '--tenant-id', tenant_id,
            '--type', cred_type,
            '--key', key,
            '--secret', secret])

        self.ob.clear()

        self.run_cmd(list_credentials)
        self.assertTableContainsRow(self.ob.read(), [credential_id,
            user_id, tenant_id, cred_type, key, secret])


class TestListCredentialsCommand(CommandTestCase):
    def test_no_args(self):
        self.run_cmd(list_credentials)
        lines = self.ob.read_lines()
        row = [col.strip() for col in lines[1].split('|') if col.strip()]
        self.assertEquals(['ID', 'User ID', 'Tenant ID', 'Type', 'Key',
            'Secret'], row)


class TestDeleteCredentialCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(delete_credential)

    def test_delete_credential(self):
        credential_id = self._create_credential(self._create_user())

        self.run_cmd(delete_credential, [
            '--where-id', credential_id])

        self.ob.clear()

        # ensure it's not returned
        self.run_cmd(list_credentials)
        output = self.ob.read()
        self.assertNotIn(credential_id, output)


class TestCreateEndpointTemplateCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(create_endpoint_template)

    def test_create_global_endpoint_template(self):
        region = uuid.uuid4().hex
        service_id = self._create_service()
        public_url = 'http://%s' % (uuid.uuid4().hex)
        admin_url = 'http://%s' % (uuid.uuid4().hex)
        internal_url = 'http://%s' % (uuid.uuid4().hex)
        self.run_cmd(create_endpoint_template, [
            '--region', region,
            '--service-id', service_id,
            '--public-url', public_url,
            '--admin-url', admin_url,
            '--internal-url', internal_url,
            '--global'])
        endpoint_template_id = self.ob.read_lines()[0]
        self.assertTrue(int(endpoint_template_id))

        self.ob.clear()

        self.run_cmd(list_endpoint_templates)
        self.assertTableContainsRow(self.ob.read(), [endpoint_template_id,
            service_id, region, str(True), str(True), public_url, admin_url,
            internal_url])


class TestUpdateEndpointTemplateCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(update_endpoint_template)

    def test_update_endpoint_template(self):
        endpoint_template_id = self._create_endpoint_template(
                self._create_service())

        region = uuid.uuid4().hex
        service_id = self._create_service()
        public_url = 'http://%s' % (uuid.uuid4().hex)
        admin_url = 'http://%s' % (uuid.uuid4().hex)
        internal_url = 'http://%s' % (uuid.uuid4().hex)

        self.run_cmd(update_endpoint_template, [
            '--where-id', endpoint_template_id,
            '--region', region,
            '--service-id', service_id,
            '--public-url', public_url,
            '--admin-url', admin_url,
            '--internal-url', internal_url,
            '--global',
            '--disable'])

        self.ob.clear()

        self.run_cmd(list_endpoint_templates)
        self.assertTableContainsRow(self.ob.read(), [endpoint_template_id,
            service_id, region, str(False), str(True), public_url, admin_url,
            internal_url])


class TestListEndpointTemplatesCommand(CommandTestCase):
    def test_no_args(self):
        self.run_cmd(list_endpoint_templates)
        lines = self.ob.read_lines()
        row = [col.strip() for col in lines[1].split('|') if col.strip()]
        self.assertEquals(['ID', 'Service ID', 'Region', 'Enabled', 'Global',
            'Public URL', 'Admin URL', 'Internal URL'], row)


class TestDeleteEndpointTemplateCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(delete_endpoint_template)

    def test_delete_endpoint_template(self):
        endpoint_template_id = self._create_endpoint_template(
                self._create_service())

        self.run_cmd(delete_endpoint_template, [
            '--where-id', endpoint_template_id])

        self.ob.clear()

        # ensure it's not returned
        self.run_cmd(list_endpoint_templates)
        output = self.ob.read()
        self.assertNotIn(endpoint_template_id, output)


class TestCreateEndpointCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(map_endpoint)

    def test_create_global_endpoint(self):
        tenant_id = self._create_tenant()
        endpoint_template_id = self._create_endpoint_template(
            self._create_service())
        self.run_cmd(map_endpoint, [
            '--endpoint-template-id', endpoint_template_id,
            '--tenant-id', tenant_id])

        self.ob.clear()

        self.run_cmd(list_endpoints)
        self.assertTableContainsRow(self.ob.read(), [endpoint_template_id,
            tenant_id])


class TestListEndpointsCommand(CommandTestCase):
    def test_no_args(self):
        self.run_cmd(list_endpoints)
        lines = self.ob.read_lines()
        row = [col.strip() for col in lines[1].split('|') if col.strip()]
        self.assertEquals(['Endpoint Template ID', 'Tenant ID'], row)


class TestDeleteEndpointCommand(CommandTestCase):
    def test_no_args(self):
        with self.assertRaises(SystemExit):
            self.run_cmd(unmap_endpoint)

    def test_delete_endpoint(self):
        tenant_id = self._create_tenant()
        endpoint_template_id = self._create_endpoint_template(
                self._create_service())
        self._map_endpoint(endpoint_template_id, tenant_id)

        self.run_cmd(unmap_endpoint, [
            '--tenant-id', tenant_id,
            '--endpoint-template-id', endpoint_template_id])

        self.ob.clear()

        # ensure it's not returned
        self.run_cmd(list_endpoints)
        output = self.ob.read()
        self.assertNotIn(" | ".join([endpoint_template_id, tenant_id]), output)
