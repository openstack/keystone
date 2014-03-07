# Copyright 2013 IBM Corp.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

import uuid

import mock
from oslo.config import cfg

from keystone.common import dependency
from keystone import notifications
from keystone.openstack.common.fixture import moxstubout
from keystone import tests
from keystone.tests import test_v3


CONF = cfg.CONF

EXP_RESOURCE_TYPE = uuid.uuid4().hex


class ArbitraryException(Exception):
    pass


class NotificationsWrapperTestCase(tests.TestCase):
    def setUp(self):
        super(NotificationsWrapperTestCase, self).setUp()

        self.exp_resource_id = None
        self.exp_operation = None
        self.send_notification_called = False

        def fake_notify(operation, resource_type, resource_id,
                        public=True):
            self.assertEqual(self.exp_operation, operation)
            self.assertEqual(EXP_RESOURCE_TYPE, resource_type)
            self.assertEqual(self.exp_resource_id, resource_id)
            self.send_notification_called = True

        fixture = self.useFixture(moxstubout.MoxStubout())
        self.stubs = fixture.stubs

        self.stubs.Set(notifications, '_send_notification', fake_notify)

    @notifications.created(EXP_RESOURCE_TYPE)
    def create_resource(self, resource_id, data):
        return data

    def test_resource_created_notification(self):
        self.exp_operation = 'created'
        self.exp_resource_id = uuid.uuid4().hex
        exp_resource_data = {
            'id': self.exp_resource_id,
            'key': uuid.uuid4().hex}

        self.create_resource(self.exp_resource_id, exp_resource_data)
        self.assertTrue(self.send_notification_called)

    @notifications.updated(EXP_RESOURCE_TYPE)
    def update_resource(self, resource_id, data):
        return data

    def test_resource_updated_notification(self):
        self.exp_operation = 'updated'
        self.exp_resource_id = uuid.uuid4().hex
        exp_resource_data = {
            'id': self.exp_resource_id,
            'key': uuid.uuid4().hex}

        self.update_resource(self.exp_resource_id, exp_resource_data)
        self.assertTrue(self.send_notification_called)

    @notifications.deleted(EXP_RESOURCE_TYPE)
    def delete_resource(self, resource_id):
        pass

    def test_resource_deleted_notification(self):
        self.exp_operation = 'deleted'
        self.exp_resource_id = uuid.uuid4().hex

        self.delete_resource(self.exp_resource_id)
        self.assertTrue(self.send_notification_called)

    @notifications.created(EXP_RESOURCE_TYPE)
    def create_exception(self, resource_id):
        raise ArbitraryException()

    def test_create_exception_without_notification(self):
        self.assertRaises(
            ArbitraryException, self.create_exception, uuid.uuid4().hex)
        self.assertFalse(self.send_notification_called)

    @notifications.created(EXP_RESOURCE_TYPE)
    def update_exception(self, resource_id):
        raise ArbitraryException()

    def test_update_exception_without_notification(self):
        self.assertRaises(
            ArbitraryException, self.update_exception, uuid.uuid4().hex)
        self.assertFalse(self.send_notification_called)

    @notifications.deleted(EXP_RESOURCE_TYPE)
    def delete_exception(self, resource_id):
        raise ArbitraryException()

    def test_delete_exception_without_notification(self):
        self.assertRaises(
            ArbitraryException, self.delete_exception, uuid.uuid4().hex)
        self.assertFalse(self.send_notification_called)


class NotificationsTestCase(tests.TestCase):
    def setUp(self):
        super(NotificationsTestCase, self).setUp()
        fixture = self.useFixture(moxstubout.MoxStubout())
        self.stubs = fixture.stubs

        # these should use self.config_fixture.config(), but they haven't
        # been registered yet
        CONF.rpc_backend = 'fake'
        CONF.notification_driver = ['fake']

    def test_send_notification(self):
        """Test the private method _send_notification to ensure event_type,
           payload, and context are built and passed properly.
        """
        resource = uuid.uuid4().hex
        resource_type = EXP_RESOURCE_TYPE
        operation = 'created'

        # NOTE(ldbragst): Even though notifications._send_notification doesn't
        # contain logic that creates cases, this is suppose to test that
        # context is always empty and that we ensure the resource ID of the
        # resource in the notification is contained in the payload. It was
        # agreed that context should be empty in Keystone's case, which is
        # also noted in the /keystone/notifications.py module. This test
        # ensures and maintains these conditions.
        expected_args = [
            {},  # empty context
            'identity.%s.created' % resource_type,  # event_type
            {'resource_info': resource},  # payload
            'INFO',  # priority is always INFO...
        ]

        with mock.patch.object(notifications._get_notifier(),
                               '_notify') as mocked:
            notifications._send_notification(operation, resource_type,
                                             resource)
            mocked.assert_called_once_with(*expected_args)

        notifications._send_notification(operation, resource_type, resource)


class NotificationsForEntities(test_v3.RestfulTestCase):
    def setUp(self):
        super(NotificationsForEntities, self).setUp()
        self._notifications = []

        def fake_notify(operation, resource_type, resource_id,
                        public=True):
            note = {
                'resource_id': resource_id,
                'operation': operation,
                'resource_type': resource_type,
                'send_notification_called': True,
                'public': public}
            self._notifications.append(note)

        fixture = self.useFixture(moxstubout.MoxStubout())
        self.stubs = fixture.stubs

        self.stubs.Set(notifications, '_send_notification', fake_notify)

    def _assertNotifySeen(self, resource_id, operation, resource_type):
        self.assertIn(operation, self.exp_operations)
        self.assertIn(resource_id, self.exp_resource_ids)
        self.assertIn(resource_type, self.exp_resource_types)
        self.assertTrue(self.send_notification_called)

    def _assertLastNotify(self, resource_id, operation, resource_type):
        self.assertTrue(len(self._notifications) > 0)
        note = self._notifications[-1]
        self.assertEqual(note['operation'], operation)
        self.assertEqual(note['resource_id'], resource_id)
        self.assertEqual(note['resource_type'], resource_type)
        self.assertTrue(note['send_notification_called'])

    def _assertNotifyNotSent(self, resource_id, operation, resource_type,
                             public=True):
        unexpected = {
            'resource_id': resource_id,
            'operation': operation,
            'resource_type': resource_type,
            'send_notification_called': True,
            'public': public}
        for note in self._notifications:
            self.assertNotEqual(unexpected, note)

    def _assertNotifySent(self, resource_id, operation, resource_type, public):
        expected = {
            'resource_id': resource_id,
            'operation': operation,
            'resource_type': resource_type,
            'send_notification_called': True,
            'public': public}
        for note in self._notifications:
            if expected == note:
                break
        else:
            self.fail("Notification not sent.")

    def test_create_group(self):
        group_ref = self.new_group_ref(domain_id=self.domain_id)
        self.identity_api.create_group(group_ref['id'], group_ref)
        self._assertLastNotify(group_ref['id'], 'created', 'group')

    def test_create_project(self):
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.assignment_api.create_project(project_ref['id'], project_ref)
        self._assertLastNotify(project_ref['id'], 'created', 'project')

    def test_create_role(self):
        role_ref = self.new_role_ref()
        self.assignment_api.create_role(role_ref['id'], role_ref)
        self._assertLastNotify(role_ref['id'], 'created', 'role')

    def test_create_user(self):
        user_ref = self.new_user_ref(domain_id=self.domain_id)
        self.identity_api.create_user(user_ref['id'], user_ref)
        self._assertLastNotify(user_ref['id'], 'created', 'user')

    def test_create_trust(self):
        trustor = self.new_user_ref(domain_id=self.domain_id)
        self.identity_api.create_user(trustor['id'], trustor)
        trustee = self.new_user_ref(domain_id=self.domain_id)
        self.identity_api.create_user(trustee['id'], trustee)
        role_ref = self.new_role_ref()
        self.assignment_api.create_role(role_ref['id'], role_ref)
        trust_ref = self.new_trust_ref(trustor['id'],
                                       trustee['id'])
        self.trust_api.create_trust(trust_ref['id'],
                                    trust_ref,
                                    [role_ref])
        self._assertLastNotify(trust_ref['id'], 'created', 'OS-TRUST:trust')

    def test_delete_group(self):
        group_ref = self.new_group_ref(domain_id=self.domain_id)
        self.identity_api.create_group(group_ref['id'], group_ref)
        self.identity_api.delete_group(group_ref['id'])
        self._assertLastNotify(group_ref['id'], 'deleted', 'group')

    def test_delete_project(self):
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.assignment_api.create_project(project_ref['id'], project_ref)
        self.assignment_api.delete_project(project_ref['id'])
        self._assertLastNotify(project_ref['id'], 'deleted', 'project')

    def test_delete_role(self):
        role_ref = self.new_role_ref()
        self.assignment_api.create_role(role_ref['id'], role_ref)
        self.assignment_api.delete_role(role_ref['id'])
        self._assertLastNotify(role_ref['id'], 'deleted', 'role')

    def test_delete_user(self):
        user_ref = self.new_user_ref(domain_id=self.domain_id)
        self.identity_api.create_user(user_ref['id'], user_ref)
        self.identity_api.delete_user(user_ref['id'])
        self._assertLastNotify(user_ref['id'], 'deleted', 'user')

    def test_update_domain(self):
        domain_ref = self.new_domain_ref()
        self.assignment_api.create_domain(domain_ref['id'], domain_ref)
        domain_ref['description'] = uuid.uuid4().hex
        self.assignment_api.update_domain(domain_ref['id'], domain_ref)
        self._assertLastNotify(domain_ref['id'], 'updated', 'domain')

    def test_delete_trust(self):
        trustor = self.new_user_ref(domain_id=self.domain_id)
        self.identity_api.create_user(trustor['id'], trustor)
        trustee = self.new_user_ref(domain_id=self.domain_id)
        self.identity_api.create_user(trustee['id'], trustee)
        role_ref = self.new_role_ref()
        trust_ref = self.new_trust_ref(trustor['id'], trustee['id'])
        self.trust_api.create_trust(trust_ref['id'],
                                    trust_ref,
                                    [role_ref])
        self.trust_api.delete_trust(trust_ref['id'])
        self._assertLastNotify(trust_ref['id'], 'deleted', 'OS-TRUST:trust')

    def test_delete_domain(self):
        domain_ref = self.new_domain_ref()
        self.assignment_api.create_domain(domain_ref['id'], domain_ref)
        domain_ref['enabled'] = False
        self.assignment_api.update_domain(domain_ref['id'], domain_ref)
        self.assignment_api.delete_domain(domain_ref['id'])
        self._assertLastNotify(domain_ref['id'], 'deleted', 'domain')

    def test_disable_domain(self):
        domain_ref = self.new_domain_ref()
        self.assignment_api.create_domain(domain_ref['id'], domain_ref)
        domain_ref['enabled'] = False
        self.assignment_api.update_domain(domain_ref['id'], domain_ref)
        self._assertNotifySent(domain_ref['id'], 'disabled', 'domain',
                               public=False)

    def test_update_group(self):
        group_ref = self.new_group_ref(domain_id=self.domain_id)
        self.identity_api.create_group(group_ref['id'], group_ref)
        self.identity_api.update_group(group_ref['id'], group_ref)
        self._assertLastNotify(group_ref['id'], 'updated', 'group')

    def test_update_project(self):
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.assignment_api.create_project(project_ref['id'], project_ref)
        self.assignment_api.update_project(project_ref['id'], project_ref)
        self._assertNotifySent(project_ref['id'], 'updated', 'project',
                               public=True)

    def test_disable_project(self):
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.assignment_api.create_project(project_ref['id'], project_ref)
        project_ref['enabled'] = False
        self.assignment_api.update_project(project_ref['id'], project_ref)
        self._assertNotifySent(project_ref['id'], 'disabled', 'project',
                               public=False)

    def test_update_project_does_not_send_disable(self):
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.assignment_api.create_project(project_ref['id'], project_ref)
        project_ref['enabled'] = True
        self.assignment_api.update_project(project_ref['id'], project_ref)
        self._assertLastNotify(project_ref['id'], 'updated', 'project')
        self._assertNotifyNotSent(project_ref['id'], 'disabled', 'project')

    def test_update_role(self):
        role_ref = self.new_role_ref()
        self.assignment_api.create_role(role_ref['id'], role_ref)
        self.assignment_api.update_role(role_ref['id'], role_ref)
        self._assertLastNotify(role_ref['id'], 'updated', 'role')

    def test_update_user(self):
        user_ref = self.new_user_ref(domain_id=self.domain_id)
        self.identity_api.create_user(user_ref['id'], user_ref)
        self.identity_api.update_user(user_ref['id'], user_ref)
        self._assertLastNotify(user_ref['id'], 'updated', 'user')


class TestEventCallbacks(test_v3.RestfulTestCase):

    def setUp(self):
        super(TestEventCallbacks, self).setUp()
        notifications.SUBSCRIBERS = {}
        self.has_been_called = False

    def _project_deleted_callback(self, service, resource_type, operation,
                                  payload):
        self.has_been_called = True

    def _project_created_callback(self, service, resource_type, operation,
                                  payload):
        self.has_been_called = True

    def test_notification_received(self):
        notifications.register_event_callback('created',
                                              'project',
                                              self._project_created_callback)
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.assignment_api.create_project(project_ref['id'], project_ref)
        self.assertTrue(self.has_been_called)

    def test_notification_method_not_callable(self):
        fake_method = None
        notifications.SUBSCRIBERS = {}
        self.assertRaises(TypeError,
                          notifications.register_event_callback,
                          'updated',
                          'project',
                          [fake_method])

    def test_notification_event_not_valid(self):
        self.assertRaises(ValueError,
                          notifications.register_event_callback,
                          uuid.uuid4().hex,
                          'project',
                          self._project_deleted_callback)

    def test_event_registration_for_unknown_resource_type(self):
        # Registration for unknown resource types should succeed.  If no event
        # is issued for that resource type, the callback wont be triggered.
        notifications.register_event_callback('deleted',
                                              uuid.uuid4().hex,
                                              self._project_deleted_callback)
        resource_type = uuid.uuid4().hex
        notifications.register_event_callback('deleted',
                                              resource_type,
                                              self._project_deleted_callback)
        self.assertIn('deleted', notifications.SUBSCRIBERS)
        self.assertIn(resource_type, notifications.SUBSCRIBERS['deleted'])

    def test_provider_event_callbacks_subscription(self):
        @dependency.provider('foo_api')
        class Foo:
            def __init__(self):
                self.event_callbacks = {
                    'created': {
                        'project': [self.foo_callback]}}

            def foo_callback(self, service, resource_type, operation,
                             payload):
                pass

        notifications.SUBSCRIBERS = {}
        Foo()
        self.assertIn('created', notifications.SUBSCRIBERS)

    def test_invalid_event_callbacks(self):
        @dependency.provider('foo_api')
        class Foo:
            def __init__(self):
                self.event_callbacks = 'bogus'

        notifications.SUBSCRIBERS = {}
        self.assertRaises(ValueError, Foo)

    def test_invalid_event_callbacks_event(self):
        @dependency.provider('foo_api')
        class Foo:
            def __init__(self):
                self.event_callbacks = {'created': 'bogus'}

        notifications.SUBSCRIBERS = {}
        self.assertRaises(ValueError, Foo)


class CadfNotificationsWrapperTestCase(test_v3.RestfulTestCase):

    LOCAL_HOST = 'localhost'
    ACTION = 'authenticate'

    def setUp(self):
        super(CadfNotificationsWrapperTestCase, self).setUp()
        self._notifications = []

        def fake_notify(action, initiator, outcome):
            note = {
                'action': action,
                'initiator': initiator,
                # NOTE(stevemar): outcome has 2 stages, pending and success
                # so we are ignoring it for now.
                #'outcome': outcome,
                'send_notification_called': True}
            self._notifications.append(note)

        # TODO(stevemar): Look into using mock instead of mox
        fixture = self.useFixture(moxstubout.MoxStubout())
        self.stubs = fixture.stubs
        self.stubs.Set(notifications, '_send_audit_notification',
                       fake_notify)

    def _assertLastNotify(self, action, user_id):
        self.assertTrue(self._notifications)
        note = self._notifications[-1]
        self.assertEqual(note['action'], action)
        initiator = note['initiator']
        self.assertEqual(initiator.name, user_id)
        self.assertEqual(initiator.host.address, self.LOCAL_HOST)
        self.assertTrue(note['send_notification_called'])

    def test_v3_authenticate_user_name_and_domain_id(self):
        user_id = self.user_id
        user_name = self.user['name']
        password = self.user['password']
        domain_id = self.domain_id
        data = self.build_authentication_request(username=user_name,
                                                 user_domain_id=domain_id,
                                                 password=password)
        self.post('/auth/tokens', body=data)
        self._assertLastNotify(self.ACTION, user_id)

    def test_v3_authenticate_user_id(self):
        user_id = self.user_id
        password = self.user['password']
        data = self.build_authentication_request(user_id=user_id,
                                                 password=password)
        self.post('/auth/tokens', body=data)
        self._assertLastNotify(self.ACTION, user_id)

    def test_v3_authenticate_user_name_and_domain_name(self):
        user_id = self.user_id
        user_name = self.user['name']
        password = self.user['password']
        domain_name = self.domain['name']
        data = self.build_authentication_request(username=user_name,
                                                 user_domain_name=domain_name,
                                                 password=password)
        self.post('/auth/tokens', body=data)
        self._assertLastNotify(self.ACTION, user_id)
