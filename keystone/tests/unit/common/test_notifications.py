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

import datetime
from unittest import mock
import uuid

import fixtures
import freezegun
import http.client
from oslo_config import fixture as config_fixture
from oslo_log import log
import oslo_messaging
from pycadf import cadftaxonomy
from pycadf import cadftype
from pycadf import eventfactory
from pycadf import resource as cadfresource

from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone import notifications
from keystone.tests import unit
from keystone.tests.unit import test_v3


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs

EXP_RESOURCE_TYPE = uuid.uuid4().hex
CREATED_OPERATION = notifications.ACTIONS.created
UPDATED_OPERATION = notifications.ACTIONS.updated
DELETED_OPERATION = notifications.ACTIONS.deleted
DISABLED_OPERATION = notifications.ACTIONS.disabled


class ArbitraryException(Exception):
    pass


def register_callback(operation, resource_type=EXP_RESOURCE_TYPE):
    """Helper for creating and registering a mock callback."""
    callback = mock.Mock(__name__='callback',
                         im_class=mock.Mock(__name__='class'))
    notifications.register_event_callback(operation, resource_type, callback)
    return callback


class AuditNotificationsTestCase(unit.BaseTestCase):
    def setUp(self):
        super(AuditNotificationsTestCase, self).setUp()
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.addCleanup(notifications.clear_subscribers)

    def _test_notification_operation_with_basic_format(self,
                                                       notify_function,
                                                       operation):
        self.config_fixture.config(notification_format='basic')
        exp_resource_id = uuid.uuid4().hex
        callback = register_callback(operation)
        notify_function(EXP_RESOURCE_TYPE, exp_resource_id)
        callback.assert_called_once_with('identity', EXP_RESOURCE_TYPE,
                                         operation,
                                         {'resource_info': exp_resource_id})

    def _test_notification_operation_with_cadf_format(self,
                                                      notify_function,
                                                      operation):
        self.config_fixture.config(notification_format='cadf')
        exp_resource_id = uuid.uuid4().hex
        with mock.patch(
                'keystone.notifications._create_cadf_payload') as cadf_notify:
            notify_function(EXP_RESOURCE_TYPE, exp_resource_id)
            initiator = None
            reason = None
            cadf_notify.assert_called_once_with(
                operation, EXP_RESOURCE_TYPE, exp_resource_id,
                notifications.taxonomy.OUTCOME_SUCCESS, initiator, reason)
            notify_function(EXP_RESOURCE_TYPE, exp_resource_id, public=False)
            cadf_notify.assert_called_once_with(
                operation, EXP_RESOURCE_TYPE, exp_resource_id,
                notifications.taxonomy.OUTCOME_SUCCESS, initiator, reason)

    def test_resource_created_notification(self):
        self._test_notification_operation_with_basic_format(
            notifications.Audit.created, CREATED_OPERATION)
        self._test_notification_operation_with_cadf_format(
            notifications.Audit.created, CREATED_OPERATION)

    def test_resource_updated_notification(self):
        self._test_notification_operation_with_basic_format(
            notifications.Audit.updated, UPDATED_OPERATION)
        self._test_notification_operation_with_cadf_format(
            notifications.Audit.updated, UPDATED_OPERATION)

    def test_resource_deleted_notification(self):
        self._test_notification_operation_with_basic_format(
            notifications.Audit.deleted, DELETED_OPERATION)
        self._test_notification_operation_with_cadf_format(
            notifications.Audit.deleted, DELETED_OPERATION)

    def test_resource_disabled_notification(self):
        self._test_notification_operation_with_basic_format(
            notifications.Audit.disabled, DISABLED_OPERATION)
        self._test_notification_operation_with_cadf_format(
            notifications.Audit.disabled, DISABLED_OPERATION)


class NotificationsTestCase(unit.BaseTestCase):

    def setUp(self):
        super(NotificationsTestCase, self).setUp()
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.config_fixture.config(
            group='oslo_messaging_notifications', transport_url='rabbit://'
        )

    def test_send_notification(self):
        """Test _send_notification.

        Test the private method _send_notification to ensure event_type,
        payload, and context are built and passed properly.

        """
        resource = uuid.uuid4().hex
        resource_type = EXP_RESOURCE_TYPE
        operation = CREATED_OPERATION

        conf = self.useFixture(config_fixture.Config(CONF))
        conf.config(notification_format='basic')

        # NOTE(ldbragst): Even though notifications._send_notification doesn't
        # contain logic that creates cases, this is supposed to test that
        # context is always empty and that we ensure the resource ID of the
        # resource in the notification is contained in the payload. It was
        # agreed that context should be empty in Keystone's case, which is
        # also noted in the /keystone/notifications.py module. This test
        # ensures and maintains these conditions.
        expected_args = [
            {},  # empty context
            'identity.%s.created' % resource_type,  # event_type
            {'resource_info': resource}  # payload
        ]

        with mock.patch.object(notifications._get_notifier(),
                               'info') as mocked:
            notifications._send_notification(operation, resource_type,
                                             resource)
            mocked.assert_called_once_with(*expected_args)

    def test_send_notification_with_opt_out(self):
        """Test the private method _send_notification with opt-out.

        Test that _send_notification does not notify when a valid
        notification_opt_out configuration is provided.
        """
        resource = uuid.uuid4().hex
        resource_type = EXP_RESOURCE_TYPE
        operation = CREATED_OPERATION
        event_type = 'identity.%s.created' % resource_type

        # NOTE(diazjf): Here we add notification_opt_out to the
        # configuration so that we should return before _get_notifer is
        # called. This is because we are opting out notifications for the
        # passed resource_type and operation.
        conf = self.useFixture(config_fixture.Config(CONF))
        conf.config(notification_opt_out=[event_type])

        with mock.patch.object(notifications._get_notifier(),
                               'info') as mocked:

            notifications._send_notification(operation, resource_type,
                                             resource)
            mocked.assert_not_called()

    def test_send_audit_notification_with_opt_out(self):
        """Test the private method _send_audit_notification with opt-out.

        Test that _send_audit_notification does not notify when a valid
        notification_opt_out configuration is provided.
        """
        resource_type = EXP_RESOURCE_TYPE

        action = CREATED_OPERATION + '.' + resource_type
        initiator = mock
        target = mock
        outcome = 'success'
        event_type = 'identity.%s.created' % resource_type

        conf = self.useFixture(config_fixture.Config(CONF))
        conf.config(notification_opt_out=[event_type])

        with mock.patch.object(notifications._get_notifier(),
                               'info') as mocked:

            notifications._send_audit_notification(action,
                                                   initiator,
                                                   outcome,
                                                   target,
                                                   event_type)
            mocked.assert_not_called()

    def test_opt_out_authenticate_event(self):
        """Test that authenticate events are successfully opted out."""
        resource_type = EXP_RESOURCE_TYPE

        action = CREATED_OPERATION + '.' + resource_type
        initiator = mock
        target = mock
        outcome = 'success'
        event_type = 'identity.authenticate'
        meter_name = '%s.%s' % (event_type, outcome)

        conf = self.useFixture(config_fixture.Config(CONF))
        conf.config(notification_opt_out=[meter_name])

        with mock.patch.object(notifications._get_notifier(),
                               'info') as mocked:

            notifications._send_audit_notification(action,
                                                   initiator,
                                                   outcome,
                                                   target,
                                                   event_type)
            mocked.assert_not_called()


class BaseNotificationTest(test_v3.RestfulTestCase):

    def setUp(self):
        super(BaseNotificationTest, self).setUp()

        self._notifications = []
        self._audits = []

        def fake_notify(operation, resource_type, resource_id, initiator=None,
                        actor_dict=None, public=True):
            note = {
                'resource_id': resource_id,
                'operation': operation,
                'resource_type': resource_type,
                'initiator': initiator,
                'send_notification_called': True,
                'public': public}
            if actor_dict:
                note['actor_id'] = actor_dict.get('id')
                note['actor_type'] = actor_dict.get('type')
                note['actor_operation'] = actor_dict.get('actor_operation')
            self._notifications.append(note)

        self.useFixture(fixtures.MockPatchObject(
            notifications, '_send_notification', fake_notify))

        def fake_audit(action, initiator, outcome, target,
                       event_type, reason=None, **kwargs):
            service_security = cadftaxonomy.SERVICE_SECURITY

            event = eventfactory.EventFactory().new_event(
                eventType=cadftype.EVENTTYPE_ACTIVITY,
                outcome=outcome,
                action=action,
                initiator=initiator,
                target=target,
                reason=reason,
                observer=cadfresource.Resource(typeURI=service_security))

            for key, value in kwargs.items():
                setattr(event, key, value)

            payload = event.as_dict()

            audit = {
                'payload': payload,
                'event_type': event_type,
                'send_notification_called': True}
            self._audits.append(audit)

        self.useFixture(fixtures.MockPatchObject(
            notifications, '_send_audit_notification', fake_audit))

    def _assert_last_note(self, resource_id, operation, resource_type,
                          actor_id=None, actor_type=None,
                          actor_operation=None):
        # NOTE(stevemar): If 'basic' format is not used, then simply
        # return since this assertion is not valid.
        if CONF.notification_format != 'basic':
            return
        self.assertGreater(len(self._notifications), 0)
        note = self._notifications[-1]
        self.assertEqual(operation, note['operation'])
        self.assertEqual(resource_id, note['resource_id'])
        self.assertEqual(resource_type, note['resource_type'])
        self.assertTrue(note['send_notification_called'])
        if actor_id:
            self.assertEqual(actor_id, note['actor_id'])
            self.assertEqual(actor_type, note['actor_type'])
            self.assertEqual(actor_operation, note['actor_operation'])

    def _assert_last_audit(self, resource_id, operation, resource_type,
                           target_uri, reason=None):
        # NOTE(stevemar): If 'cadf' format is not used, then simply
        # return since this assertion is not valid.
        if CONF.notification_format != 'cadf':
            return
        self.assertGreater(len(self._audits), 0)
        audit = self._audits[-1]
        payload = audit['payload']
        if 'resource_info' in payload:
            self.assertEqual(resource_id, payload['resource_info'])
        action = '.'.join(filter(None, [operation, resource_type]))
        self.assertEqual(action, payload['action'])
        self.assertEqual(target_uri, payload['target']['typeURI'])
        if resource_id:
            self.assertEqual(resource_id, payload['target']['id'])
        event_type = '.'.join(filter(None, ['identity',
                                            resource_type,
                                            operation]))
        self.assertEqual(event_type, audit['event_type'])
        if reason:
            self.assertEqual(reason['reasonCode'],
                             payload['reason']['reasonCode'])
            self.assertEqual(reason['reasonType'],
                             payload['reason']['reasonType'])
        self.assertTrue(audit['send_notification_called'])

    def _assert_initiator_data_is_set(self, operation, resource_type, typeURI):
        self.assertGreater(len(self._audits), 0)
        audit = self._audits[-1]
        payload = audit['payload']
        self.assertEqual(self.user_id, payload['initiator']['id'])
        self.assertEqual(self.project_id, payload['initiator']['project_id'])
        self.assertEqual(typeURI, payload['target']['typeURI'])
        self.assertIn('request_id', payload['initiator'])
        action = '%s.%s' % (operation, resource_type)
        self.assertEqual(action, payload['action'])

    def _assert_notify_not_sent(self, resource_id, operation, resource_type,
                                public=True):
        unexpected = {
            'resource_id': resource_id,
            'operation': operation,
            'resource_type': resource_type,
            'send_notification_called': True,
            'public': public}
        for note in self._notifications:
            self.assertNotEqual(unexpected, note)

    def _assert_notify_sent(self, resource_id, operation, resource_type,
                            public=True):
        expected = {
            'resource_id': resource_id,
            'operation': operation,
            'resource_type': resource_type,
            'send_notification_called': True,
            'public': public}
        for note in self._notifications:
            # compare only expected fields
            if all(note.get(k) == v for k, v in expected.items()):
                break
        else:
            self.fail("Notification not sent.")


class NotificationsForEntities(BaseNotificationTest):

    def test_create_group(self):
        group_ref = unit.new_group_ref(domain_id=self.domain_id)
        group_ref = PROVIDERS.identity_api.create_group(group_ref)
        self._assert_last_note(group_ref['id'], CREATED_OPERATION, 'group')
        self._assert_last_audit(group_ref['id'], CREATED_OPERATION, 'group',
                                cadftaxonomy.SECURITY_GROUP)

    def test_create_project(self):
        project_ref = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)
        self._assert_last_note(
            project_ref['id'], CREATED_OPERATION, 'project')
        self._assert_last_audit(project_ref['id'], CREATED_OPERATION,
                                'project', cadftaxonomy.SECURITY_PROJECT)

    def test_create_role(self):
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)
        self._assert_last_note(role_ref['id'], CREATED_OPERATION, 'role')
        self._assert_last_audit(role_ref['id'], CREATED_OPERATION, 'role',
                                cadftaxonomy.SECURITY_ROLE)

    def test_create_user(self):
        user_ref = unit.new_user_ref(domain_id=self.domain_id)
        user_ref = PROVIDERS.identity_api.create_user(user_ref)
        self._assert_last_note(user_ref['id'], CREATED_OPERATION, 'user')
        self._assert_last_audit(user_ref['id'], CREATED_OPERATION, 'user',
                                cadftaxonomy.SECURITY_ACCOUNT_USER)

    def test_create_trust(self):
        trustor = unit.new_user_ref(domain_id=self.domain_id)
        trustor = PROVIDERS.identity_api.create_user(trustor)
        trustee = unit.new_user_ref(domain_id=self.domain_id)
        trustee = PROVIDERS.identity_api.create_user(trustee)
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)
        trust_ref = unit.new_trust_ref(trustor['id'],
                                       trustee['id'])
        PROVIDERS.trust_api.create_trust(
            trust_ref['id'], trust_ref, [role_ref]
        )
        self._assert_last_note(
            trust_ref['id'], CREATED_OPERATION, 'OS-TRUST:trust')
        self._assert_last_audit(trust_ref['id'], CREATED_OPERATION,
                                'OS-TRUST:trust', cadftaxonomy.SECURITY_TRUST)

    def test_delete_group(self):
        group_ref = unit.new_group_ref(domain_id=self.domain_id)
        group_ref = PROVIDERS.identity_api.create_group(group_ref)
        PROVIDERS.identity_api.delete_group(group_ref['id'])
        self._assert_last_note(group_ref['id'], DELETED_OPERATION, 'group')
        self._assert_last_audit(group_ref['id'], DELETED_OPERATION, 'group',
                                cadftaxonomy.SECURITY_GROUP)

    def test_delete_project(self):
        project_ref = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)
        PROVIDERS.resource_api.delete_project(project_ref['id'])
        self._assert_last_note(
            project_ref['id'], DELETED_OPERATION, 'project')
        self._assert_last_audit(project_ref['id'], DELETED_OPERATION,
                                'project', cadftaxonomy.SECURITY_PROJECT)

    def test_delete_role(self):
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)
        PROVIDERS.role_api.delete_role(role_ref['id'])
        self._assert_last_note(role_ref['id'], DELETED_OPERATION, 'role')
        self._assert_last_audit(role_ref['id'], DELETED_OPERATION, 'role',
                                cadftaxonomy.SECURITY_ROLE)

    def test_delete_user(self):
        user_ref = unit.new_user_ref(domain_id=self.domain_id)
        user_ref = PROVIDERS.identity_api.create_user(user_ref)
        PROVIDERS.identity_api.delete_user(user_ref['id'])
        self._assert_last_note(user_ref['id'], DELETED_OPERATION, 'user')
        self._assert_last_audit(user_ref['id'], DELETED_OPERATION, 'user',
                                cadftaxonomy.SECURITY_ACCOUNT_USER)

    def test_create_domain(self):
        domain_ref = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain_ref['id'], domain_ref)
        self._assert_last_note(domain_ref['id'], CREATED_OPERATION, 'domain')
        self._assert_last_audit(domain_ref['id'], CREATED_OPERATION, 'domain',
                                cadftaxonomy.SECURITY_DOMAIN)

    def test_update_domain(self):
        domain_ref = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain_ref['id'], domain_ref)
        domain_ref['description'] = uuid.uuid4().hex
        PROVIDERS.resource_api.update_domain(domain_ref['id'], domain_ref)
        self._assert_last_note(domain_ref['id'], UPDATED_OPERATION, 'domain')
        self._assert_last_audit(domain_ref['id'], UPDATED_OPERATION, 'domain',
                                cadftaxonomy.SECURITY_DOMAIN)

    def test_delete_domain(self):
        domain_ref = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain_ref['id'], domain_ref)
        domain_ref['enabled'] = False
        PROVIDERS.resource_api.update_domain(domain_ref['id'], domain_ref)
        PROVIDERS.resource_api.delete_domain(domain_ref['id'])
        self._assert_last_note(domain_ref['id'], DELETED_OPERATION, 'domain')
        self._assert_last_audit(domain_ref['id'], DELETED_OPERATION, 'domain',
                                cadftaxonomy.SECURITY_DOMAIN)

    def test_delete_trust(self):
        trustor = unit.new_user_ref(domain_id=self.domain_id)
        trustor = PROVIDERS.identity_api.create_user(trustor)
        trustee = unit.new_user_ref(domain_id=self.domain_id)
        trustee = PROVIDERS.identity_api.create_user(trustee)
        role_ref = unit.new_role_ref()
        trust_ref = unit.new_trust_ref(trustor['id'], trustee['id'])
        PROVIDERS.trust_api.create_trust(
            trust_ref['id'], trust_ref, [role_ref]
        )
        PROVIDERS.trust_api.delete_trust(trust_ref['id'])
        self._assert_last_note(
            trust_ref['id'], DELETED_OPERATION, 'OS-TRUST:trust')
        self._assert_last_audit(trust_ref['id'], DELETED_OPERATION,
                                'OS-TRUST:trust', cadftaxonomy.SECURITY_TRUST)

    def test_create_endpoint(self):
        endpoint_ref = unit.new_endpoint_ref(service_id=self.service_id,
                                             interface='public',
                                             region_id=self.region_id)
        PROVIDERS.catalog_api.create_endpoint(endpoint_ref['id'], endpoint_ref)
        self._assert_notify_sent(endpoint_ref['id'], CREATED_OPERATION,
                                 'endpoint')
        self._assert_last_audit(endpoint_ref['id'], CREATED_OPERATION,
                                'endpoint', cadftaxonomy.SECURITY_ENDPOINT)

    def test_update_endpoint(self):
        endpoint_ref = unit.new_endpoint_ref(service_id=self.service_id,
                                             interface='public',
                                             region_id=self.region_id)
        PROVIDERS.catalog_api.create_endpoint(endpoint_ref['id'], endpoint_ref)
        PROVIDERS.catalog_api.update_endpoint(endpoint_ref['id'], endpoint_ref)
        self._assert_notify_sent(endpoint_ref['id'], UPDATED_OPERATION,
                                 'endpoint')
        self._assert_last_audit(endpoint_ref['id'], UPDATED_OPERATION,
                                'endpoint', cadftaxonomy.SECURITY_ENDPOINT)

    def test_delete_endpoint(self):
        endpoint_ref = unit.new_endpoint_ref(service_id=self.service_id,
                                             interface='public',
                                             region_id=self.region_id)
        PROVIDERS.catalog_api.create_endpoint(endpoint_ref['id'], endpoint_ref)
        PROVIDERS.catalog_api.delete_endpoint(endpoint_ref['id'])
        self._assert_notify_sent(endpoint_ref['id'], DELETED_OPERATION,
                                 'endpoint')
        self._assert_last_audit(endpoint_ref['id'], DELETED_OPERATION,
                                'endpoint', cadftaxonomy.SECURITY_ENDPOINT)

    def test_create_service(self):
        service_ref = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(service_ref['id'], service_ref)
        self._assert_notify_sent(service_ref['id'], CREATED_OPERATION,
                                 'service')
        self._assert_last_audit(service_ref['id'], CREATED_OPERATION,
                                'service', cadftaxonomy.SECURITY_SERVICE)

    def test_update_service(self):
        service_ref = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(service_ref['id'], service_ref)
        PROVIDERS.catalog_api.update_service(service_ref['id'], service_ref)
        self._assert_notify_sent(service_ref['id'], UPDATED_OPERATION,
                                 'service')
        self._assert_last_audit(service_ref['id'], UPDATED_OPERATION,
                                'service', cadftaxonomy.SECURITY_SERVICE)

    def test_delete_service(self):
        service_ref = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(service_ref['id'], service_ref)
        PROVIDERS.catalog_api.delete_service(service_ref['id'])
        self._assert_notify_sent(service_ref['id'], DELETED_OPERATION,
                                 'service')
        self._assert_last_audit(service_ref['id'], DELETED_OPERATION,
                                'service', cadftaxonomy.SECURITY_SERVICE)

    def test_create_region(self):
        region_ref = unit.new_region_ref()
        PROVIDERS.catalog_api.create_region(region_ref)
        self._assert_notify_sent(region_ref['id'], CREATED_OPERATION,
                                 'region')
        self._assert_last_audit(region_ref['id'], CREATED_OPERATION,
                                'region', cadftaxonomy.SECURITY_REGION)

    def test_update_region(self):
        region_ref = unit.new_region_ref()
        PROVIDERS.catalog_api.create_region(region_ref)
        PROVIDERS.catalog_api.update_region(region_ref['id'], region_ref)
        self._assert_notify_sent(region_ref['id'], UPDATED_OPERATION,
                                 'region')
        self._assert_last_audit(region_ref['id'], UPDATED_OPERATION,
                                'region', cadftaxonomy.SECURITY_REGION)

    def test_delete_region(self):
        region_ref = unit.new_region_ref()
        PROVIDERS.catalog_api.create_region(region_ref)
        PROVIDERS.catalog_api.delete_region(region_ref['id'])
        self._assert_notify_sent(region_ref['id'], DELETED_OPERATION,
                                 'region')
        self._assert_last_audit(region_ref['id'], DELETED_OPERATION,
                                'region', cadftaxonomy.SECURITY_REGION)

    def test_create_policy(self):
        policy_ref = unit.new_policy_ref()
        PROVIDERS.policy_api.create_policy(policy_ref['id'], policy_ref)
        self._assert_notify_sent(policy_ref['id'], CREATED_OPERATION,
                                 'policy')
        self._assert_last_audit(policy_ref['id'], CREATED_OPERATION,
                                'policy', cadftaxonomy.SECURITY_POLICY)

    def test_update_policy(self):
        policy_ref = unit.new_policy_ref()
        PROVIDERS.policy_api.create_policy(policy_ref['id'], policy_ref)
        PROVIDERS.policy_api.update_policy(policy_ref['id'], policy_ref)
        self._assert_notify_sent(policy_ref['id'], UPDATED_OPERATION,
                                 'policy')
        self._assert_last_audit(policy_ref['id'], UPDATED_OPERATION,
                                'policy', cadftaxonomy.SECURITY_POLICY)

    def test_delete_policy(self):
        policy_ref = unit.new_policy_ref()
        PROVIDERS.policy_api.create_policy(policy_ref['id'], policy_ref)
        PROVIDERS.policy_api.delete_policy(policy_ref['id'])
        self._assert_notify_sent(policy_ref['id'], DELETED_OPERATION,
                                 'policy')
        self._assert_last_audit(policy_ref['id'], DELETED_OPERATION,
                                'policy', cadftaxonomy.SECURITY_POLICY)

    def test_disable_domain(self):
        domain_ref = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain_ref['id'], domain_ref)
        domain_ref['enabled'] = False
        PROVIDERS.resource_api.update_domain(domain_ref['id'], domain_ref)
        self._assert_notify_sent(domain_ref['id'], 'disabled', 'domain',
                                 public=False)

    def test_disable_of_disabled_domain_does_not_notify(self):
        domain_ref = unit.new_domain_ref(enabled=False)
        PROVIDERS.resource_api.create_domain(domain_ref['id'], domain_ref)
        # The domain_ref above is not changed during the create process. We
        # can use the same ref to perform the update.
        PROVIDERS.resource_api.update_domain(domain_ref['id'], domain_ref)
        self._assert_notify_not_sent(domain_ref['id'], 'disabled', 'domain',
                                     public=False)

    def test_update_group(self):
        group_ref = unit.new_group_ref(domain_id=self.domain_id)
        group_ref = PROVIDERS.identity_api.create_group(group_ref)
        PROVIDERS.identity_api.update_group(group_ref['id'], group_ref)
        self._assert_last_note(group_ref['id'], UPDATED_OPERATION, 'group')
        self._assert_last_audit(group_ref['id'], UPDATED_OPERATION, 'group',
                                cadftaxonomy.SECURITY_GROUP)

    def test_update_project(self):
        project_ref = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)
        PROVIDERS.resource_api.update_project(project_ref['id'], project_ref)
        self._assert_notify_sent(
            project_ref['id'], UPDATED_OPERATION, 'project', public=True)
        self._assert_last_audit(project_ref['id'], UPDATED_OPERATION,
                                'project', cadftaxonomy.SECURITY_PROJECT)

    def test_disable_project(self):
        project_ref = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)
        project_ref['enabled'] = False
        PROVIDERS.resource_api.update_project(project_ref['id'], project_ref)
        self._assert_notify_sent(project_ref['id'], 'disabled', 'project',
                                 public=False)

    def test_disable_of_disabled_project_does_not_notify(self):
        project_ref = unit.new_project_ref(domain_id=self.domain_id,
                                           enabled=False)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)
        # The project_ref above is not changed during the create process. We
        # can use the same ref to perform the update.
        PROVIDERS.resource_api.update_project(project_ref['id'], project_ref)
        self._assert_notify_not_sent(project_ref['id'], 'disabled', 'project',
                                     public=False)

    def test_update_project_does_not_send_disable(self):
        project_ref = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)
        project_ref['enabled'] = True
        PROVIDERS.resource_api.update_project(project_ref['id'], project_ref)
        self._assert_last_note(
            project_ref['id'], UPDATED_OPERATION, 'project')
        self._assert_notify_not_sent(project_ref['id'], 'disabled', 'project')

    def test_update_role(self):
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)
        PROVIDERS.role_api.update_role(role_ref['id'], role_ref)
        self._assert_last_note(role_ref['id'], UPDATED_OPERATION, 'role')
        self._assert_last_audit(role_ref['id'], UPDATED_OPERATION, 'role',
                                cadftaxonomy.SECURITY_ROLE)

    def test_update_user(self):
        user_ref = unit.new_user_ref(domain_id=self.domain_id)
        user_ref = PROVIDERS.identity_api.create_user(user_ref)
        PROVIDERS.identity_api.update_user(user_ref['id'], user_ref)
        self._assert_last_note(user_ref['id'], UPDATED_OPERATION, 'user')
        self._assert_last_audit(user_ref['id'], UPDATED_OPERATION, 'user',
                                cadftaxonomy.SECURITY_ACCOUNT_USER)

    def test_config_option_no_events(self):
        self.config_fixture.config(notification_format='basic')
        role_ref = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_ref['id'], role_ref)
        # The regular notifications will still be emitted, since they are
        # used for callback handling.
        self._assert_last_note(role_ref['id'], CREATED_OPERATION, 'role')
        # No audit event should have occurred
        self.assertEqual(0, len(self._audits))

    def test_add_user_to_group(self):
        user_ref = unit.new_user_ref(domain_id=self.domain_id)
        user_ref = PROVIDERS.identity_api.create_user(user_ref)
        group_ref = unit.new_group_ref(domain_id=self.domain_id)
        group_ref = PROVIDERS.identity_api.create_group(group_ref)
        PROVIDERS.identity_api.add_user_to_group(
            user_ref['id'], group_ref['id']
        )
        self._assert_last_note(group_ref['id'], UPDATED_OPERATION, 'group',
                               actor_id=user_ref['id'], actor_type='user',
                               actor_operation='added')

    def test_remove_user_from_group(self):
        user_ref = unit.new_user_ref(domain_id=self.domain_id)
        user_ref = PROVIDERS.identity_api.create_user(user_ref)
        group_ref = unit.new_group_ref(domain_id=self.domain_id)
        group_ref = PROVIDERS.identity_api.create_group(group_ref)
        PROVIDERS.identity_api.add_user_to_group(
            user_ref['id'], group_ref['id']
        )
        PROVIDERS.identity_api.remove_user_from_group(
            user_ref['id'], group_ref['id']
        )
        self._assert_last_note(group_ref['id'], UPDATED_OPERATION, 'group',
                               actor_id=user_ref['id'], actor_type='user',
                               actor_operation='removed')

    def test_initiator_request_id(self):
        ref = unit.new_domain_ref()
        self.post('/domains', body={'domain': ref})
        note = self._notifications[-1]
        initiator = note['initiator']
        self.assertIsNotNone(initiator.request_id)

    def test_initiator_global_request_id(self):
        global_request_id = 'req-%s' % uuid.uuid4()
        ref = unit.new_domain_ref()
        self.post('/domains', body={'domain': ref},
                  headers={'X-OpenStack-Request-Id': global_request_id})
        note = self._notifications[-1]
        initiator = note['initiator']
        self.assertEqual(
            initiator.global_request_id, global_request_id)

    def test_initiator_global_request_id_not_set(self):
        ref = unit.new_domain_ref()
        self.post('/domains', body={'domain': ref})
        note = self._notifications[-1]
        initiator = note['initiator']
        self.assertFalse(hasattr(initiator, 'global_request_id'))


class CADFNotificationsForPCIDSSEvents(BaseNotificationTest):

    def setUp(self):
        super(CADFNotificationsForPCIDSSEvents, self).setUp()
        conf = self.useFixture(config_fixture.Config(CONF))
        conf.config(notification_format='cadf')
        conf.config(group='security_compliance',
                    password_expires_days=2)
        conf.config(group='security_compliance',
                    lockout_failure_attempts=3)
        conf.config(group='security_compliance',
                    unique_last_password_count=2)
        conf.config(group='security_compliance',
                    minimum_password_age=2)
        conf.config(group='security_compliance',
                    password_regex=r'^(?=.*\d)(?=.*[a-zA-Z]).{7,}$')
        conf.config(group='security_compliance',
                    password_regex_description='1 letter, 1 digit, 7 chars')

    def test_password_expired_sends_notification(self):
        password = uuid.uuid4().hex
        password_creation_time = (
            datetime.datetime.utcnow() -
            datetime.timedelta(
                days=CONF.security_compliance.password_expires_days + 1)
        )
        freezer = freezegun.freeze_time(password_creation_time)

        # NOTE(gagehugo): This part below uses freezegun to spoof
        # the time as being three days in the past from right now. We will
        # create a user and have that user successfully authenticate,
        # then stop the time machine and return to the present time,
        # where the user's password is now expired.
        freezer.start()
        user_ref = unit.new_user_ref(domain_id=self.domain_id,
                                     password=password)
        user_ref = PROVIDERS.identity_api.create_user(user_ref)
        with self.make_request():
            PROVIDERS.identity_api.authenticate(user_ref['id'], password)
        freezer.stop()

        reason_type = (exception.PasswordExpired.message_format %
                       {'user_id': user_ref['id']})
        expected_reason = {'reasonCode': '401',
                           'reasonType': reason_type}
        with self.make_request():
            self.assertRaises(exception.PasswordExpired,
                              PROVIDERS.identity_api.authenticate,
                              user_id=user_ref['id'],
                              password=password)
        self._assert_last_audit(None, 'authenticate', None,
                                cadftaxonomy.ACCOUNT_USER,
                                reason=expected_reason)

    def test_locked_out_user_sends_notification(self):
        password = uuid.uuid4().hex
        new_password = uuid.uuid4().hex
        expected_responses = [AssertionError, AssertionError, AssertionError,
                              exception.Unauthorized]
        user_ref = unit.new_user_ref(domain_id=self.domain_id,
                                     password=password)
        user_ref = PROVIDERS.identity_api.create_user(user_ref)
        reason_type = (exception.AccountLocked.message_format %
                       {'user_id': user_ref['id']})
        expected_reason = {'reasonCode': '401',
                           'reasonType': reason_type}
        for ex in expected_responses:
            with self.make_request():
                self.assertRaises(ex,
                                  PROVIDERS.identity_api.change_password,
                                  user_id=user_ref['id'],
                                  original_password=new_password,
                                  new_password=new_password)

        self._assert_last_audit(None, 'authenticate', None,
                                cadftaxonomy.ACCOUNT_USER,
                                reason=expected_reason)

    def test_repeated_password_sends_notification(self):
        conf = self.useFixture(config_fixture.Config(CONF))
        conf.config(group='security_compliance',
                    minimum_password_age=0)
        password = uuid.uuid4().hex
        new_password = uuid.uuid4().hex
        count = CONF.security_compliance.unique_last_password_count
        reason_type = (exception.PasswordHistoryValidationError.message_format
                       % {'unique_count': count})
        expected_reason = {'reasonCode': '400',
                           'reasonType': reason_type}
        user_ref = unit.new_user_ref(domain_id=self.domain_id,
                                     password=password)
        user_ref = PROVIDERS.identity_api.create_user(user_ref)
        with self.make_request():
            PROVIDERS.identity_api.change_password(
                user_id=user_ref['id'],
                original_password=password, new_password=new_password
            )
        with self.make_request():
            self.assertRaises(exception.PasswordValidationError,
                              PROVIDERS.identity_api.change_password,
                              user_id=user_ref['id'],
                              original_password=new_password,
                              new_password=password)

        self._assert_last_audit(user_ref['id'], UPDATED_OPERATION, 'user',
                                cadftaxonomy.SECURITY_ACCOUNT_USER,
                                reason=expected_reason)

    def test_invalid_password_sends_notification(self):
        password = uuid.uuid4().hex
        invalid_password = '1'
        regex = CONF.security_compliance.password_regex_description
        reason_type = (exception.PasswordRequirementsValidationError
                       .message_format %
                       {'detail': regex})
        expected_reason = {'reasonCode': '400',
                           'reasonType': reason_type}
        user_ref = unit.new_user_ref(domain_id=self.domain_id,
                                     password=password)
        user_ref = PROVIDERS.identity_api.create_user(user_ref)
        with self.make_request():
            self.assertRaises(exception.PasswordValidationError,
                              PROVIDERS.identity_api.change_password,
                              user_id=user_ref['id'],
                              original_password=password,
                              new_password=invalid_password)

        self._assert_last_audit(user_ref['id'], UPDATED_OPERATION, 'user',
                                cadftaxonomy.SECURITY_ACCOUNT_USER,
                                reason=expected_reason)

    def test_changing_password_too_early_sends_notification(self):
        password = uuid.uuid4().hex
        new_password = uuid.uuid4().hex
        next_password = uuid.uuid4().hex

        user_ref = unit.new_user_ref(domain_id=self.domain_id,
                                     password=password,
                                     password_created_at=(
                                         datetime.datetime.utcnow()))
        user_ref = PROVIDERS.identity_api.create_user(user_ref)

        min_days = CONF.security_compliance.minimum_password_age
        min_age = (user_ref['password_created_at'] +
                   datetime.timedelta(days=min_days))
        days_left = (min_age - datetime.datetime.utcnow()).days
        reason_type = (exception.PasswordAgeValidationError.message_format %
                       {'min_age_days': min_days, 'days_left': days_left})
        expected_reason = {'reasonCode': '400',
                           'reasonType': reason_type}
        with self.make_request():
            PROVIDERS.identity_api.change_password(
                user_id=user_ref['id'],
                original_password=password, new_password=new_password
            )
        with self.make_request():
            self.assertRaises(exception.PasswordValidationError,
                              PROVIDERS.identity_api.change_password,
                              user_id=user_ref['id'],
                              original_password=new_password,
                              new_password=next_password)

        self._assert_last_audit(user_ref['id'], UPDATED_OPERATION, 'user',
                                cadftaxonomy.SECURITY_ACCOUNT_USER,
                                reason=expected_reason)


class CADFNotificationsForEntities(NotificationsForEntities):

    def setUp(self):
        super(CADFNotificationsForEntities, self).setUp()
        self.config_fixture.config(notification_format='cadf')

    def test_initiator_data_is_set(self):
        ref = unit.new_domain_ref()
        resp = self.post('/domains', body={'domain': ref})
        resource_id = resp.result.get('domain').get('id')
        self._assert_last_audit(resource_id, CREATED_OPERATION, 'domain',
                                cadftaxonomy.SECURITY_DOMAIN)
        self._assert_initiator_data_is_set(CREATED_OPERATION,
                                           'domain',
                                           cadftaxonomy.SECURITY_DOMAIN)

    def test_initiator_request_id(self):
        data = self.build_authentication_request(
            user_id=self.user_id,
            password=self.user['password'])
        self.post('/auth/tokens', body=data)
        audit = self._audits[-1]
        initiator = audit['payload']['initiator']
        self.assertIn('request_id', initiator)

    def test_initiator_global_request_id(self):
        global_request_id = 'req-%s' % uuid.uuid4()
        data = self.build_authentication_request(
            user_id=self.user_id,
            password=self.user['password'])
        self.post(
            '/auth/tokens', body=data,
            headers={'X-OpenStack-Request-Id': global_request_id})
        audit = self._audits[-1]
        initiator = audit['payload']['initiator']
        self.assertEqual(
            initiator['global_request_id'], global_request_id)

    def test_initiator_global_request_id_not_set(self):
        data = self.build_authentication_request(
            user_id=self.user_id,
            password=self.user['password'])
        self.post('/auth/tokens', body=data)
        audit = self._audits[-1]
        initiator = audit['payload']['initiator']
        self.assertNotIn('global_request_id', initiator)


class TestEventCallbacks(test_v3.RestfulTestCase):

    class FakeManager(object):

        def _project_deleted_callback(self, service, resource_type, operation,
                                      payload):
            """Used just for the callback interface."""

    def test_notification_received(self):
        callback = register_callback(CREATED_OPERATION, 'project')
        project_ref = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)
        self.assertTrue(callback.called)

    def test_notification_method_not_callable(self):
        fake_method = None
        self.assertRaises(TypeError,
                          notifications.register_event_callback,
                          UPDATED_OPERATION,
                          'project',
                          [fake_method])

    def test_notification_event_not_valid(self):
        manager = self.FakeManager()
        self.assertRaises(ValueError,
                          notifications.register_event_callback,
                          uuid.uuid4().hex,
                          'project',
                          manager._project_deleted_callback)

    def test_event_registration_for_unknown_resource_type(self):
        # Registration for unknown resource types should succeed.  If no event
        # is issued for that resource type, the callback wont be triggered.

        manager = self.FakeManager()

        notifications.register_event_callback(
            DELETED_OPERATION,
            uuid.uuid4().hex,
            manager._project_deleted_callback)
        resource_type = uuid.uuid4().hex
        notifications.register_event_callback(
            DELETED_OPERATION,
            resource_type,
            manager._project_deleted_callback)

    def test_provider_event_callback_subscription(self):
        callback_called = []

        @notifications.listener
        class Foo(object):
            def __init__(self):
                self.event_callbacks = {
                    CREATED_OPERATION: {'project': self.foo_callback}}

            def foo_callback(self, service, resource_type, operation,
                             payload):
                # uses callback_called from the closure
                callback_called.append(True)

        Foo()
        project_ref = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)
        self.assertEqual([True], callback_called)

    def test_provider_event_callbacks_subscription(self):
        callback_called = []

        @notifications.listener
        class Foo(object):
            def __init__(self):
                self.event_callbacks = {
                    CREATED_OPERATION: {
                        'project': [self.callback_0, self.callback_1]}}

            def callback_0(self, service, resource_type, operation, payload):
                # uses callback_called from the closure
                callback_called.append('cb0')

            def callback_1(self, service, resource_type, operation, payload):
                # uses callback_called from the closure
                callback_called.append('cb1')

        Foo()
        project_ref = unit.new_project_ref(domain_id=self.domain_id)
        PROVIDERS.resource_api.create_project(project_ref['id'], project_ref)
        self.assertCountEqual(['cb1', 'cb0'], callback_called)

    def test_invalid_event_callbacks(self):
        @notifications.listener
        class Foo(object):
            def __init__(self):
                self.event_callbacks = 'bogus'

        self.assertRaises(AttributeError, Foo)

    def test_invalid_event_callbacks_event(self):
        @notifications.listener
        class Foo(object):
            def __init__(self):
                self.event_callbacks = {CREATED_OPERATION: 'bogus'}

        self.assertRaises(AttributeError, Foo)

    def test_using_an_unbound_method_as_a_callback_fails(self):
        # NOTE(dstanek): An unbound method is when you reference a method
        # from a class object. You'll get a method that isn't bound to a
        # particular instance so there is no magic 'self'. You can call it,
        # but you have to pass in the instance manually like: C.m(C()).
        # If you reference the method from an instance then you get a method
        # that effectively curries the self argument for you
        # (think functools.partial). Obviously is we don't have an
        # instance then we can't call the method.
        @notifications.listener
        class Foo(object):
            def __init__(self):
                self.event_callbacks = {CREATED_OPERATION:
                                        {'project': Foo.callback}}

            def callback(self, service, resource_type, operation, payload):
                pass

        # TODO(dstanek): it would probably be nice to fail early using
        # something like:
        #     self.assertRaises(TypeError, Foo)
        Foo()
        project_ref = unit.new_project_ref(domain_id=self.domain_id)
        self.assertRaises(TypeError, PROVIDERS.resource_api.create_project,
                          project_ref['id'], project_ref)


class CadfNotificationsWrapperTestCase(test_v3.RestfulTestCase):

    LOCAL_HOST = 'localhost'
    ACTION = 'authenticate'
    ROLE_ASSIGNMENT = 'role_assignment'

    def setUp(self):
        super(CadfNotificationsWrapperTestCase, self).setUp()
        self._notifications = []

        def fake_notify(action, initiator, outcome, target,
                        event_type, reason=None, **kwargs):
            service_security = cadftaxonomy.SERVICE_SECURITY

            event = eventfactory.EventFactory().new_event(
                eventType=cadftype.EVENTTYPE_ACTIVITY,
                outcome=outcome,
                action=action,
                initiator=initiator,
                target=target,
                reason=reason,
                observer=cadfresource.Resource(typeURI=service_security))

            for key, value in kwargs.items():
                setattr(event, key, value)

            note = {
                'action': action,
                'initiator': initiator,
                'event': event,
                'event_type': event_type,
                'send_notification_called': True}
            self._notifications.append(note)

        self.useFixture(fixtures.MockPatchObject(
            notifications, '_send_audit_notification', fake_notify))

    def _get_last_note(self):
        self.assertTrue(self._notifications)
        return self._notifications[-1]

    def _assert_last_note(self, action, user_id, event_type=None):
        self.assertTrue(self._notifications)
        note = self._notifications[-1]
        self.assertEqual(action, note['action'])
        initiator = note['initiator']
        self.assertEqual(user_id, initiator.id)
        self.assertEqual(self.LOCAL_HOST, initiator.host.address)
        self.assertTrue(note['send_notification_called'])
        if event_type:
            self.assertEqual(event_type, note['event_type'])

    def _assert_event(self, role_id, project=None, domain=None,
                      user=None, group=None, inherit=False):
        """Assert that the CADF event is valid.

        In the case of role assignments, the event will have extra data,
        specifically, the role, target, actor, and if the role is inherited.

        An example event, as a dictionary is seen below:
            {
                'typeURI': 'http://schemas.dmtf.org/cloud/audit/1.0/event',
                'initiator': {
                    'typeURI': 'service/security/account/user',
                    'host': {'address': 'localhost'},
                    'id': 'openstack:0a90d95d-582c-4efb-9cbc-e2ca7ca9c341',
                    'username': u'admin'
                },
                'target': {
                    'typeURI': 'service/security/account/user',
                    'id': 'openstack:d48ea485-ef70-4f65-8d2b-01aa9d7ec12d'
                },
                'observer': {
                    'typeURI': 'service/security',
                    'id': 'openstack:d51dd870-d929-4aba-8d75-dcd7555a0c95'
                },
                'eventType': 'activity',
                'eventTime': '2014-08-21T21:04:56.204536+0000',
                'role': u'0e6b990380154a2599ce6b6e91548a68',
                'domain': u'24bdcff1aab8474895dbaac509793de1',
                'inherited_to_projects': False,
                'group': u'c1e22dc67cbd469ea0e33bf428fe597a',
                'action': 'created.role_assignment',
                'outcome': 'success',
                'id': 'openstack:782689dd-f428-4f13-99c7-5c70f94a5ac1'
            }
        """
        note = self._notifications[-1]
        event = note['event']
        if project:
            self.assertEqual(project, event.project)
        if domain:
            self.assertEqual(domain, event.domain)
        if group:
            self.assertEqual(group, event.group)
        elif user:
            self.assertEqual(user, event.user)
        self.assertEqual(role_id, event.role)
        self.assertEqual(inherit, event.inherited_to_projects)

    def test_initiator_id_always_matches_user_id(self):
        # Clear notifications
        while self._notifications:
            self._notifications.pop()

        self.get_scoped_token()
        self.assertEqual(len(self._notifications), 1)
        note = self._notifications.pop()
        initiator = note['initiator']
        self.assertEqual(self.user_id, initiator.id)
        self.assertEqual(self.user_id, initiator.user_id)

    def test_initiator_always_contains_username(self):
        # Clear notifications
        while self._notifications:
            self._notifications.pop()

        self.get_scoped_token()
        self.assertEqual(len(self._notifications), 1)
        note = self._notifications.pop()
        initiator = note['initiator']
        self.assertEqual(self.user['name'], initiator.username)

    def test_v3_authenticate_user_name_and_domain_id(self):
        user_id = self.user_id
        user_name = self.user['name']
        password = self.user['password']
        domain_id = self.domain_id
        data = self.build_authentication_request(username=user_name,
                                                 user_domain_id=domain_id,
                                                 password=password)
        self.post('/auth/tokens', body=data)
        self._assert_last_note(self.ACTION, user_id)

    def test_v3_authenticate_user_id(self):
        user_id = self.user_id
        password = self.user['password']
        data = self.build_authentication_request(user_id=user_id,
                                                 password=password)
        self.post('/auth/tokens', body=data)
        self._assert_last_note(self.ACTION, user_id)

    def test_v3_authenticate_with_invalid_user_id_sends_notification(self):
        user_id = uuid.uuid4().hex
        password = self.user['password']
        data = self.build_authentication_request(user_id=user_id,
                                                 password=password)
        self.post('/auth/tokens', body=data,
                  expected_status=http.client.UNAUTHORIZED)
        note = self._get_last_note()
        initiator = note['initiator']

        # Confirm user-name specific event was emitted.
        self.assertEqual(self.ACTION, note['action'])
        self.assertEqual(user_id, initiator.user_id)
        self.assertTrue(note['send_notification_called'])
        self.assertEqual(cadftaxonomy.OUTCOME_FAILURE, note['event'].outcome)
        self.assertEqual(self.LOCAL_HOST, initiator.host.address)

    def test_v3_authenticate_with_invalid_user_name_sends_notification(self):
        user_name = uuid.uuid4().hex
        password = self.user['password']
        domain_id = self.domain_id
        data = self.build_authentication_request(username=user_name,
                                                 user_domain_id=domain_id,
                                                 password=password)
        self.post('/auth/tokens', body=data,
                  expected_status=http.client.UNAUTHORIZED)
        note = self._get_last_note()
        initiator = note['initiator']

        # Confirm user-name specific event was emitted.
        self.assertEqual(self.ACTION, note['action'])
        self.assertEqual(user_name, initiator.user_name)
        self.assertEqual(domain_id, initiator.domain_id)
        self.assertTrue(note['send_notification_called'])
        self.assertEqual(cadftaxonomy.OUTCOME_FAILURE, note['event'].outcome)
        self.assertEqual(self.LOCAL_HOST, initiator.host.address)

    def test_v3_authenticate_user_name_and_domain_name(self):
        user_id = self.user_id
        user_name = self.user['name']
        password = self.user['password']
        domain_name = self.domain['name']
        data = self.build_authentication_request(username=user_name,
                                                 user_domain_name=domain_name,
                                                 password=password)
        self.post('/auth/tokens', body=data)
        self._assert_last_note(self.ACTION, user_id)

    def _test_role_assignment(self, url, role, project=None, domain=None,
                              user=None, group=None):
        self.put(url)
        action = "%s.%s" % (CREATED_OPERATION, self.ROLE_ASSIGNMENT)
        event_type = '%s.%s.%s' % (notifications.SERVICE,
                                   self.ROLE_ASSIGNMENT, CREATED_OPERATION)
        self._assert_last_note(action, self.user_id, event_type)
        self._assert_event(role, project, domain, user, group)
        self.delete(url)
        action = "%s.%s" % (DELETED_OPERATION, self.ROLE_ASSIGNMENT)
        event_type = '%s.%s.%s' % (notifications.SERVICE,
                                   self.ROLE_ASSIGNMENT, DELETED_OPERATION)
        self._assert_last_note(action, self.user_id, event_type)
        self._assert_event(role, project, domain, user, None)

    def test_user_project_grant(self):
        url = ('/projects/%s/users/%s/roles/%s' %
               (self.project_id, self.user_id, self.role_id))
        self._test_role_assignment(url, self.role_id,
                                   project=self.project_id,
                                   user=self.user_id)

    def test_group_domain_grant(self):
        group_ref = unit.new_group_ref(domain_id=self.domain_id)
        group = PROVIDERS.identity_api.create_group(group_ref)
        PROVIDERS.identity_api.add_user_to_group(self.user_id, group['id'])
        url = ('/domains/%s/groups/%s/roles/%s' %
               (self.domain_id, group['id'], self.role_id))
        self._test_role_assignment(url, self.role_id,
                                   domain=self.domain_id,
                                   group=group['id'])

    def test_add_role_to_user_and_project(self):
        # A notification is sent when add_role_to_user_and_project is called on
        # the assignment manager.

        project_ref = unit.new_project_ref(self.domain_id)
        project = PROVIDERS.resource_api.create_project(
            project_ref['id'], project_ref)
        project_id = project['id']

        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_id, project_id, self.role_id)

        self.assertTrue(self._notifications)
        note = self._notifications[-1]
        self.assertEqual('created.role_assignment', note['action'])
        self.assertTrue(note['send_notification_called'])

        self._assert_event(self.role_id, project=project_id, user=self.user_id)

    def test_remove_role_from_user_and_project(self):
        # A notification is sent when remove_role_from_user_and_project is
        # called on the assignment manager.

        PROVIDERS.assignment_api.remove_role_from_user_and_project(
            self.user_id, self.project_id, self.role_id)

        self.assertTrue(self._notifications)
        note = self._notifications[-1]
        self.assertEqual('deleted.role_assignment', note['action'])
        self.assertTrue(note['send_notification_called'])

        self._assert_event(self.role_id, project=self.project_id,
                           user=self.user_id)


class TestCallbackRegistration(unit.BaseTestCase):
    def setUp(self):
        super(TestCallbackRegistration, self).setUp()
        self.mock_log = mock.Mock()
        # Force the callback logging to occur
        self.mock_log.logger.getEffectiveLevel.return_value = log.DEBUG

    def verify_log_message(self, data):
        """Verify log message.

        Tests that use this are a little brittle because adding more
        logging can break them.

        TODO(dstanek): remove the need for this in a future refactoring

        """
        log_fn = self.mock_log.debug
        self.assertEqual(len(data), log_fn.call_count)
        for datum in data:
            log_fn.assert_any_call(mock.ANY, datum)

    def test_a_function_callback(self):
        def callback(*args, **kwargs):
            pass

        resource_type = 'thing'
        with mock.patch('keystone.notifications.LOG', self.mock_log):
            notifications.register_event_callback(
                CREATED_OPERATION, resource_type, callback)

        callback = 'keystone.tests.unit.common.test_notifications.callback'
        expected_log_data = {
            'callback': callback,
            'event': 'identity.%s.created' % resource_type
        }
        self.verify_log_message([expected_log_data])

    def test_a_method_callback(self):
        class C(object):
            def callback(self, *args, **kwargs):
                pass

        with mock.patch('keystone.notifications.LOG', self.mock_log):
            notifications.register_event_callback(
                CREATED_OPERATION, 'thing', C().callback)

        callback = 'keystone.tests.unit.common.test_notifications.C.callback'
        expected_log_data = {
            'callback': callback,
            'event': 'identity.thing.created'
        }
        self.verify_log_message([expected_log_data])

    def test_a_list_of_callbacks(self):
        def callback(*args, **kwargs):
            pass

        class C(object):
            def callback(self, *args, **kwargs):
                pass

        with mock.patch('keystone.notifications.LOG', self.mock_log):
            notifications.register_event_callback(
                CREATED_OPERATION, 'thing', [callback, C().callback])

        callback_1 = 'keystone.tests.unit.common.test_notifications.callback'
        callback_2 = 'keystone.tests.unit.common.test_notifications.C.callback'
        expected_log_data = [
            {
                'callback': callback_1,
                'event': 'identity.thing.created'
            },
            {
                'callback': callback_2,
                'event': 'identity.thing.created'
            },
        ]
        self.verify_log_message(expected_log_data)

    def test_an_invalid_callback(self):
        self.assertRaises(TypeError,
                          notifications.register_event_callback,
                          (CREATED_OPERATION, 'thing', object()))

    def test_an_invalid_event(self):
        def callback(*args, **kwargs):
            pass

        self.assertRaises(ValueError,
                          notifications.register_event_callback,
                          uuid.uuid4().hex,
                          'thing',
                          callback)


class CADFNotificationsDataTestCase(test_v3.RestfulTestCase):

    def config_overrides(self):
        super(CADFNotificationsDataTestCase, self).config_overrides()
        # NOTE(lbragstad): This is a workaround since oslo.messaging version
        # 9.0.0 had a broken default for transport_url. This makes it so that
        # we are able to use version 9.0.0 in tests because we are supplying
        # an override to use a sane default (rabbit://). The problem is that
        # we can't update the config fixture until we call
        # get_notification_transport since that method registers the
        # configuration options for oslo.messaging, which fails since there
        # isn't a default value for transport_url with version 9.0.0. All the
        # next line is doing is bypassing the broken default logic by supplying
        # a dummy url, which allows the options to be registered. After that,
        # we can actually update the configuration option to override the
        # transport_url option that was just registered before proceeding with
        # the test.
        oslo_messaging.get_notification_transport(CONF, url='rabbit://')
        self.config_fixture.config(
            group='oslo_messaging_notifications', transport_url='rabbit://'
        )

    def test_receive_identityId_from_audit_notification(self):
        observer = None
        resource_type = EXP_RESOURCE_TYPE

        ref = unit.new_service_ref()
        ref['type'] = 'identity'
        PROVIDERS.catalog_api.create_service(ref['id'], ref.copy())

        action = CREATED_OPERATION + '.' + resource_type
        initiator = notifications._get_request_audit_info(self.user_id)
        target = cadfresource.Resource(typeURI=cadftaxonomy.ACCOUNT_USER)
        outcome = 'success'
        event_type = 'identity.authenticate.created'

        with mock.patch.object(notifications._get_notifier(),
                               'info') as mocked:

            notifications._send_audit_notification(action,
                                                   initiator,
                                                   outcome,
                                                   target,
                                                   event_type)

            for mock_args_list in mocked.call_args:
                if len(mock_args_list) != 0:
                    for mock_args in mock_args_list:
                        if 'observer' in mock_args:
                            observer = mock_args['observer']
                            break

        self.assertEqual(ref['id'], observer['id'])
