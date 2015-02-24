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

import logging
import uuid

import mock
from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslotest import mockpatch
from pycadf import cadftaxonomy
from pycadf import cadftype
from pycadf import eventfactory
from pycadf import resource as cadfresource

from keystone import notifications
from keystone.tests import unit
from keystone.tests.unit import test_v3


CONF = cfg.CONF

EXP_RESOURCE_TYPE = uuid.uuid4().hex
CREATED_OPERATION = notifications.ACTIONS.created
UPDATED_OPERATION = notifications.ACTIONS.updated
DELETED_OPERATION = notifications.ACTIONS.deleted
DISABLED_OPERATION = notifications.ACTIONS.disabled


class ArbitraryException(Exception):
    pass


def register_callback(operation, resource_type=EXP_RESOURCE_TYPE):
    """Helper for creating and registering a mock callback.

    """
    callback = mock.Mock(__name__='callback',
                         im_class=mock.Mock(__name__='class'))
    notifications.register_event_callback(operation, resource_type, callback)
    return callback


class AuditNotificationsTestCase(unit.BaseTestCase):
    def setUp(self):
        super(AuditNotificationsTestCase, self).setUp()
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.addCleanup(notifications.clear_subscribers)

    def _test_notification_operation(self, notify_function, operation):
        exp_resource_id = uuid.uuid4().hex
        callback = register_callback(operation)
        notify_function(EXP_RESOURCE_TYPE, exp_resource_id)
        callback.assert_called_once_with('identity', EXP_RESOURCE_TYPE,
                                         operation,
                                         {'resource_info': exp_resource_id})
        self.config_fixture.config(notification_format='cadf')
        with mock.patch(
                'keystone.notifications._create_cadf_payload') as cadf_notify:
            notify_function(EXP_RESOURCE_TYPE, exp_resource_id)
            initiator = None
            cadf_notify.assert_called_once_with(
                operation, EXP_RESOURCE_TYPE, exp_resource_id,
                notifications.taxonomy.OUTCOME_SUCCESS, initiator)
            notify_function(EXP_RESOURCE_TYPE, exp_resource_id, public=False)
            cadf_notify.assert_called_once_with(
                operation, EXP_RESOURCE_TYPE, exp_resource_id,
                notifications.taxonomy.OUTCOME_SUCCESS, initiator)

    def test_resource_created_notification(self):
        self._test_notification_operation(notifications.Audit.created,
                                          CREATED_OPERATION)

    def test_resource_updated_notification(self):
        self._test_notification_operation(notifications.Audit.updated,
                                          UPDATED_OPERATION)

    def test_resource_deleted_notification(self):
        self._test_notification_operation(notifications.Audit.deleted,
                                          DELETED_OPERATION)

    def test_resource_disabled_notification(self):
        self._test_notification_operation(notifications.Audit.disabled,
                                          DISABLED_OPERATION)


class NotificationsWrapperTestCase(unit.BaseTestCase):
    def create_fake_ref(self):
        resource_id = uuid.uuid4().hex
        return resource_id, {
            'id': resource_id,
            'key': uuid.uuid4().hex
        }

    @notifications.created(EXP_RESOURCE_TYPE)
    def create_resource(self, resource_id, data):
        return data

    def test_resource_created_notification(self):
        exp_resource_id, data = self.create_fake_ref()
        callback = register_callback(CREATED_OPERATION)

        self.create_resource(exp_resource_id, data)
        callback.assert_called_with('identity', EXP_RESOURCE_TYPE,
                                    CREATED_OPERATION,
                                    {'resource_info': exp_resource_id})

    @notifications.updated(EXP_RESOURCE_TYPE)
    def update_resource(self, resource_id, data):
        return data

    def test_resource_updated_notification(self):
        exp_resource_id, data = self.create_fake_ref()
        callback = register_callback(UPDATED_OPERATION)

        self.update_resource(exp_resource_id, data)
        callback.assert_called_with('identity', EXP_RESOURCE_TYPE,
                                    UPDATED_OPERATION,
                                    {'resource_info': exp_resource_id})

    @notifications.deleted(EXP_RESOURCE_TYPE)
    def delete_resource(self, resource_id):
        pass

    def test_resource_deleted_notification(self):
        exp_resource_id = uuid.uuid4().hex
        callback = register_callback(DELETED_OPERATION)

        self.delete_resource(exp_resource_id)
        callback.assert_called_with('identity', EXP_RESOURCE_TYPE,
                                    DELETED_OPERATION,
                                    {'resource_info': exp_resource_id})

    @notifications.created(EXP_RESOURCE_TYPE)
    def create_exception(self, resource_id):
        raise ArbitraryException()

    def test_create_exception_without_notification(self):
        callback = register_callback(CREATED_OPERATION)
        self.assertRaises(
            ArbitraryException, self.create_exception, uuid.uuid4().hex)
        self.assertFalse(callback.called)

    @notifications.created(EXP_RESOURCE_TYPE)
    def update_exception(self, resource_id):
        raise ArbitraryException()

    def test_update_exception_without_notification(self):
        callback = register_callback(UPDATED_OPERATION)
        self.assertRaises(
            ArbitraryException, self.update_exception, uuid.uuid4().hex)
        self.assertFalse(callback.called)

    @notifications.deleted(EXP_RESOURCE_TYPE)
    def delete_exception(self, resource_id):
        raise ArbitraryException()

    def test_delete_exception_without_notification(self):
        callback = register_callback(DELETED_OPERATION)
        self.assertRaises(
            ArbitraryException, self.delete_exception, uuid.uuid4().hex)
        self.assertFalse(callback.called)


class NotificationsTestCase(unit.BaseTestCase):

    def test_send_notification(self):
        """Test the private method _send_notification to ensure event_type,
           payload, and context are built and passed properly.
        """
        resource = uuid.uuid4().hex
        resource_type = EXP_RESOURCE_TYPE
        operation = CREATED_OPERATION

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
            {'resource_info': resource},  # payload
            'INFO',  # priority is always INFO...
        ]

        with mock.patch.object(notifications._get_notifier(),
                               '_notify') as mocked:
            notifications._send_notification(operation, resource_type,
                                             resource)
            mocked.assert_called_once_with(*expected_args)


class BaseNotificationTest(test_v3.RestfulTestCase):

    def setUp(self):
        super(BaseNotificationTest, self).setUp()

        self._notifications = []
        self._audits = []

        def fake_notify(operation, resource_type, resource_id,
                        public=True):
            note = {
                'resource_id': resource_id,
                'operation': operation,
                'resource_type': resource_type,
                'send_notification_called': True,
                'public': public}
            self._notifications.append(note)

        self.useFixture(mockpatch.PatchObject(
            notifications, '_send_notification', fake_notify))

        def fake_audit(action, initiator, outcome, target,
                       event_type, **kwargs):
            service_security = cadftaxonomy.SERVICE_SECURITY

            event = eventfactory.EventFactory().new_event(
                eventType=cadftype.EVENTTYPE_ACTIVITY,
                outcome=outcome,
                action=action,
                initiator=initiator,
                target=target,
                observer=cadfresource.Resource(typeURI=service_security))

            for key, value in kwargs.items():
                setattr(event, key, value)

            audit = {
                'payload': event.as_dict(),
                'event_type': event_type,
                'send_notification_called': True}
            self._audits.append(audit)

        self.useFixture(mockpatch.PatchObject(
            notifications, '_send_audit_notification', fake_audit))

    def _assert_last_note(self, resource_id, operation, resource_type):
        # NOTE(stevemar): If 'basic' format is not used, then simply
        # return since this assertion is not valid.
        if CONF.notification_format != 'basic':
            return
        self.assertTrue(len(self._notifications) > 0)
        note = self._notifications[-1]
        self.assertEqual(note['operation'], operation)
        self.assertEqual(note['resource_id'], resource_id)
        self.assertEqual(note['resource_type'], resource_type)
        self.assertTrue(note['send_notification_called'])

    def _assert_last_audit(self, resource_id, operation, resource_type,
                           target_uri):
        # NOTE(stevemar): If 'cadf' format is not used, then simply
        # return since this assertion is not valid.
        if CONF.notification_format != 'cadf':
            return
        self.assertTrue(len(self._audits) > 0)
        audit = self._audits[-1]
        payload = audit['payload']
        self.assertEqual(resource_id, payload['resource_info'])
        action = '%s.%s' % (operation, resource_type)
        self.assertEqual(action, payload['action'])
        self.assertEqual(target_uri, payload['target']['typeURI'])
        self.assertEqual(resource_id, payload['target']['id'])
        event_type = '%s.%s.%s' % ('identity', resource_type, operation)
        self.assertEqual(event_type, audit['event_type'])
        self.assertTrue(audit['send_notification_called'])

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
            if expected == note:
                break
        else:
            self.fail("Notification not sent.")


class NotificationsForEntities(BaseNotificationTest):

    def test_create_group(self):
        group_ref = self.new_group_ref(domain_id=self.domain_id)
        group_ref = self.identity_api.create_group(group_ref)
        self._assert_last_note(group_ref['id'], CREATED_OPERATION, 'group')
        self._assert_last_audit(group_ref['id'], CREATED_OPERATION, 'group',
                                cadftaxonomy.SECURITY_GROUP)

    def test_create_project(self):
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.resource_api.create_project(project_ref['id'], project_ref)
        self._assert_last_note(
            project_ref['id'], CREATED_OPERATION, 'project')
        self._assert_last_audit(project_ref['id'], CREATED_OPERATION,
                                'project', cadftaxonomy.SECURITY_PROJECT)

    def test_create_role(self):
        role_ref = self.new_role_ref()
        self.role_api.create_role(role_ref['id'], role_ref)
        self._assert_last_note(role_ref['id'], CREATED_OPERATION, 'role')
        self._assert_last_audit(role_ref['id'], CREATED_OPERATION, 'role',
                                cadftaxonomy.SECURITY_ROLE)

    def test_create_user(self):
        user_ref = self.new_user_ref(domain_id=self.domain_id)
        user_ref = self.identity_api.create_user(user_ref)
        self._assert_last_note(user_ref['id'], CREATED_OPERATION, 'user')
        self._assert_last_audit(user_ref['id'], CREATED_OPERATION, 'user',
                                cadftaxonomy.SECURITY_ACCOUNT_USER)

    def test_create_trust(self):
        trustor = self.new_user_ref(domain_id=self.domain_id)
        trustor = self.identity_api.create_user(trustor)
        trustee = self.new_user_ref(domain_id=self.domain_id)
        trustee = self.identity_api.create_user(trustee)
        role_ref = self.new_role_ref()
        self.role_api.create_role(role_ref['id'], role_ref)
        trust_ref = self.new_trust_ref(trustor['id'],
                                       trustee['id'])
        self.trust_api.create_trust(trust_ref['id'],
                                    trust_ref,
                                    [role_ref])
        self._assert_last_note(
            trust_ref['id'], CREATED_OPERATION, 'OS-TRUST:trust')
        self._assert_last_audit(trust_ref['id'], CREATED_OPERATION,
                                'OS-TRUST:trust', cadftaxonomy.SECURITY_TRUST)

    def test_delete_group(self):
        group_ref = self.new_group_ref(domain_id=self.domain_id)
        group_ref = self.identity_api.create_group(group_ref)
        self.identity_api.delete_group(group_ref['id'])
        self._assert_last_note(group_ref['id'], DELETED_OPERATION, 'group')
        self._assert_last_audit(group_ref['id'], DELETED_OPERATION, 'group',
                                cadftaxonomy.SECURITY_GROUP)

    def test_delete_project(self):
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.resource_api.create_project(project_ref['id'], project_ref)
        self.resource_api.delete_project(project_ref['id'])
        self._assert_last_note(
            project_ref['id'], DELETED_OPERATION, 'project')
        self._assert_last_audit(project_ref['id'], DELETED_OPERATION,
                                'project', cadftaxonomy.SECURITY_PROJECT)

    def test_delete_role(self):
        role_ref = self.new_role_ref()
        self.role_api.create_role(role_ref['id'], role_ref)
        self.role_api.delete_role(role_ref['id'])
        self._assert_last_note(role_ref['id'], DELETED_OPERATION, 'role')
        self._assert_last_audit(role_ref['id'], DELETED_OPERATION, 'role',
                                cadftaxonomy.SECURITY_ROLE)

    def test_delete_user(self):
        user_ref = self.new_user_ref(domain_id=self.domain_id)
        user_ref = self.identity_api.create_user(user_ref)
        self.identity_api.delete_user(user_ref['id'])
        self._assert_last_note(user_ref['id'], DELETED_OPERATION, 'user')
        self._assert_last_audit(user_ref['id'], DELETED_OPERATION, 'user',
                                cadftaxonomy.SECURITY_ACCOUNT_USER)

    def test_create_domain(self):
        domain_ref = self.new_domain_ref()
        self.resource_api.create_domain(domain_ref['id'], domain_ref)
        self._assert_last_note(domain_ref['id'], CREATED_OPERATION, 'domain')
        self._assert_last_audit(domain_ref['id'], CREATED_OPERATION, 'domain',
                                cadftaxonomy.SECURITY_DOMAIN)

    def test_update_domain(self):
        domain_ref = self.new_domain_ref()
        self.resource_api.create_domain(domain_ref['id'], domain_ref)
        domain_ref['description'] = uuid.uuid4().hex
        self.resource_api.update_domain(domain_ref['id'], domain_ref)
        self._assert_last_note(domain_ref['id'], UPDATED_OPERATION, 'domain')
        self._assert_last_audit(domain_ref['id'], UPDATED_OPERATION, 'domain',
                                cadftaxonomy.SECURITY_DOMAIN)

    def test_delete_domain(self):
        domain_ref = self.new_domain_ref()
        self.resource_api.create_domain(domain_ref['id'], domain_ref)
        domain_ref['enabled'] = False
        self.resource_api.update_domain(domain_ref['id'], domain_ref)
        self.resource_api.delete_domain(domain_ref['id'])
        self._assert_last_note(domain_ref['id'], DELETED_OPERATION, 'domain')
        self._assert_last_audit(domain_ref['id'], DELETED_OPERATION, 'domain',
                                cadftaxonomy.SECURITY_DOMAIN)

    def test_delete_trust(self):
        trustor = self.new_user_ref(domain_id=self.domain_id)
        trustor = self.identity_api.create_user(trustor)
        trustee = self.new_user_ref(domain_id=self.domain_id)
        trustee = self.identity_api.create_user(trustee)
        role_ref = self.new_role_ref()
        trust_ref = self.new_trust_ref(trustor['id'], trustee['id'])
        self.trust_api.create_trust(trust_ref['id'],
                                    trust_ref,
                                    [role_ref])
        self.trust_api.delete_trust(trust_ref['id'])
        self._assert_last_note(
            trust_ref['id'], DELETED_OPERATION, 'OS-TRUST:trust')
        self._assert_last_audit(trust_ref['id'], DELETED_OPERATION,
                                'OS-TRUST:trust', cadftaxonomy.SECURITY_TRUST)

    def test_create_endpoint(self):
        endpoint_ref = self.new_endpoint_ref(service_id=self.service_id)
        self.catalog_api.create_endpoint(endpoint_ref['id'], endpoint_ref)
        self._assert_notify_sent(endpoint_ref['id'], CREATED_OPERATION,
                                 'endpoint')
        self._assert_last_audit(endpoint_ref['id'], CREATED_OPERATION,
                                'endpoint', cadftaxonomy.SECURITY_ENDPOINT)

    def test_update_endpoint(self):
        endpoint_ref = self.new_endpoint_ref(service_id=self.service_id)
        self.catalog_api.create_endpoint(endpoint_ref['id'], endpoint_ref)
        self.catalog_api.update_endpoint(endpoint_ref['id'], endpoint_ref)
        self._assert_notify_sent(endpoint_ref['id'], UPDATED_OPERATION,
                                 'endpoint')
        self._assert_last_audit(endpoint_ref['id'], UPDATED_OPERATION,
                                'endpoint', cadftaxonomy.SECURITY_ENDPOINT)

    def test_delete_endpoint(self):
        endpoint_ref = self.new_endpoint_ref(service_id=self.service_id)
        self.catalog_api.create_endpoint(endpoint_ref['id'], endpoint_ref)
        self.catalog_api.delete_endpoint(endpoint_ref['id'])
        self._assert_notify_sent(endpoint_ref['id'], DELETED_OPERATION,
                                 'endpoint')
        self._assert_last_audit(endpoint_ref['id'], DELETED_OPERATION,
                                'endpoint', cadftaxonomy.SECURITY_ENDPOINT)

    def test_create_service(self):
        service_ref = self.new_service_ref()
        self.catalog_api.create_service(service_ref['id'], service_ref)
        self._assert_notify_sent(service_ref['id'], CREATED_OPERATION,
                                 'service')
        self._assert_last_audit(service_ref['id'], CREATED_OPERATION,
                                'service', cadftaxonomy.SECURITY_SERVICE)

    def test_update_service(self):
        service_ref = self.new_service_ref()
        self.catalog_api.create_service(service_ref['id'], service_ref)
        self.catalog_api.update_service(service_ref['id'], service_ref)
        self._assert_notify_sent(service_ref['id'], UPDATED_OPERATION,
                                 'service')
        self._assert_last_audit(service_ref['id'], UPDATED_OPERATION,
                                'service', cadftaxonomy.SECURITY_SERVICE)

    def test_delete_service(self):
        service_ref = self.new_service_ref()
        self.catalog_api.create_service(service_ref['id'], service_ref)
        self.catalog_api.delete_service(service_ref['id'])
        self._assert_notify_sent(service_ref['id'], DELETED_OPERATION,
                                 'service')
        self._assert_last_audit(service_ref['id'], DELETED_OPERATION,
                                'service', cadftaxonomy.SECURITY_SERVICE)

    def test_create_region(self):
        region_ref = self.new_region_ref()
        self.catalog_api.create_region(region_ref)
        self._assert_notify_sent(region_ref['id'], CREATED_OPERATION,
                                 'region')
        self._assert_last_audit(region_ref['id'], CREATED_OPERATION,
                                'region', cadftaxonomy.SECURITY_REGION)

    def test_update_region(self):
        region_ref = self.new_region_ref()
        self.catalog_api.create_region(region_ref)
        self.catalog_api.update_region(region_ref['id'], region_ref)
        self._assert_notify_sent(region_ref['id'], UPDATED_OPERATION,
                                 'region')
        self._assert_last_audit(region_ref['id'], UPDATED_OPERATION,
                                'region', cadftaxonomy.SECURITY_REGION)

    def test_delete_region(self):
        region_ref = self.new_region_ref()
        self.catalog_api.create_region(region_ref)
        self.catalog_api.delete_region(region_ref['id'])
        self._assert_notify_sent(region_ref['id'], DELETED_OPERATION,
                                 'region')
        self._assert_last_audit(region_ref['id'], DELETED_OPERATION,
                                'region', cadftaxonomy.SECURITY_REGION)

    def test_create_policy(self):
        policy_ref = self.new_policy_ref()
        self.policy_api.create_policy(policy_ref['id'], policy_ref)
        self._assert_notify_sent(policy_ref['id'], CREATED_OPERATION,
                                 'policy')
        self._assert_last_audit(policy_ref['id'], CREATED_OPERATION,
                                'policy', cadftaxonomy.SECURITY_POLICY)

    def test_update_policy(self):
        policy_ref = self.new_policy_ref()
        self.policy_api.create_policy(policy_ref['id'], policy_ref)
        self.policy_api.update_policy(policy_ref['id'], policy_ref)
        self._assert_notify_sent(policy_ref['id'], UPDATED_OPERATION,
                                 'policy')
        self._assert_last_audit(policy_ref['id'], UPDATED_OPERATION,
                                'policy', cadftaxonomy.SECURITY_POLICY)

    def test_delete_policy(self):
        policy_ref = self.new_policy_ref()
        self.policy_api.create_policy(policy_ref['id'], policy_ref)
        self.policy_api.delete_policy(policy_ref['id'])
        self._assert_notify_sent(policy_ref['id'], DELETED_OPERATION,
                                 'policy')
        self._assert_last_audit(policy_ref['id'], DELETED_OPERATION,
                                'policy', cadftaxonomy.SECURITY_POLICY)

    def test_disable_domain(self):
        domain_ref = self.new_domain_ref()
        self.resource_api.create_domain(domain_ref['id'], domain_ref)
        domain_ref['enabled'] = False
        self.resource_api.update_domain(domain_ref['id'], domain_ref)
        self._assert_notify_sent(domain_ref['id'], 'disabled', 'domain',
                                 public=False)

    def test_disable_of_disabled_domain_does_not_notify(self):
        domain_ref = self.new_domain_ref()
        domain_ref['enabled'] = False
        self.resource_api.create_domain(domain_ref['id'], domain_ref)
        # The domain_ref above is not changed during the create process. We
        # can use the same ref to perform the update.
        self.resource_api.update_domain(domain_ref['id'], domain_ref)
        self._assert_notify_not_sent(domain_ref['id'], 'disabled', 'domain',
                                     public=False)

    def test_update_group(self):
        group_ref = self.new_group_ref(domain_id=self.domain_id)
        group_ref = self.identity_api.create_group(group_ref)
        self.identity_api.update_group(group_ref['id'], group_ref)
        self._assert_last_note(group_ref['id'], UPDATED_OPERATION, 'group')
        self._assert_last_audit(group_ref['id'], UPDATED_OPERATION, 'group',
                                cadftaxonomy.SECURITY_GROUP)

    def test_update_project(self):
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.resource_api.create_project(project_ref['id'], project_ref)
        self.resource_api.update_project(project_ref['id'], project_ref)
        self._assert_notify_sent(
            project_ref['id'], UPDATED_OPERATION, 'project', public=True)
        self._assert_last_audit(project_ref['id'], UPDATED_OPERATION,
                                'project', cadftaxonomy.SECURITY_PROJECT)

    def test_disable_project(self):
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.resource_api.create_project(project_ref['id'], project_ref)
        project_ref['enabled'] = False
        self.resource_api.update_project(project_ref['id'], project_ref)
        self._assert_notify_sent(project_ref['id'], 'disabled', 'project',
                                 public=False)

    def test_disable_of_disabled_project_does_not_notify(self):
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        project_ref['enabled'] = False
        self.resource_api.create_project(project_ref['id'], project_ref)
        # The project_ref above is not changed during the create process. We
        # can use the same ref to perform the update.
        self.resource_api.update_project(project_ref['id'], project_ref)
        self._assert_notify_not_sent(project_ref['id'], 'disabled', 'project',
                                     public=False)

    def test_update_project_does_not_send_disable(self):
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.resource_api.create_project(project_ref['id'], project_ref)
        project_ref['enabled'] = True
        self.resource_api.update_project(project_ref['id'], project_ref)
        self._assert_last_note(
            project_ref['id'], UPDATED_OPERATION, 'project')
        self._assert_notify_not_sent(project_ref['id'], 'disabled', 'project')

    def test_update_role(self):
        role_ref = self.new_role_ref()
        self.role_api.create_role(role_ref['id'], role_ref)
        self.role_api.update_role(role_ref['id'], role_ref)
        self._assert_last_note(role_ref['id'], UPDATED_OPERATION, 'role')
        self._assert_last_audit(role_ref['id'], UPDATED_OPERATION, 'role',
                                cadftaxonomy.SECURITY_ROLE)

    def test_update_user(self):
        user_ref = self.new_user_ref(domain_id=self.domain_id)
        user_ref = self.identity_api.create_user(user_ref)
        self.identity_api.update_user(user_ref['id'], user_ref)
        self._assert_last_note(user_ref['id'], UPDATED_OPERATION, 'user')
        self._assert_last_audit(user_ref['id'], UPDATED_OPERATION, 'user',
                                cadftaxonomy.SECURITY_ACCOUNT_USER)

    def test_config_option_no_events(self):
        self.config_fixture.config(notification_format='basic')
        role_ref = self.new_role_ref()
        self.role_api.create_role(role_ref['id'], role_ref)
        # The regular notifications will still be emitted, since they are
        # used for callback handling.
        self._assert_last_note(role_ref['id'], CREATED_OPERATION, 'role')
        # No audit event should have occurred
        self.assertEqual(0, len(self._audits))


class CADFNotificationsForEntities(NotificationsForEntities):

    def setUp(self):
        super(CADFNotificationsForEntities, self).setUp()
        self.config_fixture.config(notification_format='cadf')

    def test_initiator_data_is_set(self):
        ref = self.new_domain_ref()
        resp = self.post('/domains', body={'domain': ref})
        resource_id = resp.result.get('domain').get('id')
        self._assert_last_audit(resource_id, CREATED_OPERATION, 'domain',
                                cadftaxonomy.SECURITY_DOMAIN)
        self.assertTrue(len(self._audits) > 0)
        audit = self._audits[-1]
        payload = audit['payload']
        self.assertEqual(self.user_id, payload['initiator']['id'])
        self.assertEqual(self.project_id, payload['initiator']['project_id'])


class TestEventCallbacks(test_v3.RestfulTestCase):

    def setUp(self):
        super(TestEventCallbacks, self).setUp()
        self.has_been_called = False

    def _project_deleted_callback(self, service, resource_type, operation,
                                  payload):
        self.has_been_called = True

    def _project_created_callback(self, service, resource_type, operation,
                                  payload):
        self.has_been_called = True

    def test_notification_received(self):
        callback = register_callback(CREATED_OPERATION, 'project')
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.resource_api.create_project(project_ref['id'], project_ref)
        self.assertTrue(callback.called)

    def test_notification_method_not_callable(self):
        fake_method = None
        self.assertRaises(TypeError,
                          notifications.register_event_callback,
                          UPDATED_OPERATION,
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
        notifications.register_event_callback(DELETED_OPERATION,
                                              uuid.uuid4().hex,
                                              self._project_deleted_callback)
        resource_type = uuid.uuid4().hex
        notifications.register_event_callback(DELETED_OPERATION,
                                              resource_type,
                                              self._project_deleted_callback)

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
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.resource_api.create_project(project_ref['id'], project_ref)
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
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.resource_api.create_project(project_ref['id'], project_ref)
        self.assertItemsEqual(['cb1', 'cb0'], callback_called)

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

            def callback(self, *args):
                pass

        # TODO(dstanek): it would probably be nice to fail early using
        # something like:
        #     self.assertRaises(TypeError, Foo)
        Foo()
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        self.assertRaises(TypeError, self.resource_api.create_project,
                          project_ref['id'], project_ref)


class CadfNotificationsWrapperTestCase(test_v3.RestfulTestCase):

    LOCAL_HOST = 'localhost'
    ACTION = 'authenticate'
    ROLE_ASSIGNMENT = 'role_assignment'

    def setUp(self):
        super(CadfNotificationsWrapperTestCase, self).setUp()
        self._notifications = []

        def fake_notify(action, initiator, outcome, target,
                        event_type, **kwargs):
            service_security = cadftaxonomy.SERVICE_SECURITY

            event = eventfactory.EventFactory().new_event(
                eventType=cadftype.EVENTTYPE_ACTIVITY,
                outcome=outcome,
                action=action,
                initiator=initiator,
                target=target,
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

        self.useFixture(mockpatch.PatchObject(
            notifications, '_send_audit_notification', fake_notify))

    def _assert_last_note(self, action, user_id, event_type=None):
        self.assertTrue(self._notifications)
        note = self._notifications[-1]
        self.assertEqual(note['action'], action)
        initiator = note['initiator']
        self.assertEqual(initiator.id, user_id)
        self.assertEqual(initiator.host.address, self.LOCAL_HOST)
        self.assertTrue(note['send_notification_called'])
        if event_type:
            self.assertEqual(note['event_type'], event_type)

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
                    'name': u'bccc2d9bfc2a46fd9e33bcf82f0b5c21'
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
        group_ref = self.new_group_ref(domain_id=self.domain_id)
        group = self.identity_api.create_group(group_ref)
        self.identity_api.add_user_to_group(self.user_id, group['id'])
        url = ('/domains/%s/groups/%s/roles/%s' %
               (self.domain_id, group['id'], self.role_id))
        self._test_role_assignment(url, self.role_id,
                                   domain=self.domain_id,
                                   user=self.user_id,
                                   group=group['id'])

    def test_add_role_to_user_and_project(self):
        # A notification is sent when add_role_to_user_and_project is called on
        # the assignment manager.

        project_ref = self.new_project_ref(self.domain_id)
        project = self.resource_api.create_project(
            project_ref['id'], project_ref)
        tenant_id = project['id']

        self.assignment_api.add_role_to_user_and_project(
            self.user_id, tenant_id, self.role_id)

        self.assertTrue(self._notifications)
        note = self._notifications[-1]
        self.assertEqual(note['action'], 'created.role_assignment')
        self.assertTrue(note['send_notification_called'])

        self._assert_event(self.role_id, project=tenant_id, user=self.user_id)

    def test_remove_role_from_user_and_project(self):
        # A notification is sent when remove_role_from_user_and_project is
        # called on the assignment manager.

        self.assignment_api.remove_role_from_user_and_project(
            self.user_id, self.project_id, self.role_id)

        self.assertTrue(self._notifications)
        note = self._notifications[-1]
        self.assertEqual(note['action'], 'deleted.role_assignment')
        self.assertTrue(note['send_notification_called'])

        self._assert_event(self.role_id, project=self.project_id,
                           user=self.user_id)


class TestCallbackRegistration(unit.BaseTestCase):
    def setUp(self):
        super(TestCallbackRegistration, self).setUp()
        self.mock_log = mock.Mock()
        # Force the callback logging to occur
        self.mock_log.logger.getEffectiveLevel.return_value = logging.DEBUG

    def verify_log_message(self, data):
        """Tests that use this are a little brittle because adding more
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
