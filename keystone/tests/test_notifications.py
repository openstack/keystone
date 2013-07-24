# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from keystone import notifications
from keystone.openstack.common.notifier import api as notifier_api
from keystone.tests import core


class NotificationsTestCase(core.TestCase):

    def test_send_notification_project_created(self):
        """Test to ensure resource_type is 'project' and operation is
           'created'.
        """

        resource_id = 'created_resource_id'
        self.send_notification_called = False

        def fake_send_notification(resource, resource_type, operation,
                                   host=None):
            exp_resource_type = 'project'
            exp_operation = 'created'
            self.assertEqual(exp_resource_type, resource_type)
            self.assertEqual(exp_operation, operation)
            self.assertEqual(resource_id, resource)
            self.send_notification_called = True

        self.stubs.Set(notifications, '_send_notification',
                       fake_send_notification)
        notifications.notify_created(resource_id, 'project')
        self.assertTrue(self.send_notification_called)

    def test_send_notification_project_updated(self):
        """Test to ensure resource_type is 'project' and operation is
           'updated'.
        """

        resource_id = 'updated_resource_id'
        self.send_notification_called = False

        def fake_send_notification(resource, resource_type, operation,
                                   host=None):
            exp_resource_type = 'project'
            exp_operation = 'updated'
            self.assertEqual(exp_resource_type, resource_type)
            self.assertEqual(exp_operation, operation)
            self.assertEqual(resource_id, resource)
            self.send_notification_called = True

        self.stubs.Set(notifications, '_send_notification',
                       fake_send_notification)
        notifications.notify_updated(resource_id, 'project')
        self.assertTrue(self.send_notification_called)

    def test_send_notification_project_deleted(self):
        """Test to ensure resource_type is 'project' and operation is
           'deleted'.
        """

        resource_id = 'deleted_resource_id'
        self.send_notification_called = False

        def fake_send_notification(resource, resource_type, operation,
                                   host=None):
            exp_resource_type = 'project'
            exp_operation = 'deleted'
            self.assertEqual(exp_resource_type, resource_type)
            self.assertEqual(exp_operation, operation)
            self.assertEqual(resource_id, resource)
            self.send_notification_called = True

        self.stubs.Set(notifications, '_send_notification',
                       fake_send_notification)
        notifications.notify_deleted(resource_id, 'project')
        self.assertTrue(self.send_notification_called)

    def test_send_notification(self):
        """Test the private method _send_notification to ensure event_type,
           payload, and context are built and passed properly.
        """

        resource = 'some_resource_id'
        resource_type = 'project'
        operation = 'created'
        host = None

        # NOTE(ldbragst): Even though notifications._send_notification doesn't
        # contain logic that creates cases, this is suppose to test that
        # context is always empty and that we ensure the resource ID of the
        # resource in the notification is contained in the payload. It was
        # agreed that context should be empty in Keystone's case, which is
        # also noted in the /keystone/notifications.py module. This test
        # ensures and maintains these conditions.
        def fake_notify(context, publisher_id, event_type, priority, payload):
            exp_event_type = 'identity.project.created'
            self.assertEqual(exp_event_type, event_type)
            exp_context = {}
            self.assertEqual(exp_context, context)
            exp_payload = {'resource_info': 'some_resource_id'}
            self.assertEqual(exp_payload, payload)

        self.stubs.Set(notifier_api, 'notify', fake_notify)
        notifications._send_notification(resource, resource_type, operation,
                                         host=host)
