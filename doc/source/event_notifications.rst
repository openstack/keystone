
..
      Copyright 2013 IBM Corp.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

============================
Keystone Event Notifications
============================

Keystone provides notifications about usage data so that 3rd party applications
can use the data for billing, monitoring, or quota purposes.  This document
describes the current inclusions and exclusions for Keystone usage
notifications.

Notifications for Create/Update/Delete Events
=============================================

A notification is sent when a resource is successfully ``created``,
``updated``, or ``deleted``. The following resource types (where a
``<resource type>`` is always a singular noun) produce notifications:

- ``user``
- ``project`` (i.e. "tenant")

The following message template is used to form a message when an operation on a
resource completes successfully::

    {
        "event_type": "identity.<resource type>.<operation>",
        "message_id": "<message ID>",
        "payload": {
            "resource_info": "<resource ID>"
        },
        "priority": "INFO",
        "publisher_id": "identity.<hostname>",
        "timestamp": "<timestamp>"
    }

Notifications for create, update and delete events are all similar to each
other, where either ``created``, ``updated`` or ``deleted`` is inserted as the
``<operation>`` in the above notification's ``event_type``.

If the operation fails, the notification won't be sent, and no special error
notification will be sent.  Information about the error is handled through
normal exception paths.

Notification Example
^^^^^^^^^^^^^^^^^^^^

This is an example of a notification sent for a newly created user::

    {
        "event_type": "identity.user.created",
        "message_id": "0156ee79-b35f-4cef-ac37-d4a85f231c69",
        "payload": {
            "resource_info": "671da331c47d4e29bb6ea1d270154ec3"
        },
        "priority": "INFO",
        "publisher_id": "identity.host1234",
        "timestamp": "2013-08-29 19:03:45.960280"
    }
