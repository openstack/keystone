
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


Create/Delete/Update User
=========================

One notification is sent when a user
is successfully created, deleted, or updated.

The following message is sent when create user finishes::

 {"event_type": "identity.user.created",
  "message_id": "<message ID>",
  "publisher_id": "identity.<hostname>",
  "timestamp": "<timestamp>",
  "priority": "INFO",
  "payload":
   {"resource_info": "<resource ID>"}}

Notifications for deletes and updates are similar to those for creates, with
``deleted`` or ``updated`` replacing ``created`` in the above notification.

If the operation fails, the notification won't be sent, and no special
error notification will be sent.  Information about the error is handled
through normal exception paths.


Notification Example
====================

This is an example of a notification sent for user creation::

 {"event_type": "identity.user.created",
  "message_id": "0156ee79-b35f-4cef-ac37-d4a85f231c69",
  "publisher_id": "identity.host1234",
  "timestamp": "2013-08-29 19:03:45.960280",
  "priority": "INFO",
  "payload":
   {"resource_info": "671da331c47d4e29bb6ea1d270154ec3"}}
