
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
``<resource type>`` is always a singular noun) produce notifications. For
resource types that are immutable, like trusts, notifications are only sent
on creation and deletion of that resource. Resource types that should be
immutable from a Keystone perspective will not support update operations:

- ``group``
- ``project`` (i.e. "tenant")
- ``role``
- ``user``
- ``trust`` (immutable resource - no ``updated`` notification)
- ``region``
- ``endpoint``
- ``service``
- ``policy``

The following message template is used to form a message when an operation on a
resource completes successfully:

.. code-block:: javascript

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

The ``priority`` of the notification being sent is not configurable through
the Keystone configuration file. This value is defaulted to INFO for all
notifications sent in Keystone's case.

If the operation fails, the notification won't be sent, and no special error
notification will be sent.  Information about the error is handled through
normal exception paths.

Notification Example
--------------------

This is an example of a notification sent for a newly created user:

.. code-block:: javascript

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

Recommendations for consumers
-----------------------------

One of the most important notifications that Keystone emits is for project
deletions (``event_type`` = ``identity.project.deleted``). This event should
indicate to the rest of OpenStack that all resources (such as virtual machines)
associated with the project should be deleted.

Projects can also have update events (``event_type`` =
``identity.project.updated``), wherein the project has been disabled. Keystone
ensures this has an immediate impact on the accessibility of the project's
resources by revoking tokens with authorization on the project, but should
**not** have a direct impact on the projects resources (in other words, virtual
machines should **not** be deleted).

Auditing with CADF
==================

Keystone has begun to add audit notification support for authentication and
for authorization events using the `DMTF Cloud Auditing Data Federation (CADF)
Open Standard. <http://docs.openstack.org/developer/pycadf/>`_

Note that the CADF format is used in place of the traditional notification
format mentioned above.

This standard provides auditing capabilities for compliance with security,
operational, and business processes and supports normalized and categorized
event data for federation and aggregation.

The following CADF example illustrates a Keystone event record whereby the
user has failed to authenticate:

.. code-block:: javascript

    {
        "event_type": "identity.authenticate",
        "message_id": "1371a590-d5fd-448f-b3bb-a14dead6f4cb",
        "payload": {
            "typeURI": "http://schemas.dmtf.org/cloud/audit/1.0/event",
            "initiator": {
                "typeURI": "service/security/account/user",
                "host": {
                    "agent": "curl/7.22.0(x86_64-pc-linux-gnu)",
                    "address": "127.0.0.1"
                },
                "id": "openstack:5ee22124-6f41-4d23-a9f7-862c13a53a66",
                "name": "joeuser"
            },
            "target": {
                "typeURI": "service/security/account/user",
                "id": "openstack:1c2fc591-facb-4479-a327-520dade1ea15"
            },
            "observer": {
                "typeURI": "service/security",
                "id": "openstack:3d4a50a9-2b59-438b-bf19-c231f9c7625a"
            },
            "eventType": "activity",
            "eventTime": "2014-02-14T01:20:47.932842+00:00",
            "action": "authenticate",
            "outcome": "failure",
            "id": "openstack:f5352d7b-bee6-4c22-8213-450e7b646e9f"
        },
        "priority": "INFO",
        "publisher_id": "identity.host1234",
        "timestamp": "2014-02-14T01:20:47.932842"
    }

The following CADF example illustrates a Keystone event record whereby the
user has assigned a role to a group on a specific project:

.. code-block:: javascript

    {
        "event_type": "identity.created.role_assignment",
        "message_id": "a5901371-d5fd-b3bb-448f-a14dead6f4cb",
        "payload": {
            "typeURI": "http://schemas.dmtf.org/cloud/audit/1.0/event",
            "initiator": {
                "typeURI": "service/security/account/user",
                "host": {
                    "agent": "curl/7.22.0(x86_64-pc-linux-gnu)",
                    "address": "127.0.0.1"
                },
                "id": "openstack:f6eac6ad-ef02-4469-a40f-c1c9151d3813",
                "name": "7bdae1f0c3754e9f8af3794016b88093"
            },
            "target": {
                "typeURI": "service/security/account/user",
                "id": "openstack:1c2fc591-facb-4479-a327-520dade1ea15"
            },
            "observer": {
                "typeURI": "service/security",
                "id": "openstack:3d4a50a9-2b59-438b-bf19-c231f9c7625a"
            },
            "eventType": "activity",
            "eventTime": "2014-08-20T01:20:47.932842+00:00",
            "role": "0e6b990380154a2599ce6b6e91548a68",
            "project": "24bdcff1aab8474895dbaac509793de1",
            "inherited_to_projects": false,
            "group": "c1e22dc67cbd469ea0e33bf428fe597a",
            "action": "created.role_assignment",
            "outcome": "success",
            "id": "openstack:f5352d7b-bee6-4c22-8213-450e7b646e9f"
        },
        "priority": "INFO",
        "publisher_id": "identity.host1234",
        "timestamp": "2014-08-20T01:20:47.932842"
    }
