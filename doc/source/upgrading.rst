..
    Licensed under the Apache License, Version 2.0 (the "License"); you may not
    use this file except in compliance with the License. You may obtain a copy
    of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
    License for the specific language governing permissions and limitations
    under the License.

==================
Upgrading Keystone
==================

As of the Newton release, keystone supports two different approaches to
upgrading across releases. The traditional approach requires a significant
outage to be scheduled for the entire duration of the upgrade process. The more
modern approach results in zero downtime, but is more complicated due to a
longer upgrade procedure.

.. NOTE::

    The details of these steps are entirely dependent on the details of your
    specific deployment, such as your chosen application server and database
    management system. Use it only as a guide when implementing your own
    upgrade process.

Before you begin
----------------

Plan your upgrade:

* Read and ensure you understand the `release notes
  http://docs.openstack.org/releasenotes/keystone/`_ for the next release.

* Resolve any outstanding deprecation warnings in your logs. Some deprecation
  cycles are as short as a single release, so it's possible to break a
  deployment if you leave *any* outstanding warnings. It might be a good idea
  to re-read the release notes for the previous release (or two!).

* Prepare your new configuration files, including ``keystone.conf``,
  ``logging.conf``, ``policy.json``, ``keystone-paste.ini``, and anything else
  in ``/etc/keystone/``, by customizing the corresponding files from the next
  release.

Upgrading with downtime
-----------------------

This is a high-level description of our upgrade strategy built around
``keystone-manage db_sync``. It assumes that you are willing to have downtime
of your control plane during the upgrade process and presents minimal risk.
With keystone unavailable, no other OpenStack services will be able to
authenticate requests, effectively preventing the rest of the control plane
from functioning normally.

#. Stop all keystone processes. Otherwise, you'll risk multiple releases of
   keystone trying to write to the database at the same time, which may result
   in data being inconsistently written and read.

#. Make a backup of your database. Keystone does not support downgrading the
   database, so restoring from a full backup is your only option for recovery
   in the event of an upgrade failure.

#. Upgrade all keystone nodes to the next release.

#. Update your configuration files (``/etc/keystone/``) with those
   corresponding from the latest release.

#. Run ``keystone-manage db_sync`` from any single node to upgrade both the
   database schema and run any corresponding database migrations.

#. (*New in Newton*) Run ``keystone-manage doctor`` to diagnose symptoms of
   common deployment issues and receive instructions for resolving them.

#. Start all keystone processes.

Upgrading without downtime
--------------------------

This is a high-level description of our upgrade strategy built around
additional options in ``keystone-manage db_sync``. Although it is much more
complex than the upgrade process described above, it assumes that you are not
willing to have downtime of your control plane during the upgrade process. With
this upgrade process, end users will still be able to authenticate to receive
tokens normally, and other OpenStack services will still be able to
authenticate requests normally.

#. Make a backup of your database. Keystone does not support downgrading the
   database, so restoring from a full backup is your only option for recovery
   in the event of an upgrade failure.

#. Stop the keystone processes on the first node (or really, any arbitrary
   node). This node will serve to orchestrate database upgrades.

#. Upgrade your first node to the next release, but do not start any keystone
   processes.

#. Update your configuration files on the first node (``/etc/keystone/``) with
   those corresponding to the latest release.

#. (*New in Newton*) Run ``keystone-manage doctor`` on the first node to
   diagnose symptoms of common deployment issues and receive instructions for
   resolving them.

#. Run ``keystone-manage db_sync --expand`` on the first node to expand the
   database schema to a superset of what both the previous and next release can
   utilize, and create triggers to facilitate the live migration process.

   At this point, new columns and tables may exist in the database, but will
   *not* all be populated in such a way that the next release will be able to
   function normally.

   As the previous release continues to write to the old schema, database
   triggers will live migrate the data to the new schema so it can be read by
   the next release.

#. Run ``keystone-manage db_sync --migrate`` on the first node to forcefully
   perform data migrations. This process will migrate all data from the old
   schema to the new schema while the previous release continues to operate
   normally.

   When this process completes, all data will be available in both the new
   schema and the old schema, so both the previous release and the next release
   will be capable are operating normally.

#. Update your configuration files (``/etc/keystone/``) on all nodes (except
   the first node, which you've already done) with those corresponding to the
   latest release.

#. Upgrade all keystone nodes to the next release, and restart them one at a
   time. During this step, you'll have a mix of releases operating side by
   side, both writing to the database.

   As the next release begins writing to the new schema, database triggers will
   also migrate the data to the old schema, keeping both data schemas in sync.

#. Run ``keystone-manage db_sync --contract`` to remove the old schema and all
   data migration triggers.

   When this process completes, the database will no longer be able to support
   the previous release.
