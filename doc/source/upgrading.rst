..

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

==================
Upgrading Keystone
==================

This is a high-level description of our upgrade strategy built around
``keystone-manage db_sync``. It assumes that you are willing to have downtime
of your control plane during the upgrade process. With keystone unavailable, no
other OpenStack services will be able to authenticate requests, effectively
preventing the rest of the control plane from functioning normally.

.. NOTE::

    The details of these steps are entirely dependent on the details of your
    specific deployment, such as your chosen application server and database
    management system. Use it only as a guide when implementing your own
    upgrade process.

1. Plan!

   * Read and ensure you understand the `release notes
     http://docs.openstack.org/releasenotes/keystone/`_ for the next release.

   * Resolve any outstanding deprecation warnings in your logs. Some
     deprecation cycles are as short as a single release, so it's possible to
     break a deployment if you leave *any* outstanding warnings. It might be a
     good idea to re-read the release notes for the previous release (or two!).

   * Prepare your new configuration files, including ``keystone.conf``,
     ``logging.conf``, ``policy.json``, ``keystone-paste.ini``, and anything
     else in ``/etc/keystone/``, by customizing the corresponding files from
     the next release.

2. Stop all keystone processes. Otherwise, you'll risk multiple releases of
   keystone trying to write to the database at the same time.

3. Make a backup of your database. Keystone does not support downgrading the
   database, so restoring from a full backup is your only option for recovery
   in the event of an upgrade failure.

4. Upgrade all keystone nodes to the next release.

5. Update your configuration files (``/etc/keystone/``) with those
   corresponding from the latest release.

6. Run ``keystone-manage db_sync`` from any one node to upgrade both the
   database schema and run any corresponding database migrations.

7. Run ``keystone-manage doctor`` to diagnose symptoms of common deployment
   issues and receive instructions for resolving them.

8. Start all keystone processes.
