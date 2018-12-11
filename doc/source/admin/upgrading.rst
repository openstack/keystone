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
  <https://docs.openstack.org/releasenotes/keystone/>`_ for the next release.

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

Upgrading with minimal downtime
-------------------------------

If you run a multi-node keystone cluster that uses a replicated database, like
a Galera cluster, it is possible to upgrade with minimal downtime. This method
also optimizes recovery time from a failed upgrade. This section assumes
familiarity with the base case (`Upgrading with downtime`_) outlined above.
In these steps the nodes will be divided into ``first`` and ``other`` nodes.

#. Backup your database. There is no way to rollback the upgrade of keystone
   and this is your worst-case fallback option.

#. Disable keystone on all nodes but the ``first`` node. This can be done via a
   variety of mechanisms that will depend on the deployment. If you are unable
   to disable a service or place a service into maintenance mode in your load
   balancer, you can stop the keystone processes.

#. Stop the database service on one of the ``other`` nodes in the cluster. This
   will isolate the old dataset on a single node in the cluster. In the event
   of a failed update this data can be used to rebuild the cluster without
   having to restore from backup.

#. Update the configuration files on the ``first`` node.

#. Upgrade keystone on the ``first`` node. keystone is now down for your cloud.

#. Run ``keystone-manage db_sync`` on the ``first`` node. As soon as this
   finishes, keystone is now working again on a single node in the cluster.

#. keystone is now upgraded on a single node. Your load balancers will be
   sending all traffic to this single node. This is your chance to run
   ensure keystone up and running, and not broken. If keystone is broken, see
   the `Rollback after a failed upgrade`_ section below.

#. Once you have verified that keystone is up and running, begin the upgrade on
   the ``other`` nodes. This entails updating configuration files and upgrading
   the code. The ``db_sync`` does not need to be run again.

#. On the node where you stopped the database service, be sure to restart
   it and ensure that it properly rejoins the cluster.

Using this model, the outage window is minimized because the only time
when your cluster is totally offline is between loading the newer version
of keystone and running the ``db_sync`` command. Typically the outage with
this method can be measured in tens of seconds especially if automation is
used.

Rollback after a failed upgrade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If the upgrade fails, only a single node has been affected. This makes the
recovery simpler and quicker. If issues are not discovered until the entire
cluster is upgraded, a full shutdown and restore from backup will be required.
That will take much longer than just fixing a single node with an old copy of
the database still available. This process will be dependent on your
architecture and it is highly recommended that you've practiced this in a
development environment before trying to use it for the first time.

#. Isolate the bad node. Shutdown keystone and the database services
   on the upgraded "bad" node.

#. Bootstrap the database cluster from the node holding the old data.
   This may require wiping the data first on any nodes who are not
   holding old data.

#. Enable keystone on the old nodes in your load balancer or if
   the processes were stopped, restart them.

#. Validate that keystone is working.

#. Downgrade the code and config files on the bad node.

This process should be doable in a matter of minutes and will minimize cloud
downtime if it is required.

Upgrading without downtime
--------------------------

.. NOTE:

    Upgrading without downtime is only supported in deployments upgrading
    *from* Newton or a newer release.

    If upgrading a Mitaka deployment to Newton, the commands described here
    will be available as described below, but the ``keystone-manage db_sync
    --expand`` command will incur downtime (similar to running
    ``keystone-manage db_sync``), as it runs legacy (downtime-incurring)
    migrations prior to running schema expansions.

This is a high-level description of our upgrade strategy built around
additional options in ``keystone-manage db_sync``. Although it is much more
complex than the upgrade process described above, it assumes that you are not
willing to have downtime of your control plane during the upgrade process. With
this upgrade process, end users will still be able to authenticate to receive
tokens normally, and other OpenStack services will still be able to
authenticate requests normally.

#. Make a backup of your database. keystone does not support downgrading the
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

#. (*New in Newton*) Run ``keystone-manage db_sync --expand`` on the first node
   to expand the database schema to a superset of what both the previous and
   next release can utilize, and create triggers to facilitate the live
   migration process.

   .. warning::

     For MySQL, using the ``keystone-manage db_sync --expand`` command requires
     that you either grant your keystone user ``SUPER`` privileges, or run
     ``set global log_bin_trust_function_creators=1;`` in mysql beforehand.

   At this point, new columns and tables may exist in the database, but will
   *not* all be populated in such a way that the next release will be able to
   function normally.

   As the previous release continues to write to the old schema, database
   triggers will live migrate the data to the new schema so it can be read by
   the next release.

#. (*New in Newton*) Run ``keystone-manage db_sync --migrate`` on the first
   node to forcefully perform data migrations. This process will migrate all
   data from the old schema to the new schema while the previous release
   continues to operate normally.

   When this process completes, all data will be available in both the new
   schema and the old schema, so both the previous release and the next release
   will be capable of operating normally.

#. Update your configuration files (``/etc/keystone/``) on all nodes (except
   the first node, which you've already done) with those corresponding to the
   latest release.

#. Upgrade all keystone nodes to the next release, and restart them one at a
   time. During this step, you'll have a mix of releases operating side by
   side, both writing to the database.

   As the next release begins writing to the new schema, database triggers will
   also migrate the data to the old schema, keeping both data schemas in sync.

#. (*New in Newton*) Run ``keystone-manage db_sync --contract`` to remove the
   old schema and all data migration triggers.

   When this process completes, the database will no longer be able to support
   the previous release.

Using db_sync check
~~~~~~~~~~~~~~~~~~~

(*New in Pike*) In order to check the current state of your rolling upgrades,
you may run the command ``keystone-manage db_sync --check``. This will inform
you of any outstanding actions you have left to take as well as any possible
upgrades you can make from your current version. Here are a list of possible
return codes.

* A return code of ``0`` means you are currently up to date with the latest
  migration script version and all ``db_sync`` commands are complete.

* A return code of ``1`` generally means something serious is wrong with your
  database and operator intervention will be required.

* A return code of ``2`` means that an upgrade from your current database
  version is available, your database is not currently under version control,
  or the database is already under control. Your first step is to run
  ``keystone-manage db_sync --expand``.

* A return code of ``3`` means that the expansion stage is complete, and the
  next step is to run ``keystone-manage db_sync --migrate``.

* A return code of ``4`` means that the expansion and data migration stages are
  complete, and the next step is to run ``keystone-manage db_sync --contract``.
