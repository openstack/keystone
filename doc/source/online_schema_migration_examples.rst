
====================================
Online SQL schema migration examples
====================================

This document links to several examples implementing online SQL schema
migrations to facilitate simultaneously running OpenStack services in
different versions with the same DB schema.


* Nova `data migration example
  <http://specs.openstack.org/openstack/nova-specs/specs/kilo/implemented/flavor-from-sysmeta-to-blob.html>`_
* Nova `data migration enforcement example
  <https://review.openstack.org/#/c/174480/15/nova/db/sqlalchemy/migrate_repo/versions/291_enforce_flavors_migrated.py>`_
  of sqlalchemy migrate/deprecated scripts
* Nova `flavor migration spec
  <http://specs.openstack.org/openstack/nova-specs/specs/kilo/implemented/flavor-from-sysmeta-to-blob.html>`_
  example of data migrations in the object layer
* Cinder `online schema upgrades spec <https://specs.openstack.org/openstack/cinder-specs/specs/mitaka/online-schema-upgrades.html>`_
  example of migrating a column to a many-to-many relation table


For documentation on how to make online migrations move on to
:ref:`Database Schema Migrations <online-migration>`.
