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
