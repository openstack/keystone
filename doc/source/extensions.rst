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

==========
Extensions
==========

Status
======

An extension may be considered ``stable``, ``experimental`` or ``out-of-tree``.

* A `stable` status indicates that an extension is fully supported by the
  OpenStack Identity team.

* An `experimental` status indicates that although the intention is to keep
  the API unchanged, we reserve the right to change it up until the point that
  it is deemed `stable`.

* An `out-of-tree` status indicates that no formal support will be provided.

Graduation Process
==================

By default, major new functionality that is proposed to be in-tree will start
off in `experimental` status. Typically it would take at minimum of one cycle
to transition from `experimental` to `stable`, although in special cases this
might happened within a cycle.

Removal Process
===============

It is not intended that functionality should stay in experimental for a long
period, functionality that stays `experimental` for more than **two** releases
would be expected to make a transition to either `stable` or `out-of-tree`.

Current Extensions
==================

------------------
Endpoint Filtering
------------------

The Endpoint Filtering extension enables creation of ad-hoc catalogs for each
project-scoped token request.

.. NOTE:: Support status for Endpoint Filtering

   *Experimental* (Icehouse, Juno)
   *Stable* (Kilo)

.. toctree::
   :maxdepth: 1

   extensions/endpoint_filter.rst

* `API Specification for Endpoint Filtering <http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3-os-ep-filter-ext.html>`__

---------------
Endpoint Policy
---------------

The Endpoint Policy extension provides associations between service endpoints
and policies that are already stored in the Identity server and referenced by
a policy ID.

.. NOTE:: Support status for Endpoint Policy

   *Experimental* (Juno)
   *Stable* (Kilo)

.. toctree::
   :maxdepth: 1

   extensions/endpoint_policy.rst

* `API Specification for Endpoint Policy <http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3-os-endpoint-policy.html>`__

-------
Inherit
-------

The Inherit extension provides the ability for projects to inherit role
assignments from their owning domain, or from projects higher in the
hierarchy.

.. NOTE:: Support status for Inherit

   *Experimental* (Havava, Icehouse)
   *Stable* (Juno)

* `API Specification for Inherit <http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3-os-inherit-ext.html>`__

----------
OAuth 1.0a
----------

The OAuth 1.0a extension provides the ability for Identity users to delegate
roles to third party consumers via the OAuth 1.0a specification.

.. NOTE:: Support status for OAuth 1.0a

   *Experimental* (Havana, Icehouse)
   *Stable* (Juno)

.. toctree::
   :maxdepth: 1

   extensions/oauth1.rst

* `API Specification for OAuth 1.0a <http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3-os-oauth1-ext.html>`__

-----------------
Revocation Events
-----------------

The Revocation Events extension provides a list of token revocations. Each
event expresses a set of criteria which describes a set of tokens that are
no longer valid.

.. NOTE:: Support status for Revocation Events

   *Experimental* (Juno)
   *Stable* (Kilo)

.. toctree::
   :maxdepth: 1

   extensions/revoke.rst

* `API Specification for Revocation Events <http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3-os-revoke-ext.html>`__
