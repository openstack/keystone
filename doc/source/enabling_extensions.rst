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

===================
Enabling Extensions
===================

------------------
Endpoint Filtering
------------------

The Endpoint Filtering extension enables creation of ad-hoc catalogs for each
project-scoped token request.

.. toctree::
   :maxdepth: 1

   extensions/endpoint_filter.rst

---------------
Endpoint Policy
---------------

The Endpoint Policy extension provides associations between service endpoints
and policies that are already stored in the Identity server and referenced by
a policy ID.

.. toctree::
   :maxdepth: 1

   extensions/endpoint_policy.rst

----------
Federation
----------

The Federation extension provides the ability for users to manage Identity
Providers (IdPs) and establish a set of rules to map federation protocol
attributes to Identity API attributes.

.. toctree::
   :maxdepth: 1

   extensions/federation.rst

----------
OAuth 1.0a
----------

The OAuth 1.0a extension provides the ability for Identity users to delegate
roles to third party consumers via the OAuth 1.0a specification.

.. toctree::
   :maxdepth: 1

   extensions/oauth1.rst

------------------
Revocation Events
------------------

The Revocation Events extension provides a list of token revocations. Each
event expresses a set of criteria which describes a set of tokens that are
no longer valid.

.. toctree::
   :maxdepth: 1

   extensions/revoke.rst
