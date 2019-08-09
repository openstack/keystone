..
      Copyright 2018 SUSE Linux GmbH
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

======
Trusts
======

OpenStack Identity manages authentication and authorization. A trust is
an OpenStack Identity extension that enables delegation and, optionally,
impersonation through ``keystone``. A trust extension defines a
relationship between:

**Trustor**
  The user delegating a limited set of their own rights to another user.

**Trustee**
  The user trust is being delegated to, for a limited time.

  The trust can eventually allow the trustee to impersonate the trustor.
  For security reasons, some safeties are added. For example, if a trustor
  loses a given role, any trusts the user issued with that role, and the
  related tokens, are automatically revoked.

The delegation parameters are:

**User ID**
  The user IDs for the trustor and trustee.

**Privileges**
  The delegated privileges are a combination of a project ID and a
  number of roles that must be a subset of the roles assigned to the
  trustor.

  If you omit all privileges, nothing is delegated. You cannot
  delegate everything.

**Delegation depth**
  Defines whether or not the delegation is recursive. If it is
  recursive, defines the delegation chain length.

  Specify one of the following values:

  - ``0``. The delegate cannot delegate these permissions further.

  - ``1``. The delegate can delegate the permissions to any set of
    delegates but the latter cannot delegate further.

  - ``inf``. The delegation is infinitely recursive.

**Endpoints**
  A list of endpoints associated with the delegation.

  This parameter further restricts the delegation to the specified
  endpoints only. If you omit the endpoints, the delegation is
  useless. A special value of ``all_endpoints`` allows the trust to be
  used by all endpoints associated with the delegated project.

**Duration**
  (Optional) Comprised of the start time and end time for the trust.

.. note::

   See the administrator guide on :doc:`removing expired trusts
   </admin/manage-trusts>` for recommended
   maintenance procedures.
