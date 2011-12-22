Keystone
========

Keystone is an OpenStack project that provides Identity, Token and Catalog
services for use specifically by projects in the OpenStack family.

Much of the design is precipitated from the expectation that the auth backends
for most deployments will actually be shims in front of existing user systems.


----------
Data Model
----------

Keystone was designed from the ground up to be amenable to multiple styles of
backends and as such many of the methods and data types will happily accept 
more data than they know what to do with and pass them on to a backend.

There are a few main data types:

 * **User**: has account credentials, is associated with one or more tenants
 * **Tenant**: unit of ownership in openstack, contains one or more users
 * **Token**: identifying credential associated with a user or user and tenant
 * **Extras**: bucket of key-values associated with a user-tenant pair, typically used to define roles.

While the general data model allows a many-to-many relationship between Users
and Tenants and a many-to-one relationship between Extras and User-Tenant pairs,
the actual backend implementations take varying levels of advantage of that
functionality.


KVS Backend
-----------

A simple backend interface meant to be further backended on anything that can
support primary key lookups, the most trivial implementation being an in-memory
dict.

Supports all features of the general data model.


PAM Backend
-----------

Extra simple backend that uses the current system's PAM service to authenticate,
providing a one-to-one relationship between Users and Tenants with the `root`
User also having the 'admin' role.


Templated Backend
-----------------

Largely designed for a common use case around service catalogs in the Keystone
project, a Catalog backend that simply expands pre-configured templates to
provide catalog data.

Example paste.deploy config (uses $ instead of % to avoid ConfigParser's
interpolation)::

  [DEFAULT]
  catalog.RegionOne.identity.publicURL = http://localhost:$(public_port)s/v2.0
  catalog.RegionOne.identity.adminURL = http://localhost:$(public_port)s/v2.0
  catalog.RegionOne.identity.internalURL = http://localhost:$(public_port)s/v2.0
  catalog.RegionOne.identity.name = 'Identity Service'


---------------
Keystone Compat
---------------

While Keystone Light takes a fundamentally different approach to its services
from Keystone, a compatibility layer is included to make switching much easier
for projects already attempting to use Keystone.

The compatibility service is activated by defining an alternate application in
the paste.deploy config and adding it to your main pipeline::

  [app:keystone]
  paste.app_factory = keystonelight.keystone_compat:app_factory

Also relevant to Keystone compatibility are these sequence diagrams (openable
with sdedit_)

.. _sdedit: http://sourceforge.net/projects/sdedit/files/sdedit/4.0/

Diagram: keystone_compat_flows.sdx_

..  _: https://raw.github.com/termie/keystonelight/master/docs/keystone_compat_flows.sdx

----------------
Approach to CRUD
----------------

While it is expected that any "real" deployment at a large company will manage
their users, tenants and other metadata in their existing user systems, a
variety of CRUD operations are provided for the sake of development and testing.

CRUD is treated as an extension or additional feature to the core feature set in
that it is not required that a backend support it.


----------------------------------
Approach to Authorization (Policy)
----------------------------------

Various components in the system require that different actions are allowed
based on whether the user is authorized to perform that action.

For the purposes of Keystone Light there are only a couple levels of
authorization being checked for:

 * Require that the performing user is considered an admin.
 * Require that the performing user matches the user being referenced.

Other systems wishing to use the policy engine will require additional styles
of checks and will possibly write completely custom backends. Backends included
in Keystone Light are:


Trivial True
------------

Allows all actions.


Simple Match
------------

Given a list of matches to check for, simply verify that the credentials
contain the matches. For example::

  credentials = {'user_id': 'foo', 'is_admin': 1, 'roles': ['nova:netadmin']}

  # An admin only call:
  policy_api.can_haz(('is_admin:1',), credentials)

  # An admin or owner call:
  policy_api.can_haz(('is_admin:1', 'user_id:foo'),
                     credentials)

  # A netadmin call:
  policy_api.can_haz(('roles:nova:netadmin',),
                     credentials)


Credentials are generally built from the user metadata in the 'extras' part
of the Identity API. So, adding a 'role' to the user just means adding the role
to the user metadata.


Capability RBAC
---------------

(Not yet implemented.)

Another approach to authorization can be action-based, with a mapping of roles
to which capabilities are allowed for that role. For example::

  credentials = {'user_id': 'foo', 'is_admin': 1, 'roles': ['nova:netadmin']}

  # add a policy
  policy_api.add_policy('action:nova:add_network', ('roles:nova:netadmin',))

  policy_api.can_haz(('action:nova:add_network',), credentials)


In the backend this would look up the policy for 'action:nova:add_network' and
then do what is effectively a 'Simple Match' style match against the creds.


-----------
Still To Do
-----------

 * Dev and testing setups would do well with some user/tenant/etc CRUD, for the
   KVS backends at least.
 * Fixture loading functionality would also be killer tests and dev.
 * LDAP backend.
 * Keystone import.
 * (./) Admin-only interface
 * Don't check git checkouts as often, to speed up tests
