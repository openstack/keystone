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

===========================
Developing Keystone Drivers
===========================

A driver, also known as a backend, is an important architectural
component of Keystone. It is an abstraction around the data access
needed by a particular subsystem. This pluggable implementation is not
only how Keystone implements its own data access, but how you can
implement your own!

Each major subsystem (that has data access needs) implements the data access
by using drivers. Some examples of Keystone's drivers:

- :class:`keystone.identity.backends.ldap.Identity`
- :class:`keystone.token.providers.fernet.Provider`
- :class:`keystone.contrib.federation.backends.sql.Federation`

In/Out of Tree
--------------

It's best to start developing your custom driver outside of the Keystone
development process. This means developing it in your own public or private git
repository and not worrying about getting it upstream (for now).

This is better for you because it gives you more freedom and you are not bound
to the strict OpenStack development rules or schedule. You can iterate faster
and take whatever shortcuts you need to get your product out of the door.

This is also good for Keystone because it will limit the amount of drivers
that must be maintained by the team. If the team had to maintain a
driver for each NoSQL DB that deployers want to use in production there
would be less time to make Keystone itself better. Not to mention that
the team would have to start gaining expertise in potentially dozens of
new technologies.

As you'll see below there is no penalty for open sourcing your driver,
on GitHub for example, or even keeping your implementation private. We
use `Setuptools entry points`_ to load your driver from anywhere in the
Python path.

.. _Setuptools entry points: no good resource?

How To Make a Driver
--------------------

The TLDR; steps (and too long didn't write yet):

1. Determine which subsystem you would like write a driver for
2. Subclass the most current version of the driver interface
3. Implement each of the abstract methods for that driver

   a. We are currently not documenting the exact input/outputs of the
      driver methods. The best approach right now is to use an existing
      driver as an example of what data your driver will receive and
      what data your driver will be required to return.
   b. There is a plan in place to document these APIs in more detail.

4. Register your new driver as an entry point
5. Configure your new driver in ``keystone.conf``
6. Sit back and enjoy!

Driver Versioning
-----------------

In the past the driver class was named ``Driver`` and changes would
sometimes be devastating to developers that depend on our driver
contracts. To help alleviate some of the issues we are now creating
version driver classes, e.g. ``DriverV8``.

We'll be supporting the current driver version for at least one version back.
This gives developers a full cycle to update their drivers. Some cases, such
as critical security flaws, may require a change to be introduced that breaks
compatibility. These special cases will be communicated as widely as possible
via the typical OpenStack communication channels.

As new driver interface versions are added old ones will be moved to a
"deprecated" state and will output deprecation messages when used. When a
driver version moves from "deprecated" to "unsupported" it will be
removed from the keystone source tree.

Removing Methods
~~~~~~~~~~~~~~~~

Newer driver interfaces may remove methods that are currently required.
Methods are removed when they are no longer required or invoked by Keystone.
There is no reason why methods removed from the Keystone interface need to be
removed from custom drivers.

Adding Methods
--------------

The most common API changes will be adding method to support new
features. We'll do our best to add methods in a way that is backward
compatible. The new version of the driver will define the new method as
an ``abc.abstractmethod`` that must be implemented by driver
implementations. When possible we'll also go back to our supported drivers and
add the method, with a default implementation.

For example, given a ``thing.DriverV8`` that added a new method
``list_things_by_name()``, we will go back to ``thing.DriverV7`` and
implement that method. This is good because in many cases your driver
will just work, but there are a couple of unfortunate side effects.
First if you have already used that method name you will have to rename
your method and cut a new version. Second is that the default
implementation may cause a performance penalty due to its naive
implementation.

Updating Methods
~~~~~~~~~~~~~~~~

We will try not to update existing methods in ways that will break old
driver implementations. That means that:

* We will respect existing parameters and not just delete them. If they are
  to be removed we will respect their behavior and deprecate them in older
  versions.
* We will add new parameters as optional with backward compatible defaults.
