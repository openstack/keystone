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
- :class:`keystone.token.providers.fernet.core.Provider`
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

.. _Setuptools entry points: https://setuptools.readthedocs.io/en/latest/setuptools.html#dynamic-discovery-of-services-and-plugins

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

Driver Interface Changes
------------------------

We no longer support driver versioning. Thus, if a driver interface
changes, you will need to upgrade your custom driver to meet the
new driver contract.

Removing Methods
~~~~~~~~~~~~~~~~

Newer driver interfaces may remove methods that are currently required.
Methods are removed when they are no longer required or invoked by Keystone.
There is no reason why methods removed from the Keystone interface need to be
removed from custom drivers.

Adding Methods
~~~~~~~~~~~~~~

The most common API changes will be adding methods to support new
features. The new method must be implemented by custom driver
implementations.

Updating Methods
~~~~~~~~~~~~~~~~

We will do our best not to update existing methods in ways that will break
custom driver implementations. However, if that is not possible, again you
will need to upgrade your custom driver implementation to meet the new
driver contract.
