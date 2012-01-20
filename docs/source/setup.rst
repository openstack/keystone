..
      Copyright 2011 OpenStack, LLC
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

=============================================
Setting up a Keystone development environment
=============================================

This document describes setting up keystone directly from GitHub_
for development purposes.

To install keystone from packaging, refer instead to Keystone's `User Documentation`_.

.. _GitHub: http://github.com/openstack/keystone
.. _`User Documentation`: http://docs.openstack.org/

Prerequisites
=============

This document assumes you are using:

- Ubuntu 11.10, Fedora 15, or Mac OS X Lion
- `Python 2.7`_

.. _`Python 2.7`: http://www.python.org/

And that you have the following tools available on your system:

- git_
- setuptools_
- pip_

**Reminder**: If you're successfully using a different platform, or a
different version of the above, please document your configuration here!

.. _git: http://git-scm.com/
.. _setuptools: http://pypi.python.org/pypi/setuptools

Getting the latest code
=======================

You can clone our latest code from our `Github repository`::

    $ git clone https://github.com/openstack/keystone.git

When that is complete, you can::

    $ cd keystone

.. _`Github repository`: https://github.com/openstack/keystone

Installing dependencies
=======================

Keystone maintains a list of PyPi_ dependencies, designed for use by
pip_.

.. _PyPi: http://pypi.python.org/
.. _pip: http://pypi.python.org/pypi/pip

However, your system *may* need additional dependencies that `pip` (and by
extension, PyPi) cannot satisfy. These dependencies should be installed
prior to using `pip`, and the installation method may vary depending on
your platform.

Ubuntu 11.10::

    $ sudo apt-get install python-dev libxml2-dev libxslt1-dev libsasl2-dev libsqlite3-dev libssl-dev libldap2-dev

Fedora 15::

    $ sudo yum install python-sqlite2 python-lxml python-greenlet-devel python-ldap

Mac OS X Lion (requires MacPorts_)::

    $ sudo port install py-ldap

.. _MacPorts: http://www.macports.org/

PyPi Packages
-------------

Assuming you have any necessary binary packages & header files available
on your system, you can then install PyPi dependencies.

You may also need to prefix `pip install` with `sudo`, depending on your
environment::

    # Describe dependencies (including non-PyPi dependencies)
    $ cat tools/pip-requires

    # Install all PyPi dependencies (for production, testing, and development)
    $ pip install -r tools/pip-requires

Updating your PYTHONPATH
========================

There are a number of methods for getting Keystone into your PYTHON PATH,
the easiest of which is::

    # Fake-install the project by symlinking Keystone into your Python site-packages
    $ python setup.py develop

You should then be able to `import keystone` from your Python shell
without issue::

    >>> import keystone.version
    >>>

If you want to check the version of Keystone you are running:

    >>> print keystone.version.version()
    2012.1-dev


If you can import keystone successfully, you should be ready to move on to :doc:`testing`.

Troubleshooting
===============

Eventlet segfaults on RedHat / Fedora
-------------------------------------

[*If this is no longer an issue, please remove this section, thanks!*]

On some OSes, specifically Fedora 15, the current versions of
greenlet/eventlet segfault when running keystone. To fix this, install
the development versions of greenlet and eventlet::

    $ pip uninstall greenlet eventlet
    $ cd <appropriate working directory>
    $ hg clone https://bitbucket.org/ambroff/greenlet
    $ cd greenlet
    $ sudo python setup.py install

    $ cd <appropriate working directory>
    $ hg clone https://bitbucket.org/which_linden/eventlet
    $ cd greenlet
    $ sudo python setup.py install
