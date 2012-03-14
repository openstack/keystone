..
      Copyright 2011-2012 OpenStack, LLC
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

This document describes getting the source from keystone's `GitHub repository`_
for development purposes.

To install keystone from packaging, refer instead to Keystone's `User
Documentation`_.

.. _`GitHub Repository`: http://github.com/openstack/keystone
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

Make a clone of the code from our `Github repository`::

    $ git clone https://github.com/openstack/keystone.git

When that is complete, you can::

    $ cd keystone

Installing dependencies
=======================

Keystone maintains two lists of dependencies::

    tools/pip-requires
    tools/test-requires

The first is the list of dependencies needed for running keystone, the second list includes dependencies used for active development and testing of keystone itself.

These depdendencies can be installed from PyPi_ using the python tool pip_.

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

PyPi Packages and VirtualEnv
----------------------------

We recommend establishing a virtualenv to run keystone within. Virtualenv
limits the python environment to just what you're installing as depdendencies,
useful to keep a clean environment for working on Keystone. The tools directory
in keystone has a script already created to make this very simple::

    $ python tools/install_venv.py

This will create a local virtual environment in the directory ``.venv``.
Once created, you can activate this virtualenv for your current shell using::

    $ source .venv/bin/activate

The virtual environment can be disabled using the command::

    $ deactivate

You can also use ``tools\with_venv.sh`` to prefix commands so that they run
within the virtual environment. For more information on virtual environments,
see virtualenv_.

.. _virtualenv: http://www.virtualenv.org/

If you want to run keystone outside of a virtualenv, you can install the
dependencies directly into your system from the requires files::

    # Install the dependencies for running keystone
    $ pip install -r tools/pip-requires

    # Install the dependencies for developing, testing, and running keystone
    $ pip install -r tools/test-requires

    # Use python setup.py to link Keystone into python's site-packages
    $ python setup.py develop


Verifying Keystone is set up
============================

Once set up, either directly or within a virtualenv, you should be able to
invoke python and import the libraries. If you're using a virtualenv, don't
forget to activate it::

    $ source .venv/bin/activate
    $ python

You should then be able to `import keystone` from your Python shell
without issue::

    >>> import keystone
    >>>

If you can import keystone successfully, you should be ready to move on to
:doc:`developing`

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
