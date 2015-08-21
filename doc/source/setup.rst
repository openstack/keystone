..
      Copyright 2011-2012 OpenStack Foundation
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

This document describes getting the source from keystone's `Git repository`_
for development purposes.

To install Keystone from packaging, refer instead to Keystone's `User
Documentation`_.

.. _`Git Repository`: http://git.openstack.org/cgit/openstack/keystone
.. _`User Documentation`: http://docs.openstack.org/

Prerequisites
=============

This document assumes you are using Ubuntu, Fedora or openSUSE (SLE)

And that you have the following tools available on your system:

- Python_ 2.7 and 3.4
- git_
- setuptools_
- pip_
- msgfmt (part of the gettext package)
- virtualenv_

**Reminder**: If you're successfully using a different platform, or a
different version of the above, please document your configuration here!

.. _Python: http://www.python.org/
.. _git: http://git-scm.com/
.. _setuptools: http://pypi.python.org/pypi/setuptools

Getting the latest code
=======================

Make a clone of the code from our `Git repository`:

.. code-block:: bash

    $ git clone https://git.openstack.org/openstack/keystone.git

When that is complete, you can:

.. code-block:: bash

    $ cd keystone

Installing dependencies
=======================

Keystone maintains two lists of dependencies::

    requirements.txt
    test-requirements.txt

The first is the list of dependencies needed for running keystone, the second list includes dependencies used for active development and testing of Keystone itself.

These dependencies can be installed from PyPi_ using the Python tool pip_.

.. _PyPi: http://pypi.python.org/
.. _pip: http://pypi.python.org/pypi/pip

However, your system *may* need additional dependencies that `pip` (and by
extension, PyPi) cannot satisfy. These dependencies should be installed
prior to using `pip`, and the installation method may vary depending on
your platform.

Ubuntu 14.04:

.. code-block:: bash

    $ sudo apt-get install python-dev python3-dev libxml2-dev libxslt1-dev \
        libsasl2-dev libsqlite3-dev libssl-dev libldap2-dev libffi-dev


Fedora 19+:

.. code-block:: bash

    $ sudo yum install python-lxml python-greenlet-devel python-ldap sqlite-devel openldap-devel python-devel libxslt-devel openssl-devel libffi-devel

openSUSE 13.2 (SLE 12):

.. code-block:: bash

    $ sudo zypper install libxslt-devel openldap2-devel libopenssl-devel python-devel python-greenlet-devel python-ldap python-lxml python-pysqlite sqlite3-devel

PyPi Packages and VirtualEnv
----------------------------

We recommend establishing a virtualenv to run Keystone within. virtualenv
limits the Python environment to just what you're installing as dependencies,
useful to keep a clean environment for working on Keystone. The tools directory
in Keystone has a script already created to make this very simple:

.. code-block:: bash

    $ python tools/install_venv.py

This will create a local virtual environment in the directory ``.venv``.
Once created, you can activate this virtualenv for your current shell using:

.. code-block:: bash

    $ source .venv/bin/activate

The virtual environment can be disabled using the command:

.. code-block:: bash

    $ deactivate

You can also use ``tools\with_venv.sh`` to prefix commands so that they run
within the virtual environment. For more information on virtual environments,
see virtualenv_.

.. _virtualenv: http://www.virtualenv.org/

If you want to run Keystone outside of a virtualenv, you can install the
dependencies directly into your system from the requirements files:

.. code-block:: bash

    # Install the dependencies for running keystone
    $ pip install -r requirements.txt

    # Install the dependencies for developing, testing, and running keystone
    $ pip install -r test-requirements.txt

    # Use 'python setup.py' to link Keystone into Python's site-packages
    $ python setup.py develop


Verifying Keystone is set up
============================

Once set up, either directly or within a virtualenv, you should be able to
invoke Python and import the libraries. If you're using a virtualenv, don't
forget to activate it:

.. code-block:: bash

    $ source .venv/bin/activate

You should then be able to `import keystone` using Python without issue:

.. code-block:: bash

    $ python -c "import keystone"

If you can import Keystone without a traceback, you should be ready to move on
to :doc:`developing`.
