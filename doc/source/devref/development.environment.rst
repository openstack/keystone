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

====================================
Setting up a Development Environment
====================================

This document describes getting the source from keystone's `Git Repository`_
and setting the environment up for development purposes.

To install keystone from packaging, refer instead to OpenStack's `User
Documentation`_.

.. _`Git Repository`: https://git.openstack.org/cgit/openstack/keystone
.. _`User Documentation`: https://docs.openstack.org/

Prerequisites
=============

This document assumes you are using an Ubuntu, Fedora, or openSUSE platform and
that you have the following tools pre-installed on your system:

- Python_ 2.7 and 3.4, as the programming language;
- git_, as the version control tool;

**Reminder**: If you are successfully using a different platform, or a
different version of the above, please document your configuration here!

.. _git: http://git-scm.com/
.. _Python: http://www.python.org/

Getting the latest code
=======================

Make a clone of the code from our git repository and enter the directory:

.. code-block:: bash

    $ git clone https://git.openstack.org/openstack/keystone.git
    $ cd keystone

Development environment
=======================

For setting up the Python development environment and running `tox` testing
environments, please refer to the `Project Team Guide: Python Project Guide`_,
the OpenStack guide on wide standard practices around the use of Python.

That documentation will guide you to configure your development environment
and run keystone tests using `tox`, which uses virtualenv_ to isolate the Python
environment. After running it, notice the existence of a `.tox` directory.

.. _`Project Team Guide: Python Project Guide`: https://docs.openstack.org/project-team-guide/project-setup/python.html
.. _virtualenv: http://www.virtualenv.org/

Verifying keystone is set up
============================

Once set up, you should be able to invoke Python and import the libraries:

.. code-block:: bash

    $ .tox/py27/bin/python -c "import keystone"

If you can import keystone without a traceback, you should be ready to move on
to :doc:`development_best_practices`.

Database setup
==============

The script ``tools/test-setup.sh`` sets up databases as used by the
unit tests.
