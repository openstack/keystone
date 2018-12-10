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

Supported clients
=================

There are two supported clients, `python-keystoneclient`_ project provides
python bindings and `python-openstackclient`_ provides a command line
interface.

.. _`python-openstackclient`: https://docs.openstack.org/python-openstackclient/latest
.. _`python-keystoneclient`: https://docs.openstack.org/python-keystoneclient/latest


Authenticating with a Password via CLI
--------------------------------------

To authenticate with keystone using a password and ``python-openstackclient``,
set the following flags, note that the following user referenced below should
be granted the ``admin`` role.

* ``--os-username OS_USERNAME``: Name of your user
* ``--os-user-domain-name OS_USER_DOMAIN_NAME``: Name of the user's domain
* ``--os-password OS_PASSWORD``: Password for your user
* ``--os-project-name OS_PROJECT_NAME``: Name of your project
* ``--os-project-domain-name OS_PROJECT_DOMAIN_NAME``: Name of the project's domain
* ``--os-auth-url OS_AUTH_URL``: URL of the keystone authentication server
* ``--os-identity-api-version OS_IDENTITY_API_VERSION``: This should always be set to 3

You can also set these variables in your environment so that they do not need
to be passed as arguments each time:

.. code-block:: bash

    $ export OS_USERNAME=my_username
    $ export OS_USER_DOMAIN_NAME=my_user_domain
    $ export OS_PASSWORD=my_password
    $ export OS_PROJECT_NAME=my_project
    $ export OS_PROJECT_DOMAIN_NAME=my_project_domain
    $ export OS_AUTH_URL=http://localhost:5000/v3
    $ export OS_IDENTITY_API_VERSION=3

For example, the commands ``user list``, ``token issue`` and ``project create``
can be invoked as follows:

.. code-block:: bash

    # Using password authentication, with environment variables
    $ export OS_USERNAME=admin
    $ export OS_USER_DOMAIN_NAME=Default
    $ export OS_PASSWORD=secret
    $ export OS_PROJECT_NAME=admin
    $ export OS_PROJECT_DOMAIN_NAME=Default
    $ export OS_AUTH_URL=http://localhost:5000/v3
    $ export OS_IDENTITY_API_VERSION=3
    $ openstack user list
    $ openstack project create demo
    $ openstack token issue

    # Using password authentication, with flags
    $ openstack --os-username=admin --os-user-domain-name=Default \
                --os-password=secret \
                --os-project-name=admin --os-project-domain-name=Default \
                --os-auth-url=http://localhost:5000/v3 --os-identity-api-version=3 \
                user list
    $ openstack --os-username=admin --os-user-domain-name=Default \
                --os-password=secret \
                --os-project-name=admin --os-project-domain-name=Default \
                --os-auth-url=http://localhost:5000/v3 --os-identity-api-version=3 \
                project create demo
