
Example usage and Identity features
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``openstack`` CLI is used to interact with the Identity service.
It is set up to expect commands in the general
form of ``openstack command argument``, followed by flag-like keyword
arguments to provide additional (often optional) information. For
example, the :command:`openstack user list` and
:command:`openstack project create` commands can be invoked as follows:

.. code-block:: bash

   # Using token auth env variables
   export OS_SERVICE_ENDPOINT=http://127.0.0.1:5000/v2.0/
   export OS_SERVICE_TOKEN=secrete_token
   openstack user list
   openstack project create demo --domain default

   # Using token auth flags
   openstack --os-token secrete --os-endpoint http://127.0.0.1:5000/v2.0/ user list
   openstack --os-token secrete --os-endpoint http://127.0.0.1:5000/v2.0/ project create demo

   # Using user + password + project_name env variables
   export OS_USERNAME=admin
   export OS_PASSWORD=secrete
   export OS_PROJECT_NAME=admin
   openstack user list
   openstack project create demo --domain default

   # Using user + password + project-name flags
   openstack --os-username admin --os-password secrete --os-project-name admin user list
   openstack --os-username admin --os-password secrete --os-project-name admin project create demo


Logging
-------

You configure logging externally to the rest of Identity. The name of
the file specifying the logging configuration is set using the
``log_config`` option in the ``[DEFAULT]`` section of the
``/etc/keystone/keystone.conf`` file. To route logging through syslog,
set ``use_syslog=true`` in the ``[DEFAULT]`` section.

A sample logging configuration file is available with the project in
``etc/logging.conf.sample``. Like other OpenStack projects, Identity
uses the Python logging module, which provides extensive configuration
options that let you define the output levels and formats.


User CRUD
---------

Identity provides a user CRUD (Create, Read, Update, and Delete) filter that
Administrators can add to the ``public_api`` pipeline. The user CRUD filter
enables users to use a HTTP PATCH to change their own password. To enable
this extension you should define a ``user_crud_extension`` filter, insert
it after the ``*_body`` middleware and before the ``public_service``
application in the ``public_api`` WSGI pipeline in
``keystone-paste.ini``. For example:

.. code-block:: ini

   [filter:user_crud_extension]
   paste.filter_factory = keystone.contrib.user_crud:CrudExtension.factory

   [pipeline:public_api]
   pipeline = sizelimit url_normalize request_id build_auth_context token_auth admin_token_auth json_body ec2_extension user_crud_extension public_service

Each user can then change their own password with a HTTP PATCH.

.. code-block:: console

   $ curl -X PATCH http://localhost:5000/v2.0/OS-KSCRUD/users/USERID -H "Content-type: application/json"  \
     -H "X_Auth_Token: AUTHTOKENID" -d '{"user": {"password": "ABCD", "original_password": "DCBA"}}'

In addition to changing their password, all current tokens for the user
are invalidated.

.. note::

    Only use a KVS back end for tokens when testing.

