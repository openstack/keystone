
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
   export OS_TOKEN=secret
   export OS_URL=http://127.0.0.1:5000/v3/
   openstack user list
   openstack project create demo --domain default

   # Using token auth flags
   openstack --os-token secret --os-url http://127.0.0.1:5000/v3/ user list
   openstack --os-token secret --os-url http://127.0.0.1:5000/v3/ project create demo

   # Using user + password + project_name env variables
   export OS_USERNAME=admin
   export OS_PASSWORD=secret
   export OS_PROJECT_NAME=admin
   openstack user list
   openstack project create demo --domain default

   # Using user + password + project-name flags
   openstack --os-username admin --os-password secret --os-project-name admin user list
   openstack --os-username admin --os-password secret --os-project-name admin project create demo


Logging
-------

You configure logging externally to the rest of Identity. The name of
the file specifying the logging configuration is set using the
``log_config_append`` option in the ``[DEFAULT]`` section of the
``/etc/keystone/keystone.conf`` file. To route logging through syslog,
set ``use_syslog=true`` in the ``[DEFAULT]`` section.

A sample logging configuration file is available with the project in
``etc/logging.conf.sample``. Like other OpenStack projects, Identity
uses the `Python logging module`_, which provides extensive configuration
options that let you define the output levels and formats.

.. _`Python logging module`: https://docs.python.org/library/logging.html
