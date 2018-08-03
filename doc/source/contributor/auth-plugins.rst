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

Authentication Plugins
======================

.. NOTE::
    This feature is only supported by keystone for the Identity API v3 clients.

Keystone supports authentication plugins and they are specified in the
``[auth]`` section of the configuration file. However, an authentication plugin
may also have its own section in the configuration file. It is up to the plugin
to register its own configuration options.

* ``methods`` - comma-delimited list of authentication plugin names
* ``<plugin name>`` - specify the class which handles to authentication method,
  in the same manner as one would specify a backend driver.

Keystone provides three authentication methods by default. ``password`` handles
password authentication and ``token`` handles token authentication.
``external`` is used in conjunction with authentication performed by a
container web server that sets the ``REMOTE_USER`` environment variable. For
more details, refer to :doc:`External Authentication
<../advanced-topics/external-auth>`.

How to Implement an Authentication Plugin
-----------------------------------------

All authentication plugins must extend the
:class:`keystone.auth.plugins.base.AuthMethodHandler` class and implement the
``authenticate()`` method. The ``authenticate()`` method expects the following
parameters.

* ``context`` - keystone's request context
* ``auth_payload`` - the content of the authentication for a given method
* ``auth_context`` - user authentication context, a dictionary shared by all
  plugins. It contains ``method_names`` and ``bind`` by default.
  ``method_names`` is a list and ``bind`` is a dictionary.

If successful, the ``authenticate()`` method must provide a valid ``user_id``
in ``auth_context`` and return ``None``. ``method_name`` is used to convey any
additional authentication methods in case authentication is for re-scoping. For
example, if the authentication is for re-scoping, a plugin must append the
previous method names into ``method_names``.

If authentication requires multiple steps, the ``authenticate()`` method must
return the payload in the form of a dictionary for the next authentication
step.

If authentication is unsuccessful, the ``authenticate()`` method must raise a
:class:`keystone.exception.Unauthorized` exception.

Simply add the new plugin name to the ``methods`` list along with your plugin
class configuration in the ``[auth]`` sections of the configuration file to
deploy it.

If the plugin requires additional configurations, it may register its own
section in the configuration file.

Plugins are invoked in the order in which they are specified in the ``methods``
attribute of the ``authentication`` request body. If multiple plugins are
invoked, all plugins must succeed in order to for the entire authentication to
be successful. Furthermore, all the plugins invoked must agree on the
``user_id`` in the ``auth_context``.

The ``REMOTE_USER`` environment variable is only set from a containing
webserver. However, to ensure that a user must go through other authentication
mechanisms, even if this variable is set, remove ``external`` from the list of
plugins specified in ``methods``. This effectively disables external
authentication. For more details, refer to :doc:`External Authentication
<../advanced-topics/external-auth>`.

