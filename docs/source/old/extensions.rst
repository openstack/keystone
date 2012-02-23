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

==========
Extensions
==========

Extensions support adding features and functions to OpenStack APIs at any time, without prior
approval or waiting for a new API and release cycles.

The extension framework is in development and documented in extensions_ and extensionspresentation_.

This document describes the extensions included with Keystone, how to enable and disable them,
and briefly touches on how to write your own extensions.

.. _extensions: http://docs.openstack.org/trunk/openstack-compute/developer/openstack-api-extensions/content/ch02s01.html
.. _extensionspresentation: http://www.slideshare.net/RackerWilliams/openstack-extensions

Built-in Extensions
-------------------

Keystone ships with a number of extensions found under the
``keystone/contib/extensions`` folder.

The following built-in extensions are included:

OS-KSADM

    This is an extensions that supports managing users, tenants, and roles
    through the API. Without this extensions, the ony way to manage those
    objects is through keystone-manage or directly in the underlying database.

    This is an Admin API extension only.

OS-KSCATALOG

    This extensions supports managing Endpoints and prrovides the Endpoint
    Template mechanism for managing bulk endpoints.

    This is an Admin API extension only.

OS-EC2

    This extension adds support for EC2 credentials.

    This is an Admin and Service API extension.

RAX-GRP

    This extension adds functionality the enables groups.

    This is an Admin and Service API extension.

RAX-KEY

    This extensions adds support for authentication with an API Key (the core
    Keystone API only supports username/password credentials)

    This is an Admin and Service API extension.

HP-IDM

    This extension adds capability to filter roles with optional service IDs
    for token validation to mitigate security risks with role name conflicts.
    See https://bugs.launchpad.net/keystone/+bug/890411 for more details.

    This is an Admin API extension. Applicable to validate token (GET)
    and check token (HEAD) APIs only.

OS-KSVALIDATE

    This extensions supports admin calls to /tokens without having to specify
    the token ID in the URL. Instead, the ID is supplied in a header called
    X-Subject-Token. This is provided as an alternative to address any security
    concerns that arise when token IDs are passed as part of the URL which is
    often (and by default) logged to insecure media.

    This is an Admin API extension only.

.. note::

    The included extensions are in the process of being rewritten. Currently
    osksadm, oskscatalog, hpidm, and osksvalidate work with this new
    extensions design.


Enabling & Disabling Extensions
-------------------------------

The Keystone conf file has a property called extensions. This property holds
the list of supported extensions that you want enabled. If you want to
add/remove an extension from being supported, add/remove the extension key
from this property. The key is the name of the folder of the extension
under the keystone/contrib/extensions folder.

.. note::

    If you want to load different extensions in the service API than the Admin API
    you need to use different config files.

Creating New Extensions
-----------------------

#. **Adopt a unique organization abbreviation.**

   This prefix should uniquely identify your organization within the community.
   The goal is to avoid schema and resource collisions with similiar extensions.
   (e.g. ``OS`` for OpenStack, ``RAX`` for Rackspace, or ``HP`` for Hewlett-Packard)

#. **Adopt a unique extension abbreviation.**

   Select an abbreviation to identify your extension, and append to
   your organization prefix using a hyphen (``-``), by convention
   (e.g. ``OS-KSADM`` (for OpenStack's Keystone Administration extension).

   This combination is referred to as your extension's prefix.

#. **Determine the scope of your extension.**

   Extensions can enhance the Admin API, Service API or both.

#. **Create a new module.**

   Create a module to isolate your namespace based on the extension prefix
   you selected::

       keystone/contrib/extensions/admin

   ... and/or::

       keystone/contrib/extensions/service/

   ... based on which API you are enhancing.

   .. note::

       In the future, we will support loading external extensions.

#. Add static extension files for JSON (``*.json``) and XML
   (``*.xml``) to the new extension module.

   Refer to `Service Guide <https://github.com/openstack/keystone/blob/master/keystone/content/admin/identityadminguide.pdf?raw=true>`_
   `Sample extension XML <https://github.com/openstack/keystone/blob/master/keystone/content/common/samples/extension.json>`_
   `Sample extension JSON <https://github.com/openstack/keystone/blob/master/keystone/content/common/samples/extension.xml>`_ for the the content and structure.

#. If your extension is adding additional methods override the base class
   ``BaseExtensionHandler``, name it ``ExtensionHandler``, and add your methods.

#. **Document your work.**

   Provide documentation to support your extension.

   Extensions documentation, WADL, and XSD files can be stored in the
   ``keystone/content`` folder.

#. Add your extension name to the list of supported extensions in The
   ``keystone.conf`` file.

Which extensions are enabled?
-----------------------------

Discover which extensions are available (service API)::

    curl http://localhost:5000/v2.0/extensions

... or (admin API)::

    curl http://localhost:35357/v2.0/extensions

The response will list the extensions available.
