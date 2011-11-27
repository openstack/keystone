================
Extensions
================

Extensions support adding features and functions to OpenStack APIs at any time, without prior
approval or waiting for a new API and release cycles.

The extension mechanism is in development and documented in extensions_ and extensionspresentation_.

This document describes the extensions included with Keystone, how to enable and disable them,
and briefly touches on how to write your own extensions. 

.. _extensions: http://docs.openstack.org/trunk/openstack-compute/developer/openstack-api-extensions/content/ch02s01.html
.. _extensionspresentation: http://www.slideshare.net/RackerWilliams/openstack-extensions


Built-in Extensions
-------------------

Keystone ships with a number of extensions found under the
keystone/contib/extensions folder.

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


.. note::

    The included extensions are in the process of being rewritten. Currently
    only osksadm and oskscatalog work with this new extensions design.


Enabling/Disabling extensions.
------------------------------
  The Keystone conf file has a property called extensions. This property holds
  the list of supported extensions that you want enabled. If you want to
  add/remove an extension from being supported, add/remove the extension key
  from this property. The key is the name of the folder of the extension
  under the keystone/contrib/extensions folder.
  **If you want to load different extensions in the service API than the Admin API 
  you need to use different config files. 
  
Adding additional extensions.
------------------------------

To add a new extension, these are the steps involved.

1. Register your identifier (this process is not ready. For now, find a short
identifier that you know won't conflict with other extension writers).

    Example: OS for OpenStack, RAX for Rackspace

2. Decide a short hand name for extension.

    Example: OS-KSADM (for OpenStack's Keystone Admin extensions)

3. Decide whether the extension enhances Admin API, Service API or both.

4. Add a folder with the name we have already decided @
/contrib/extensions/{admin or service} based on which API you are enhancing.

5. Add static extension files for json (name it as extension.json) and xml
(name it as extension.xml) to the new extension folder. Refer to `Service Guide <https://github.com/openstack/keystone/blob/master/keystone/content/admin/identityadminguide.pdf?raw=true>`_
`Sample extension XML <https://github.com/openstack/keystone/blob/master/keystone/content/common/samples/extension.json>`_
`Sample extension JSON <https://github.com/openstack/keystone/blob/master/keystone/content/common/samples/extension.xml>`_ for the the content and structure.

6. If your extension is adding additional methods override the base class
'BaseExtensionHandler', call it 'ExtensionHandler', and add your methods.

7. If your extension modifies existing calls yu need to modify existing code to support the extension.

8. Modify this documentation to refelect the availability of your extension.

9. Add your extensions documentation, WADL, and XSD files in the keystone/content
folder

10. Add your extension name to the list of supported extensions in the keystone conf file. 

 
Finding out which extensions are running
----------------------------------------

A quick and simple test is::

    curl http://localhost:35357/v2.0/extensions
    
    or
    
    curl http://localhost:5000/v2.0/extensions

The response will list the extensions available.
    