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

=========================
Keystone for Contributors
=========================

Keystone is a cloud identity service written in Python, which provides
authentication, authorization, and an OpenStack service catalog. It
implements `OpenStack's Identity API`_.

This document describes Keystone for contributors of the project, and assumes
that you are already familiar with Keystone from an `end-user perspective`_.

.. _`OpenStack's Identity API`: https://github.com/openstack/identity-api
.. _`end-user perspective`: http://docs.openstack.org/

Getting Started
===============

.. toctree::
    :maxdepth: 1

    setup
    testing
    migration
    configuration
    community
    usingkeystone

API Use Case Examples
=====================

.. toctree::
    :maxdepth: 1

    adminAPI_curl_examples
    serviceAPI_curl_examples

Configuration File Examples
===========================

.. toctree::
    :maxdepth: 1

    nova-api-paste
    keystone.conf

Man Pages
=========

.. toctree::
    :maxdepth: 1

    man/keystone-manage
    man/keystone
    man/keystone-auth
    man/keystone-admin
    man/keystone-import
    man/keystone-control
    man/sampledata

Developer Docs
==============

.. toctree::
    :maxdepth: 1

    developing
    architecture
    middleware
    sourcecode/autoindex

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
