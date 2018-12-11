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

====================
Configuring Keystone
====================

Identity sources
================

One of the most impactful decisions you'll have to make when configuring
keystone is deciding how you want keystone to source your identity data.
Keystone supports several different choices that will substantially impact how
you'll configure, deploy, and interact with keystone.

You can also mix-and-match various sources of identity (see `Domain-specific
Configuration`_ for an example). For example, you can store OpenStack service users
and their passwords in SQL, manage customers in LDAP, and authenticate employees
via SAML federation.

.. _Domain-specific Configuration: admin/domain-specific-config.html
.. support_matrix:: identity-support-matrix.ini

Limiting list return size
=========================

Keystone provides a method of setting a limit to the number of entities
returned in a collection, which is useful to prevent overly long response times
for list queries that have not specified a sufficiently narrow filter. This
limit can be set globally by setting ``list_limit`` in the default section of
``keystone.conf``, with no limit set by default. Individual driver sections may
override this global value with a specific limit, for example:

.. code-block:: ini

    [resource]
    list_limit = 100

If a response to ``list_{entity}`` call has been truncated, then the response
status code will still be 200 (OK), but the ``truncated`` attribute in the
collection will be set to ``true``.
