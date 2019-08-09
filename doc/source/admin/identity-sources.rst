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

====================
Configuring Keystone
====================

Identity sources
================

One of the most impactful decisions you'll have to make when configuring
keystone is deciding how you want keystone to source your identity data.
Keystone supports several different choices that will substantially impact how
you'll configure, deploy, and interact with keystone.

You can also mix-and-match various sources of identity (see
:ref:`Domain-specific Configuration <domain_specific_configuration>` for an
example). For example, you can store OpenStack service users
and their passwords in SQL, manage customers in LDAP, and authenticate employees
via SAML federation.

.. support_matrix:: identity-support-matrix.ini
