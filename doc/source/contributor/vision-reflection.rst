..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

=============================
Technical Vision for Keystone
=============================

This document is a self-evaluation of keystone with regard to the
Technical Committee's `technical vision`_ and serves as a basis for guiding the
mission of the keystone project. The objectives captured here are what the
keystone team strives to build. New features and design changes should be
compared with this document before being embarked upon. When such proposals are
not in alignment, propose a change to this document or to the overall `technical
vision`_ to initiate a discussion on the renewed vision for the project.

.. _technical vision: https://governance.openstack.org/tc/reference/technical-vision.html

Mission Statement
=================

Keystone's mission is to provide secure, resilient, and user-friendly discovery,
authentication, and authorization for multitenant services.

Vision for OpenStack
====================

Self-service
------------

Keystone needs to strive to provide a flexible and simple mechanism to expose
OpenStack functionality safely and securely in a multi-tenant environment, to
enable a true self-service experience for end users in a shared-resource system.

Application Control
-------------------

Keystone provides the ability for applications to have their own
identity through :ref:`application credentials
<application_credentials>`, in service of developers building
applications that need to access cloud APIs and cloud-native
applications.

Interoperability
----------------

Keystone strives for a completely seamless experience for end users and
applications running on multiple clouds. Initiatives in service of providing
such a consistent user experience include providing a discovery mechanism for
available functionality, eliminating optional API extensions, and providing
useful default roles which eliminate the need for inconsistently-named,
operator-defined roles for similar access levels between clouds. Keystone is
also capable of itself acting as a bridge between separate clouds through its
Keystone-to-Keystone federated authentication functionality.

Bidirectional Compatibility
---------------------------

To support clients operating across multiple clouds of potentially different
versions, changes in keystone's major API are additive-only, and updates to
the API are signaled by the minor version number, which allows clients to
discover, to a reasonable degree, what capabilities are available in the
keystone version they are connecting to. Keystone also provides a JSON-home
document to aid clients in discovering the availability and status of features.
Enhancements to the discoverability of keystone's APIs are a priority.

Partitioning
------------

Keystone's service catalog mechanism makes it possible for users to have
authorization for resources in geographically distributed regions, and
keystone's various mechanisms for distributed authentication, such as using a
distributed database or LDAP identity backend, using an external authentication
source, or federating keystone itself to provide distributed identity providers,
support geographically distributed computing. Keystone hopes to create a
consistent user story and reference architecture for large-scale distributed
deployments, including edge-computing use cases.

Basic Physical Data Center Management
-------------------------------------

In support of OpenStack being primarily a data center management tool, keystone
should always work out of the box and not rely on the pre-existence of another
identity management system in the data center. In practice this means always
continuing to support a SQL storage backend for user data.

Plays Well With Others
----------------------

Keystone encourages its use outside of an OpenStack environment. In support of
this, keystone supports a standard authentication token format (`JWT`_) that can
be understood by many applications, and seeks to support full Single-Sign-On
functionality that can be used in front of any web application.

.. _JWT: https://tools.ietf.org/html/rfc7519

Customizable Integration
------------------------

In service of supporting customizable integration both between OpenStack
services and from client applications, keystone has an ongoing mission to
fulfill the `Principle of Least Privilege`_ and permit the cloud consumer to
delegate only the minimum permissions needed to an application. Keystone works
to provide this both through reforming OpenStack policy to make it easier to
manage across services, and by providing new mechanisms such as application
credential access rules to allow users to restrict capabilities of applications
to a subset of service APIs.

Graphical User Interface
------------------------

Keystone does not provide a graphical user interface, but must always be mindful
of how its APIs will be presented in dashboards. For some features, such as
Single-Sign-On authentication, keystone may provide its own graphical user
interface in order to provide a smooth web-login experience without requiring a
dependency on another dashboard.

Secure by Design
----------------

Keystone strives to be secure by design, by making opinionated choices about the
default security configuration. Making it easier to administer fine-grained
access control in support of the `Principle of Least Privilege`_ is an ongoing
effort.

.. _Principle of Least Privilege: https://en.wikipedia.org/wiki/Principle_of_least_privilege
