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

=======================
Middleware Architecture
=======================

Abstract
========

The Keystone middleware architecture supports a common authentication protocol
in use between the OpenStack projects. By using Keystone as a common
authentication and authorization mechanism, the OpenStack project can plug in
to existing authentication and authorization systems in use by existing
environments.

The auth_token middleware is no longer hosted in Keystone and has moved to the
keystonemiddleware project. The `documentation regarding authentication
middleware`_ can be found there.

.. _`documentation regarding authentication middleware`: http://docs.openstack.org/developer/keystonemiddleware/middlewarearchitecture.html
