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

======================================================
Programming Exercises for Interns and New Contributors
======================================================

The keystone team participates in open source internship programs such as
`Outreachy`_ and `Google Summer of Code`_ and welcomes contributions from
students and developers of all skill levels. To help with formal applications
for work programs or to give casual contributors a taste of what working on
keystone is like, we've created a few exercises to showcase what we think are
valuable development skills.

These exercises are samples, and code produced to solve them should most likely
not be merged into keystone. However, you should still propose them to `Gerrit`_
to get practice with the code review system and to get feedback from the team.
This is a good way to get used to the development workflow and get acquainted
with the benefits of working in a collaborative development environment. Also
feel free to :doc:`talk to the keystone team
<../getting-started/community>` to get help with these exercises, and
refer to the :doc:`contributor documentation <index>` for more context
on the architecture
and contributing guidelines for keystone.

The exercises provide some ideas of what you can do in keystone, but feel free
to get creative.

.. _Outreachy: https://www.outreachy.org/
.. _Google Summer of Code: https://summerofcode.withgoogle.com/
.. _Gerrit: https://docs.openstack.org/contributors/common/setup-gerrit.html

Add a Parameter to an API
=========================

Add a string parameter named ``nickname`` to the Project API. The end result will
be that you can use the new parameter when you create a new project using the
`POST /v3/projects`_ API, update the parameter using the `PATCH
/v3/projects/{project_id}`_ API, and the value displayed using the `GET
/v3/projects/{project_id}`_.

Refer to the :doc:`API Change tutorial <api_change_tutorial>`. In short, you will need to follow these
steps:

#. Create a SQL migration to add the parameter to the database table
   (:py:mod:`keystone.common.sql.migrations.versions`)

#. Add a SQL migration unit test (`keystone/tests/unit/test_sql_upgrade.py`)

#. Add the parameter to the SQL model for projects
   (:py:mod:`keystone.resource.backends.sql`)

#. Add unit tests (`keystone/tests/unit/resource/test_backend.py`) for the
   manager (:py:mod:`keystone.resource.core`) to show that the project can be
   created and updated with the new parameter using the provider mechanism

#. Add the parameter to the API schema (:py:mod:`keystone.resource.schema`)

#. Add an API unit test (`keystone/tests/unit/test_v3_resource.py`)

#. Document the new parameter in the `api-ref`_

.. _POST /v3/projects: https://docs.openstack.org/api-ref/identity/v3/#create-project
.. _PATCH /v3/projects/{project_id}: https://docs.openstack.org/api-ref/identity/v3/#update-project
.. _GET /v3/projects/{project_id}: https://docs.openstack.org/api-ref/identity/v3/#show-project-details
.. _api-ref: https://docs.openstack.org/api-ref/identity/

Write an External Driver
========================

Write an external driver named ``file`` that implements the Project API. The end
result will be that you can set ``[resource]/driver = file`` in `keystone.conf`
to have keystone load a list of project names from a text file, and querying
keystone for projects will return projects with those names in the default
domain.

Refer to the :doc:`Developing Keystone Drivers <developing-drivers>`
tutorial. Your driver can start as
an in-tree driver: create a class named ``Resource`` in
`keystone/resource/backends/file.py` that implements
:py:mod:`keystone.resource.backends.base.Resource`. Once you have that working,
break it out into a separate repository and create a `Setuptools entrypoint`_
to allow you to register it with keystone.

.. _Setuptools entrypoint: https://setuptools.readthedocs.io/en/latest/setuptools.html#dynamic-discovery-of-services-and-plugins

Write an Auth Plugin
====================

Write an auth plugin named ``hacker`` that allows any existing user to
authenticate if they provide a valid username and the password ``"hax0r"``. The
end result will be that you can add ``hacker`` as an auth method in
``[auth]/methods`` in `keystone.conf`, and users will be able to get an
:doc:`unscoped token <../admin/tokens>` using `POST /v3/auth/tokens`_ and providing ``"hacker"`` as
the auth method, a valid username as the username, and ``"hax0r"`` as the
password.

Refer to the :doc:`auth-plugins` documentation. You should create a class
``Hacker`` in `keystone/auth/plugins/hacker.py` that implements
:py:mod:`keystone.auth.plugins.base.AuthMethodHandler`. For bonus points, also
add the plugin to `keystoneauth`_ so that Python clients can also use this auth
method.

.. _POST /v3/auth/tokens: https://docs.openstack.org/api-ref/identity/v3/#password-authentication-with-unscoped-authorization
.. _keystoneauth: https://docs.openstack.org/keystoneauth/latest/
