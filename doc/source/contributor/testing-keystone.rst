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

================
Testing Keystone
================

Running Tests
-------------

Before running tests, you should have ``tox`` installed and available in your
environment (in addition to the other external dependencies in
:ref:`dev-environment`):

.. code-block:: bash

    $ pip install tox

.. NOTE::

    You may need to perform both the above operation and the next inside a
    python virtualenv, or prefix the above command with ``sudo``, depending on
    your preference.

To execute the full suite of tests maintained within keystone, simply run:

.. code-block:: bash

    $ tox

This iterates over multiple configuration variations, and uses external
projects to do light integration testing to verify the Identity API against
other projects.

.. NOTE::

    The first time you run ``tox``, it will take additional time to build
    virtualenvs. You can later use the ``-r`` option with ``tox`` to rebuild
    your virtualenv in a similar manner.

To run tests for one or more specific test environments (for example, the most
common configuration of Python 2.7 and PEP-8), list the environments with the
``-e`` option, separated by spaces:

.. code-block:: bash

    $ tox -e py27,pep8

Use ``tox --listenvs`` to list all testing environments specified in keystone's
``tox.ini`` file.

Interactive debugging
~~~~~~~~~~~~~~~~~~~~~

Using ``pdb`` breakpoints with ``tox`` and ``testr`` normally doesn't work
since the tests just fail with a ``BdbQuit`` exception rather than stopping at
the breakpoint.

To capture breakpoints while running tests, use the ``debug`` environment. The
following example uses the environment while invoking a specific test run.

.. code-block:: bash

    $ tox -e debug keystone.tests.unit.test_module.TestClass.test_case

For reference, the ``debug`` environment implements the instructions here:
https://wiki.openstack.org/wiki/Testr#Debugging_.28pdb.29_Tests

Building the Documentation
--------------------------

The ``docs`` and ``api-ref`` environments will automatically generate
documentation and the API reference respectively. The results are written to
``doc/`` and ``api-ref/``.

For example, use the following command to render all documentation and manual
pages:

.. code-block:: bash

    $ tox -e docs

Tests Structure
---------------

Not all of the tests in the ``keystone/tests/unit`` directory are strictly unit
tests. Keystone intentionally includes tests that run the service locally and
drives the entire configuration to achieve basic functional testing.

For the functional tests, an in-memory key-value store or in-memory SQLite
database is used to keep the tests fast.

Within the tests directory, the general structure of the backend tests is a
basic set of tests represented under a test class, and then subclasses of those
tests under other classes with different configurations to drive different
backends through the APIs. To add tests covering all drivers, update the base
test class in ``test_backend.py``.

.. NOTE::

    The structure of backend testing is in transition, migrating from having
    all classes in a single file (``test_backend.py``) to one where there is a
    directory structure to reduce the size of the test files. See:

        - :mod:`keystone.tests.unit.backend.role`
        - :mod:`keystone.tests.unit.backend.domain_config`

To add new drivers, subclass the base class at ``test_backend.py`` (look at
``test_backend_sql.py`` for examples) and update the configuration of the test
class in ``setUp()``.

For example, ``test_backend.py`` has a sequence of tests under the class
:class:`keystone.tests.unit.test_backend.IdentityTests` that will work with the
default drivers. The ``test_backend_sql.py`` module subclasses those tests,
changing the configuration by overriding with configuration files stored in the
``tests/unit/config_files`` directory aimed at enabling the SQL backend for the
Identity module.

Testing Schema Migrations
-------------------------

The application of schema migrations can be tested using SQLAlchemy Migrate's
built-in test runner, one migration at a time.

.. WARNING::

    This may leave your database in an inconsistent state; attempt this in
    non-production environments only!

This is useful for testing the *next* migration in sequence in a database under
version control:

.. code-block:: bash

    $ python keystone/common/sql/migrate_repo/manage.py test \
    --url=sqlite:///test.db \
    --repository=keystone/common/sql/migrate_repo/

This command references to a SQLite database (test.db) to be used. Depending on
the migration, this command alone does not make assertions as to the integrity
of your data during migration.

LDAP Tests
----------

LDAP has a fake backend that performs rudimentary operations. If you
are building more significant LDAP functionality, you should test against
a live LDAP server.  Devstack has an option to set up a directory server for
Keystone to use.  Add ldap to the ``ENABLED_SERVICES`` environment variable,
and set environment variables ``KEYSTONE_IDENTITY_BACKEND=ldap`` and
``KEYSTONE_CLEAR_LDAP=yes`` in your ``localrc`` file.

The unit tests can be run against a live server with
``keystone/tests/unit/test_ldap_livetest.py`` and
``keystone/tests/unit/test_ldap_pool_livetest.py``. The default password is
``test`` but if you have installed devstack with a different LDAP password,
modify the file ``keystone/tests/unit/config_files/backend_liveldap.conf`` and
``keystone/tests/unit/config_files/backend_pool_liveldap.conf`` to reflect your
password.

.. NOTE::
    To run the live tests you need to set the environment variable
    ``ENABLE_LDAP_LIVE_TEST`` to a non-negative value.

"Work in progress" Tests
------------------------

Work in progress (WIP) tests are very useful in a variety of situations
including:

* While doing test-driven-development they can be used to add tests to a review
  while they are not yet working and will not cause test failures. They can be
  removed when the functionality is fixed in a later patch set.
* A common practice is to recreate bugs by exposing the broken behavior in a
  functional or unit test. To encapsulate the correct behavior in the test, the
  test will usually assert the correct outcome, which will break without a fix.
  Marking the test as WIP gives us the ability to capture the broken behavior
  in code if a fix isn't ready yet.

The :func:`keystone.tests.unit.utils.wip` decorator can be used to mark a test
as WIP. A WIP test will always be run. If the test fails then a TestSkipped
exception is raised because we expect the test to fail. We do not pass
the test in this case so that it doesn't count toward the number of
successfully run tests. If the test passes an AssertionError exception is
raised so that the developer knows they made the test pass. This is a
reminder to remove the decorator.

The :func:`keystone.tests.unit.utils.wip` decorator requires that the author
provides a message. This message is important because it will tell other
developers why this test is marked as a work in progress. Reviewers will
require that these messages are descriptive and accurate.

.. NOTE::
    The :func:`keystone.tests.unit.utils.wip` decorator is not a replacement
    for skipping tests.

.. code-block:: python

    @wip('waiting on bug #000000')
    def test():
        pass

.. NOTE::
   Another strategy is to not use the wip decorator and instead show how the
   code currently incorrectly works. Which strategy is chosen is up to the
   developer.

API & Scenario Tests
--------------------

Keystone provides API and scenario tests via a `tempest plugin`_ which is
located in a separate `repository`_. This tempest plugin is mainly intended for
specific scenarios that require a special deployment, such as the tests for the
``Federated Identity`` feature or live testing against LDAP. For the deployment
of these scenarios, keystone also provides a `devstack plugin`_.

For example, to setup a working federated environment, add the following lines
in your `devstack` `local.conf`` file:

.. code-block:: bash

    [[local|localrc]]
    enable_plugin keystone git://git.openstack.org/openstack/keystone
    enable_service keystone-saml2-federation

Clone and install keystone-tempest-plugin.

.. code-block:: bash

    git clone https://git.openstack.org/openstack/keystone-tempest-plugin
    sudo pip install ./keystone-tempest-plugin

Finally, to run keystone's API and scenario tests, deploy `tempest`_ with
`devstack`_ (using the configuration above) and then run the following command
from the tempest directory:

.. code-block:: bash

    tox -e all-plugin -- keystone_tempest_plugin

.. NOTE::
   Most of keystone's API tests are implemented in `tempest`_ and it is usually
   the correct place to add new tests.

.. _devstack: https://git.openstack.org/cgit/openstack-dev/devstack
.. _devstack plugin: https://docs.openstack.org/devstack/latest/plugins.html
.. _tempest: https://git.openstack.org/cgit/openstack/tempest
.. _tempest plugin: https://docs.openstack.org/tempest/latest/plugin.html
.. _repository: http://git.openstack.org/cgit/openstack/keystone-tempest-plugin

Writing new API & Scenario Tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When writing tests for the keystone tempest plugin, we should follow the
official tempest guidelines, details about the guidelines can be found at the
`tempest coding guide`_. There are also specific guides for the API and
scenario tests: `Tempest Field Guide to API tests`_ and
`Tempest Field Guide to Scenario tests`_.

The keystone tempest plugin also provides a base class. For most cases, the
tests should inherit from it:
:class:`keystone_tempest_plugin.tests.base.BaseIdentityTest`. This class
already setups the identity API version and is the container of all API
services clients.
New API services clients :mod:`keystone_tempest_plugin.services`
(which are used to communicate with the REST API from
the services) should also be added to this class. For example, below we have a
snippet from the tests at
:py:mod:`keystone_tempest_plugin.tests.api.identity.v3.test_identity_providers.py`.

.. code-block:: python

    class IdentityProvidersTest(base.BaseIdentityTest):

    ...

    def _create_idp(self, idp_id, idp_ref):
        idp = self.idps_client.create_identity_provider(
            idp_id, **idp_ref)['identity_provider']
        self.addCleanup(
            self.idps_client.delete_identity_provider, idp_id)
        return idp

    @decorators.idempotent_id('09450910-b816-4150-8513-a2fd4628a0c3')
    def test_identity_provider_create(self):
        idp_id = data_utils.rand_uuid_hex()
        idp_ref = fixtures.idp_ref()
        idp = self._create_idp(idp_id, idp_ref)

        # The identity provider is disabled by default
        idp_ref['enabled'] = False

        # The remote_ids attribute should be set to an empty list by default
        idp_ref['remote_ids'] = []

        self._assert_identity_provider_attributes(idp, idp_id, idp_ref)

The test class extends
:class:`keystone_tempest_plugin.tests.base.BaseIdentityTest`. Also, the
``_create_idp`` method calls keystone's API using the ``idps_client``,
which is an instance from.
:class:`keystone_tempest_plugin.tests.services.identity.v3.identity_providers_client.IdentityProvidersClient`.

Additionally, to illustrate the construction of a new test class, below we have
a snippet from the scenario test that checks the complete federated
authentication workflow (
:py:mod:`keystone_tempest_plugin.tests.scenario.test_federated_authentication.py`).
In the test setup, all of the needed resources are created using the API
service clients. Since it is a scenario test, it is common to need some
customized settings that will come from the environment (in this case, from
the devstack plugin) - these settings are collected in the ``_setup_settings``
method.

.. code-block:: python

    class TestSaml2EcpFederatedAuthentication(base.BaseIdentityTest):

    ...

    def _setup_settings(self):
        self.idp_id = CONF.fed_scenario.idp_id
        self.idp_url = CONF.fed_scenario.idp_ecp_url
        self.keystone_v3_endpoint = CONF.identity.uri_v3
        self.password = CONF.fed_scenario.idp_password
        self.protocol_id = CONF.fed_scenario.protocol_id
        self.username = CONF.fed_scenario.idp_username

    ...

    def setUp(self):
        super(TestSaml2EcpFederatedAuthentication, self).setUp()
        self._setup_settings()

        # Reset client's session to avoid getting garbage from another runs
        self.saml2_client.reset_session()

        # Setup identity provider, mapping and protocol
        self._setup_idp()
        self._setup_mapping()
        self._setup_protocol()

Finally, the tests perform the complete workflow of the feature, asserting
correctness in each step:

.. code-block:: python

    def _request_unscoped_token(self):
        resp = self.saml2_client.send_service_provider_request(
            self.keystone_v3_endpoint, self.idp_id, self.protocol_id)
        self.assertEqual(http_client.OK, resp.status_code)
        saml2_authn_request = etree.XML(resp.content)

        relay_state = self._str_from_xml(
            saml2_authn_request, self.ECP_RELAY_STATE)
        sp_consumer_url = self._str_from_xml(
            saml2_authn_request, self.ECP_SERVICE_PROVIDER_CONSUMER_URL)

        # Perform the authn request to the identity provider
        resp = self.saml2_client.send_identity_provider_authn_request(
            saml2_authn_request, self.idp_url, self.username, self.password)
        self.assertEqual(http_client.OK, resp.status_code)
        saml2_idp_authn_response = etree.XML(resp.content)

        idp_consumer_url = self._str_from_xml(
            saml2_idp_authn_response, self.ECP_IDP_CONSUMER_URL)

        # Assert that both saml2_authn_request and saml2_idp_authn_response
        # have the same consumer URL.
        self.assertEqual(sp_consumer_url, idp_consumer_url)

        ...


    @testtools.skipUnless(CONF.identity_feature_enabled.federation,
                          "Federated Identity feature not enabled")
    def test_request_unscoped_token(self):
        self._request_unscoped_token()

Notice that the ``test_request_unscoped_token`` test only executes if the
``federation`` feature flag is enabled.

.. NOTE::
   For each patch submitted upstream, all of the tests from the keystone
   tempest plugin are executed in the
   ``gate-keystone-dsvm-functional-v3-only-*`` job.

.. _Tempest Field Guide to Scenario tests: https://docs.openstack.org/tempest/latest/field_guide/scenario.html
.. _Tempest Field Guide to API tests: https://docs.openstack.org/tempest/latest/field_guide/api.html
.. _tempest coding guide: https://docs.openstack.org/tempest/latest/HACKING.html
