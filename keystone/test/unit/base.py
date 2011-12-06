# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Base test case classes for the unit tests"""

import datetime
import functools
import httplib
import logging
import pprint
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__),
                                '..', '..', '..', '..', '..', 'keystone')))
import unittest2 as unittest

from lxml import etree, objectify
import webob

from keystone import server
import keystone.backends.sqlalchemy as db
import keystone.backends.api as db_api
from keystone import backends

logger = logging.getLogger('test.unit.base')


class ServiceAPITest(unittest.TestCase):

    """
    Base test case class for any unit test that tests the main service API.
    """

    """
    The `api` attribute for this base class is the `server.KeystoneAPI`
    controller.
    """
    api_class = server.ServiceApi

    """
    Set of dicts of tenant attributes we start each test case with
    """
    tenant_fixtures = [
        {'name': 'tenant1',
         'enabled': True,
         'desc': 'tenant1'}]

    """
    Attributes of the user the test creates for each test case that
    will authenticate against the API. The `auth_user` attribute
    will contain the created user with the following attributes.
    """
    auth_user_attrs = {'name': 'auth_user',
                       'password': 'auth_pass',
                       'email': 'auth_user@example.com',
                       'enabled': True,
                       'tenant_name': 'tenant1'}
    """
    Special attribute that is the identifier of the token we use in
    authenticating. Makes it easy to test the authentication process.
    """
    auth_token_id = 'SPECIALAUTHTOKEN'

    """
    Content-type of requests. Generally, you don't need to manually
    change this. Instead, :see test.unit.decorators
    """
    content_type = 'json'

    """
    Version of the API to test
    """
    api_version = '2.0'

    """
    Dict of configuration options to pass to the API controller
    """
    options = {
        'backends': "keystone.backends.sqlalchemy",
        'keystone.backends.sqlalchemy': {
            # in-memory db
            'sql_connection': 'sqlite://',
            'verbose': False,
            'debug': False,
            'backend_entities':
                "['UserRoleAssociation', 'Endpoints', 'Role', 'Tenant', "
                "'Tenant', 'User', 'Credentials', 'EndpointTemplates', "
                "'Token', 'Service']",
        },
        'keystone-admin-role': 'Admin',
        'keystone-service-admin-role': 'KeystoneServiceAdmin',
        'hash-password': 'True',
    }

    def setUp(self):
        self.api = self.api_class(self.options)

        dt = datetime
        self.expires = dt.datetime.utcnow() + dt.timedelta(days=1)
        self.clear_all_data()

        # Create all our base tenants
        for tenant in self.tenant_fixtures:
            self.fixture_create_tenant(**tenant)

        # Create the user we will authenticate with
        self.auth_user = self.fixture_create_user(**self.auth_user_attrs)
        self.auth_token = self.fixture_create_token(
            id=self.auth_token_id,
            user_id=self.auth_user['id'],
            tenant_id=self.auth_user['tenant_id'],
            expires=self.expires,
        )

        self.add_verify_status_helpers()

    def tearDown(self):
        self.clear_all_data()
        setattr(self, 'req', None)
        setattr(self, 'res', None)

    def clear_all_data(self):
        """
        Purges the database of all data
        """
        db.unregister_models()
        logger.debug("Cleared all data from database")
        opts = self.options
        reload(db)
        backends.configure_backends(opts)

    def fixture_create_credentials(self, **kwargs):
        """
        Creates a tenant fixture.

        :params \*\*kwargs: Attributes of the tenant to create
        """
        values = kwargs.copy()
        user = db_api.USER.get_by_name(values['user_name'])
        if user:
            values['user_id'] = user.id
            credentials = db_api.CREDENTIALS.create(values)
            logger.debug("Created credentials fixture %s",
                credentials['user_id'])
            return credentials

    def fixture_create_tenant(self, **kwargs):
        """
        Creates a tenant fixture.

        :params \*\*kwargs: Attributes of the tenant to create
        """
        values = kwargs.copy()
        tenant = db_api.TENANT.create(values)
        logger.debug("Created tenant fixture %s", values['name'])
        return tenant

    def fixture_create_user(self, **kwargs):
        """
        Creates a user fixture. If the user's tenant ID is set, and the tenant
        does not exist in the database, the tenant is created.

        :params \*\*kwargs: Attributes of the user to create
        """
        values = kwargs.copy()
        tenant_name = values.get('tenant_name')
        if tenant_name:
            if not db_api.TENANT.get_by_name(tenant_name):
                tenant = db_api.TENANT.create({'name': tenant_name,
                                      'enabled': True,
                                      'desc': tenant_name})
                values['tenant_id'] = tenant.id
        user = db_api.USER.create(values)
        logger.debug("Created user fixture %s", user.id)
        return user

    def fixture_create_token(self, **kwargs):
        """
        Creates a token fixture.

        :params \*\*kwargs: Attributes of the token to create
        """
        values = kwargs.copy()
        token = db_api.TOKEN.create(values)
        logger.debug("Created token fixture %s", values['id'])
        return token

    def get_request(self, method, url, headers=None):
        """
        Sets the `req` attribute to a `webob.Request` object that
        is constructed with the supplied method and url. Supplied
        headers are added to appropriate Content-type headers.
        """
        headers = headers or {}
        self.req = webob.Request.blank(url)
        self.req.method = method
        self.req.headers = headers
        if 'content-type' not in headers:
            ct = 'application/%s' % self.content_type
            self.req.headers['content-type'] = ct
            self.req.headers['accept'] = ct
        return self.req

    def get_response(self):
        """
        Sets the appropriate headers for the `req` attribute for
        the current content type, then calls `req.get_response()` and
        sets the `res` attribute to the returned `webob.Response` object
        """
        self.res = self.req.get_response(self.api)
        logger.debug("%s %s returned %s", self.req.method, self.req.path_qs,
                     self.res.status)
        if self.res.status_int != httplib.OK:
            logger.debug("Response Body:")
            for line in self.res.body.split("\n"):
                logger.debug(line)
        return self.res

    def verify_status(self, status_code):
        """
        Simple convenience wrapper for validating a response's status
        code.
        """
        if not getattr(self, 'res'):
            raise RuntimeError("Called verify_status() before calling "
                               "get_response()!")

        self.assertEqual(status_code, self.res.status_int,
                         "Incorrect status code %d. Expected %d" %
                         (self.res.status_int, status_code))

    def add_verify_status_helpers(self):
        """
        Adds some convenience helpers using partials...
        """
        self.status_ok = functools.partial(self.verify_status,
                                           httplib.OK)
        self.status_not_found = functools.partial(self.verify_status,
                                           httplib.NOT_FOUND)
        self.status_unauthorized = functools.partial(self.verify_status,
                                           httplib.UNAUTHORIZED)
        self.status_bad_request = functools.partial(self.verify_status,
                                           httplib.BAD_REQUEST)

    def assert_dict_equal(self, expected, got):
        """
        Compares two dicts for equality and prints the dictionaries
        nicely formatted for easy comparison if there is a failure.
        """
        self.assertEqual(expected, got, "Mappings are not equal.\n"
                         "Got:\n%s\nExpected:\n%s" %
                         (pprint.pformat(got),
                          pprint.pformat(expected)))

    def assert_xml_strings_equal(self, expected, got):
        """
        Compares two XML strings for equality by parsing them both
        into DOMs.  Prints the DOMs nicely formatted for easy comparison
        if there is a failure.
        """
        # This is a nice little trick... objectify.fromstring() returns
        # a DOM different from etree.fromstring(). The objectify version
        # removes any different whitespacing...
        got = objectify.fromstring(got)
        expected = objectify.fromstring(expected)
        self.assertEqual(etree.tostring(expected),
                         etree.tostring(got), "DOMs are not equal.\n"
                         "Got:\n%s\nExpected:\n%s" %
                         (etree.tostring(got, pretty_print=True),
                          etree.tostring(expected, pretty_print=True)))


class AdminAPITest(ServiceAPITest):

    """
    Base test case class for any unit test that tests the admin API. The
    """

    """
    The `api` attribute for this base class is the `server.KeystoneAdminAPI`
    controller.
    """
    api_class = server.AdminApi

    """
    Set of dicts of tenant attributes we start each test case with
    """
    tenant_fixtures = [
        {'id': 'tenant1',
         'enabled': True,
         'desc': 'tenant1'},
        {'id': 'tenant2',
         'enabled': True,
         'desc': 'tenant2'}]

    """
    Attributes of the user the test creates for each test case that
    will authenticate against the API.
    """
    auth_user_attrs = {'id': 'admin_user',
                       'password': 'admin_pass',
                       'email': 'admin_user@example.com',
                       'enabled': True,
                       'tenant_id': 'tenant2'}
