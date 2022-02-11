# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import atexit
import base64
import contextlib
import datetime
import functools
import hashlib
import json
import secrets

import ldap
import os
import shutil
import socket
import sys
import uuid

import fixtures
import flask
from flask import testing as flask_testing
import http.client
from oslo_config import fixture as config_fixture
from oslo_context import context as oslo_context
from oslo_context import fixture as oslo_ctx_fixture
from oslo_log import fixture as log_fixture
from oslo_log import log
from oslo_utils import timeutils
import testtools
from testtools import testcase

import keystone.api
from keystone.common import context
from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import sql
import keystone.conf
from keystone import exception
from keystone.identity.backends.ldap import common as ks_ldap
from keystone import notifications
from keystone.resource.backends import base as resource_base
from keystone.server.flask import application as flask_app
from keystone.server.flask import core as keystone_flask
from keystone.tests.unit import ksfixtures


keystone.conf.configure()
keystone.conf.set_config_defaults()

PID = str(os.getpid())
TESTSDIR = os.path.dirname(os.path.abspath(__file__))
TESTCONF = os.path.join(TESTSDIR, 'config_files')
ROOTDIR = os.path.normpath(os.path.join(TESTSDIR, '..', '..', '..'))
VENDOR = os.path.join(ROOTDIR, 'vendor')
ETCDIR = os.path.join(ROOTDIR, 'etc')


def _calc_tmpdir():
    env_val = os.environ.get('KEYSTONE_TEST_TEMP_DIR')
    if not env_val:
        return os.path.join(TESTSDIR, 'tmp', PID)
    return os.path.join(env_val, PID)


TMPDIR = _calc_tmpdir()

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs
log.register_options(CONF)

IN_MEM_DB_CONN_STRING = 'sqlite://'

# Strictly matches ISO 8601 timestamps with subsecond precision like:
# 2016-06-28T20:48:56.000000Z
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
TIME_FORMAT_REGEX = r'^\d{4}-[0-1]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d\.\d{6}Z$'

exception._FATAL_EXCEPTION_FORMAT_ERRORS = True
os.makedirs(TMPDIR)
atexit.register(shutil.rmtree, TMPDIR)


class dirs(object):
    @staticmethod
    def root(*p):
        return os.path.join(ROOTDIR, *p)

    @staticmethod
    def etc(*p):
        return os.path.join(ETCDIR, *p)

    @staticmethod
    def tests(*p):
        return os.path.join(TESTSDIR, *p)

    @staticmethod
    def tmp(*p):
        return os.path.join(TMPDIR, *p)

    @staticmethod
    def tests_conf(*p):
        return os.path.join(TESTCONF, *p)


@atexit.register
def remove_test_databases():
    db = dirs.tmp('test.db')
    if os.path.exists(db):
        os.unlink(db)
    pristine = dirs.tmp('test.db.pristine')
    if os.path.exists(pristine):
        os.unlink(pristine)


def skip_if_cache_disabled(*sections):
    """Skip a test if caching is disabled, this is a decorator.

    Caching can be disabled either globally or for a specific section.

    In the code fragment::

        @skip_if_cache_is_disabled('assignment', 'token')
        def test_method(*args):
            ...

    The method test_method would be skipped if caching is disabled globally via
    the `enabled` option in the `cache` section of the configuration or if
    the `caching` option is set to false in either `assignment` or `token`
    sections of the configuration.  This decorator can be used with no
    arguments to only check global caching.

    If a specified configuration section does not define the `caching` option,
    this decorator makes the caching enabled if `enabled` option in the `cache`
    section of the configuration is true.

    """
    def wrapper(f):
        @functools.wraps(f)
        def inner(*args, **kwargs):
            if not CONF.cache.enabled:
                raise testcase.TestSkipped('Cache globally disabled.')
            for s in sections:
                conf_sec = getattr(CONF, s, None)
                if conf_sec is not None:
                    if not getattr(conf_sec, 'caching', True):
                        raise testcase.TestSkipped('%s caching disabled.' % s)
            return f(*args, **kwargs)
        return inner
    return wrapper


def skip_if_cache_is_enabled(*sections):
    def wrapper(f):
        @functools.wraps(f)
        def inner(*args, **kwargs):
            if CONF.cache.enabled:
                for s in sections:
                    conf_sec = getattr(CONF, s, None)
                    if conf_sec is not None:
                        if getattr(conf_sec, 'caching', True):
                            raise testcase.TestSkipped('%s caching enabled.' %
                                                       s)
            return f(*args, **kwargs)
        return inner
    return wrapper


def skip_if_no_multiple_domains_support(f):
    """Decorator to skip tests for identity drivers limited to one domain."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        test_obj = args[0]
        if not test_obj.identity_api.multiple_domains_supported:
            raise testcase.TestSkipped('No multiple domains support')
        return f(*args, **kwargs)
    return wrapper


class UnexpectedExit(Exception):
    pass


def new_region_ref(parent_region_id=None, **kwargs):
    ref = {
        'id': uuid.uuid4().hex,
        'description': uuid.uuid4().hex,
        'parent_region_id': parent_region_id}

    ref.update(kwargs)
    return ref


def new_service_ref(**kwargs):
    ref = {
        'id': uuid.uuid4().hex,
        'name': uuid.uuid4().hex,
        'description': uuid.uuid4().hex,
        'enabled': True,
        'type': uuid.uuid4().hex,
    }
    ref.update(kwargs)
    return ref


NEEDS_REGION_ID = object()


def new_endpoint_ref(service_id, interface='public',
                     region_id=NEEDS_REGION_ID, **kwargs):

    ref = {
        'id': uuid.uuid4().hex,
        'name': uuid.uuid4().hex,
        'description': uuid.uuid4().hex,
        'interface': interface,
        'service_id': service_id,
        'url': 'https://' + uuid.uuid4().hex + '.com',
    }

    if region_id is NEEDS_REGION_ID:
        ref['region_id'] = uuid.uuid4().hex
    elif region_id is None and kwargs.get('region') is not None:
        # pre-3.2 form endpoints are not supported by this function
        raise NotImplementedError("use new_endpoint_ref_with_region")
    else:
        ref['region_id'] = region_id
    ref.update(kwargs)
    return ref


def new_endpoint_group_ref(filters, **kwargs):
    ref = {
        'id': uuid.uuid4().hex,
        'description': uuid.uuid4().hex,
        'filters': filters,
        'name': uuid.uuid4().hex
    }
    ref.update(kwargs)
    return ref


def new_endpoint_ref_with_region(service_id, region, interface='public',
                                 **kwargs):
    """Define an endpoint_ref having a pre-3.2 form.

    Contains the deprecated 'region' instead of 'region_id'.
    """
    ref = new_endpoint_ref(service_id, interface, region=region,
                           region_id='invalid', **kwargs)
    del ref['region_id']
    return ref


def new_domain_ref(**kwargs):
    ref = {
        'id': uuid.uuid4().hex,
        'name': uuid.uuid4().hex,
        'description': uuid.uuid4().hex,
        'enabled': True,
        'tags': [],
        'options': {}
    }
    ref.update(kwargs)
    return ref


def new_project_ref(domain_id=None, is_domain=False, **kwargs):
    ref = {
        'id': uuid.uuid4().hex,
        'name': uuid.uuid4().hex,
        'description': uuid.uuid4().hex,
        'enabled': True,
        'domain_id': domain_id,
        'is_domain': is_domain,
        'tags': [],
        'options': {}
    }
    # NOTE(henry-nash): We don't include parent_id in the initial list above
    # since specifying it is optional depending on where the project sits in
    # the hierarchy (and a parent_id of None has meaning - i.e. it's a top
    # level project).
    ref.update(kwargs)
    return ref


def new_user_ref(domain_id, project_id=None, **kwargs):
    ref = {
        'id': uuid.uuid4().hex,
        'name': uuid.uuid4().hex,
        'enabled': True,
        'domain_id': domain_id,
        'email': uuid.uuid4().hex,
        'password': uuid.uuid4().hex,
    }
    if project_id:
        ref['default_project_id'] = project_id
    ref.update(kwargs)
    return ref


def new_federated_user_ref(idp_id=None, protocol_id=None, **kwargs):
    ref = {
        'idp_id': idp_id or 'ORG_IDP',
        'protocol_id': protocol_id or 'saml2',
        'unique_id': uuid.uuid4().hex,
        'display_name': uuid.uuid4().hex,
    }
    ref.update(kwargs)
    return ref


def new_mapping_ref(mapping_id=None, rules=None, **kwargs):
    ref = {
        'id': mapping_id or uuid.uuid4().hex,
        'rules': rules or []
    }
    ref.update(kwargs)
    return ref


def new_protocol_ref(protocol_id=None, idp_id=None, mapping_id=None, **kwargs):
    ref = {
        'id': protocol_id or 'saml2',
        'idp_id': idp_id or 'ORG_IDP',
        'mapping_id': mapping_id or uuid.uuid4().hex
    }
    ref.update(kwargs)
    return ref


def new_identity_provider_ref(idp_id=None, **kwargs):
    ref = {
        'id': idp_id or 'ORG_IDP',
        'enabled': True,
        'description': '',
    }
    ref.update(kwargs)
    return ref


def new_service_provider_ref(**kwargs):
    ref = {
        'auth_url': 'https://' + uuid.uuid4().hex + '.com',
        'enabled': True,
        'description': uuid.uuid4().hex,
        'sp_url': 'https://' + uuid.uuid4().hex + '.com',
        'relay_state_prefix': CONF.saml.relay_state_prefix
    }
    ref.update(kwargs)
    return ref


def new_group_ref(domain_id, **kwargs):
    ref = {
        'id': uuid.uuid4().hex,
        'name': uuid.uuid4().hex,
        'description': uuid.uuid4().hex,
        'domain_id': domain_id
    }
    ref.update(kwargs)
    return ref


def new_credential_ref(user_id, project_id=None, type='cert', **kwargs):
    ref = {
        'id': uuid.uuid4().hex,
        'user_id': user_id,
        'type': type,
    }

    if project_id:
        ref['project_id'] = project_id
    if 'blob' not in kwargs:
        ref['blob'] = uuid.uuid4().hex

    ref.update(kwargs)
    return ref


def new_cert_credential(user_id, project_id=None, blob=None, **kwargs):
    if blob is None:
        blob = {'access': uuid.uuid4().hex, 'secret': uuid.uuid4().hex}

    credential = new_credential_ref(user_id=user_id,
                                    project_id=project_id,
                                    blob=json.dumps(blob),
                                    type='cert',
                                    **kwargs)
    return blob, credential


def new_ec2_credential(user_id, project_id=None, blob=None, **kwargs):
    if blob is None:
        blob = {
            'access': uuid.uuid4().hex,
            'secret': uuid.uuid4().hex,
            'trust_id': None
        }

    if 'id' not in kwargs:
        access = blob['access'].encode('utf-8')
        kwargs['id'] = hashlib.sha256(access).hexdigest()

    credential = new_credential_ref(user_id=user_id,
                                    project_id=project_id,
                                    blob=json.dumps(blob),
                                    type='ec2',
                                    **kwargs)
    return blob, credential


def new_totp_credential(user_id, project_id=None, blob=None):
    if not blob:
        # NOTE(notmorgan): 20 bytes of data from secrets.token_bytes for
        # a totp secret.
        blob = base64.b32encode(secrets.token_bytes(20)).decode('utf-8')
    credential = new_credential_ref(user_id=user_id,
                                    project_id=project_id,
                                    blob=blob,
                                    type='totp')
    return credential


def new_application_credential_ref(roles=None,
                                   name=None,
                                   expires=None,
                                   secret=None):
    ref = {
        'id': uuid.uuid4().hex,
        'name': uuid.uuid4().hex,
        'description': uuid.uuid4().hex,
    }
    if roles:
        ref['roles'] = roles
    if secret:
        ref['secret'] = secret

    if isinstance(expires, str):
        ref['expires_at'] = expires
    elif isinstance(expires, dict):
        ref['expires_at'] = (
            timeutils.utcnow() + datetime.timedelta(**expires)
        ).strftime(TIME_FORMAT)
    elif expires is None:
        pass
    else:
        raise NotImplementedError('Unexpected value for "expires"')

    return ref


def new_role_ref(**kwargs):
    ref = {
        'id': uuid.uuid4().hex,
        'name': uuid.uuid4().hex,
        'description': uuid.uuid4().hex,
        'domain_id': None,
        'options': {},
    }
    ref.update(kwargs)
    return ref


def new_policy_ref(**kwargs):
    ref = {
        'id': uuid.uuid4().hex,
        'name': uuid.uuid4().hex,
        'description': uuid.uuid4().hex,
        'enabled': True,
        # Store serialized JSON data as the blob to mimic real world usage.
        'blob': json.dumps({'data': uuid.uuid4().hex, }),
        'type': uuid.uuid4().hex,
    }

    ref.update(kwargs)
    return ref


def new_domain_config_ref(**kwargs):
    ref = {
        "identity": {
            "driver": "ldap"
        },
        "ldap": {
            "url": "ldap://myldap.com:389/",
            "user_tree_dn": "ou=Users,dc=my_new_root,dc=org"
        }
    }
    ref.update(kwargs)
    return ref


def new_trust_ref(trustor_user_id, trustee_user_id, project_id=None,
                  impersonation=None, expires=None, role_ids=None,
                  role_names=None, remaining_uses=None,
                  allow_redelegation=False, redelegation_count=None, **kwargs):
    ref = {
        'id': uuid.uuid4().hex,
        'trustor_user_id': trustor_user_id,
        'trustee_user_id': trustee_user_id,
        'impersonation': impersonation or False,
        'project_id': project_id,
        'remaining_uses': remaining_uses,
        'allow_redelegation': allow_redelegation,
    }

    if isinstance(redelegation_count, int):
        ref.update(redelegation_count=redelegation_count)

    if isinstance(expires, str):
        ref['expires_at'] = expires
    elif isinstance(expires, dict):
        ref['expires_at'] = (
            timeutils.utcnow() + datetime.timedelta(**expires)
        ).strftime(TIME_FORMAT)
    elif expires is None:
        pass
    else:
        raise NotImplementedError('Unexpected value for "expires"')

    role_ids = role_ids or []
    role_names = role_names or []
    if role_ids or role_names:
        ref['roles'] = []
        for role_id in role_ids:
            ref['roles'].append({'id': role_id})
        for role_name in role_names:
            ref['roles'].append({'name': role_name})

    ref.update(kwargs)
    return ref


def new_registered_limit_ref(**kwargs):
    ref = {
        'service_id': uuid.uuid4().hex,
        'resource_name': uuid.uuid4().hex,
        'default_limit': 10,
        'description': uuid.uuid4().hex
    }

    ref.update(kwargs)
    return ref


def new_limit_ref(**kwargs):
    ref = {
        'service_id': uuid.uuid4().hex,
        'resource_name': uuid.uuid4().hex,
        'resource_limit': 10,
        'description': uuid.uuid4().hex
    }

    ref.update(kwargs)
    return ref


def create_user(api, domain_id, **kwargs):
    """Create a user via the API. Keep the created password.

    The password is saved and restored when api.create_user() is called.
    Only use this routine if there is a requirement for the user object to
    have a valid password after api.create_user() is called.
    """
    user = new_user_ref(domain_id=domain_id, **kwargs)
    password = user['password']
    user = api.create_user(user)
    user['password'] = password
    return user


def _assert_expected_status(f):
    """Add `expected_status_code` as an argument to the test_client methods.

    `expected_status_code` must be passed as a kwarg.
    """
    TEAPOT_HTTP_STATUS = 418

    _default_expected_responses = {
        'get': http.client.OK,
        'head': http.client.OK,
        'post': http.client.CREATED,
        'put': http.client.NO_CONTENT,
        'patch': http.client.OK,
        'delete': http.client.NO_CONTENT,
    }

    @functools.wraps(f)
    def inner(*args, **kwargs):
        # Get the "expected_status_code" kwarg if supplied. If not supplied use
        # the `_default_expected_response` mapping, or fall through to
        # "HTTP OK" if the method is somehow unknown.
        expected_status_code = kwargs.pop(
            'expected_status_code',
            _default_expected_responses.get(
                f.__name__.lower(), http.client.OK))
        response = f(*args, **kwargs)

        # Logic to verify the response object is sane. Expand as needed
        if response.status_code == TEAPOT_HTTP_STATUS:
            # NOTE(morgan): We use 418 internally during tests to indicate
            # an un-routed HTTP call was made. This allows us to avoid
            # misinterpreting HTTP 404 from Flask and HTTP 404 from a
            # resource that is not found (e.g. USER NOT FOUND) programmatically
            raise AssertionError("I AM A TEAPOT(418): %s" % response.data)

        if response.status_code != expected_status_code:
            raise AssertionError(
                'Expected HTTP Status does not match observed HTTP '
                'Status: %(expected)s != %(observed)s (%(data)s)' % {
                    'expected': expected_status_code,
                    'observed': response.status_code,
                    'data': response.data})

        # return the original response object
        return response
    return inner


class KeystoneFlaskTestClient(flask_testing.FlaskClient):
    """Subclass of flask.testing.FlaskClient implementing assertions.

    Implements custom "expected" HTTP Status assertion for
    GET/HEAD/PUT/PATCH/DELETE.
    """

    @_assert_expected_status
    def get(self, *args, **kwargs):
        return super(KeystoneFlaskTestClient, self).get(*args, **kwargs)

    @_assert_expected_status
    def head(self, *args, **kwargs):
        return super(KeystoneFlaskTestClient, self).head(*args, **kwargs)

    @_assert_expected_status
    def post(self, *args, **kwargs):
        return super(KeystoneFlaskTestClient, self).post(*args, **kwargs)

    @_assert_expected_status
    def patch(self, *args, **kwargs):
        return super(KeystoneFlaskTestClient, self).patch(*args, **kwargs)

    @_assert_expected_status
    def put(self, *args, **kwargs):
        return super(KeystoneFlaskTestClient, self).put(*args, **kwargs)

    @_assert_expected_status
    def delete(self, *args, **kwargs):
        return super(KeystoneFlaskTestClient, self).delete(*args, **kwargs)


class BaseTestCase(testtools.TestCase):
    """Light weight base test class.

    This is a placeholder that will eventually go away once the
    setup/teardown in TestCase is properly trimmed down to the bare
    essentials. This is really just a play to speed up the tests by
    eliminating unnecessary work.
    """

    def setUp(self):
        super(BaseTestCase, self).setUp()

        self.useFixture(fixtures.NestedTempfile())
        self.useFixture(fixtures.TempHomeDir())

        self.useFixture(fixtures.MockPatchObject(sys, 'exit',
                                                 side_effect=UnexpectedExit))
        self.useFixture(log_fixture.get_logging_handle_error_fixture())
        self.stdlog = self.useFixture(ksfixtures.StandardLogging())
        self.useFixture(ksfixtures.WarningsFixture())

        # Ensure we have an empty threadlocal context at the start of each
        # test.
        self.assertIsNone(oslo_context.get_current())
        self.useFixture(oslo_ctx_fixture.ClearRequestContext())

        orig_debug_level = ldap.get_option(ldap.OPT_DEBUG_LEVEL)
        self.addCleanup(ldap.set_option, ldap.OPT_DEBUG_LEVEL,
                        orig_debug_level)
        orig_tls_cacertfile = ldap.get_option(ldap.OPT_X_TLS_CACERTFILE)
        if orig_tls_cacertfile is None:
            orig_tls_cacertfile = ''
        self.addCleanup(ldap.set_option, ldap.OPT_X_TLS_CACERTFILE,
                        orig_tls_cacertfile)
        orig_tls_cacertdir = ldap.get_option(ldap.OPT_X_TLS_CACERTDIR)
        # Setting orig_tls_cacertdir to None is not allowed.
        if orig_tls_cacertdir is None:
            orig_tls_cacertdir = ''
        self.addCleanup(ldap.set_option, ldap.OPT_X_TLS_CACERTDIR,
                        orig_tls_cacertdir)
        orig_tls_require_cert = ldap.get_option(ldap.OPT_X_TLS_REQUIRE_CERT)
        self.addCleanup(ldap.set_option, ldap.OPT_X_TLS_REQUIRE_CERT,
                        orig_tls_require_cert)
        self.addCleanup(ks_ldap.PooledLDAPHandler.connection_pools.clear)

    def cleanup_instance(self, *names):
        """Create a function suitable for use with self.addCleanup.

        :returns: a callable that uses a closure to delete instance attributes

        """
        def cleanup():
            for name in names:
                # TODO(dstanek): remove this 'if' statement once
                # load_backend in test_backend_ldap is only called once
                # per test
                if hasattr(self, name):
                    delattr(self, name)
        return cleanup

    def skip_if_env_not_set(self, env_var):
        if not os.environ.get(env_var):
            self.skipTest('Env variable %s is not set.' % env_var)

    def skip_test_overrides(self, *args, **kwargs):
        if self._check_for_method_in_parents(self._testMethodName):
            return super(BaseTestCase, self).skipTest(*args, **kwargs)
        raise Exception('%r is not a previously defined test method'
                        % self._testMethodName)

    def _check_for_method_in_parents(self, name):
        # skip first to get to parents
        for cls in self.__class__.__mro__[1:]:
            if hasattr(cls, name):
                return True
        return False

    def loadapp(self, name='public'):
        app = flask_app.application_factory(name)
        app.testing = True
        app.test_client_class = KeystoneFlaskTestClient

        # NOTE(morgan): any unexpected 404s, not handled by the routed apis,
        # is a hard error and should not pass testing.
        def page_not_found_teapot(e):
            content = (
                'TEST PROGRAMMING ERROR - Reached a 404 from an unrouted (`%s`'
                ') path. Be sure the test is requesting the right resource '
                'and that all blueprints are registered with the flask app.' %
                flask.request.url)
            return content, 418

        app.register_error_handler(404, page_not_found_teapot)

        self.test_client = app.test_client
        self.test_request_context = app.test_request_context
        self.cleanup_instance('test_request_context')
        self.cleanup_instance('test_client')
        return keystone_flask.setup_app_middleware(app)


class TestCase(BaseTestCase):

    def config_files(self):
        return []

    def _policy_fixture(self):
        return ksfixtures.Policy(self.config_fixture)

    @contextlib.contextmanager
    def make_request(self, path='/', **kwargs):
        # standup a fake app and request context with a passed in/known
        # environment.

        is_admin = kwargs.pop('is_admin', False)
        environ = kwargs.setdefault('environ', {})
        query_string = kwargs.pop('query_string', None)
        if query_string:
            # Make sure query string is properly added to the context
            path = '{path}?{qs}'.format(path=path, qs=query_string)

        if not environ.get(context.REQUEST_CONTEXT_ENV):
            environ[context.REQUEST_CONTEXT_ENV] = context.RequestContext(
                is_admin=is_admin,
                authenticated=kwargs.pop('authenticated', True))

        # Create a dummy flask app to work with
        app = flask.Flask(__name__)
        with app.test_request_context(path=path, environ_overrides=environ):
            yield

    def config_overrides(self):
        # NOTE(morganfainberg): enforce config_overrides can only ever be
        # called a single time.
        assert self.__config_overrides_called is False
        self.__config_overrides_called = True

        signing_certfile = 'examples/pki/certs/signing_cert.pem'
        signing_keyfile = 'examples/pki/private/signing_key.pem'

        self.useFixture(self._policy_fixture())

        self.config_fixture.config(
            # TODO(morganfainberg): Make Cache Testing a separate test case
            # in tempest, and move it out of the base unit tests.
            group='cache',
            backend='dogpile.cache.memory',
            enabled=True,
            proxies=['oslo_cache.testing.CacheIsolatingProxy'])
        self.config_fixture.config(
            group='catalog',
            driver='sql',
            template_file=dirs.tests('default_catalog.templates'))
        self.config_fixture.config(
            group='saml', certfile=signing_certfile, keyfile=signing_keyfile)
        self.config_fixture.config(
            default_log_levels=[
                'amqp=WARN',
                'amqplib=WARN',
                'boto=WARN',
                'qpid=WARN',
                'sqlalchemy=WARN',
                'suds=INFO',
                'oslo.messaging=INFO',
                'iso8601=WARN',
                'requests.packages.urllib3.connectionpool=WARN',
                'routes.middleware=INFO',
                'stevedore.extension=INFO',
                'keystone.notifications=INFO',
                'keystone.identity.backends.ldap.common=INFO',
            ])
        # NOTE(notmorgan): Set password rounds low here to ensure speedy
        # tests. This is explicitly set because the tests here are not testing
        # the integrity of the password hashing, just that the correct form
        # of hashing has been used. Note that 4 is the lowest for bcrypt
        # allowed in the `[identity] password_hash_rounds` setting
        self.config_fixture.config(group='identity', password_hash_rounds=4)

        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )

        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_receipts',
                CONF.fernet_receipts.max_active_keys
            )
        )

    def _assert_config_overrides_called(self):
        assert self.__config_overrides_called is True

    def setUp(self):
        super(TestCase, self).setUp()
        self.__config_overrides_called = False
        self.__load_backends_called = False
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.addCleanup(delattr, self, 'config_fixture')
        self.config(self.config_files())

        # NOTE(morganfainberg): mock the auth plugin setup to use the config
        # fixture which automatically unregisters options when performing
        # cleanup.
        def mocked_register_auth_plugin_opt(conf, opt):
            self.config_fixture.register_opt(opt, group='auth')
        self.useFixture(fixtures.MockPatchObject(
            keystone.conf.auth, '_register_auth_plugin_opt',
            new=mocked_register_auth_plugin_opt))

        self.config_overrides()
        # explicitly load auth configuration
        keystone.conf.auth.setup_authentication()
        # NOTE(morganfainberg): ensure config_overrides has been called.
        self.addCleanup(self._assert_config_overrides_called)

        self.useFixture(fixtures.FakeLogger(level=log.DEBUG))

        # NOTE(morganfainberg): This code is a copy from the oslo-incubator
        # log module. This is not in a function or otherwise available to use
        # without having a CONF object to setup logging. This should help to
        # reduce the log size by limiting what we log (similar to how Keystone
        # would run under mod_wsgi).
        for pair in CONF.default_log_levels:
            mod, _sep, level_name = pair.partition('=')
            logger = log.getLogger(mod)
            logger.logger.setLevel(level_name)

        self.useFixture(ksfixtures.Cache())

        # Clear the registry of providers so that providers from previous
        # tests aren't used.
        self.addCleanup(provider_api.ProviderAPIs._clear_registry_instances)

        # Clear the registry of JSON Home Resources
        self.addCleanup(json_home.JsonHomeResources._reset)

        # Ensure Notification subscriptions and resource types are empty
        self.addCleanup(notifications.clear_subscribers)
        self.addCleanup(notifications.reset_notifier)

    def config(self, config_files):
        sql.initialize()
        CONF(args=[], project='keystone', default_config_files=config_files)

    def load_backends(self):
        """Initialize each manager and assigns them to an attribute."""
        # TODO(morgan): Ensure our tests only ever call load_backends
        # a single time via this method. for now just clear the registry
        # if we are reloading.
        provider_api.ProviderAPIs._clear_registry_instances()
        self.useFixture(ksfixtures.BackendLoader(self))

    def load_fixtures(self, fixtures):
        """Hacky basic and naive fixture loading based on a python module.

        Expects that the various APIs into the various services are already
        defined on `self`.

        """
        # NOTE(dstanek): create a list of attribute names to be removed
        # from this instance during cleanup
        fixtures_to_cleanup = []

        # TODO(termie): doing something from json, probably based on Django's
        #               loaddata will be much preferred.
        if (hasattr(self, 'identity_api') and
            hasattr(self, 'assignment_api') and
                hasattr(self, 'resource_api')):
            try:
                PROVIDERS.resource_api.create_domain(
                    resource_base.NULL_DOMAIN_ID, fixtures.ROOT_DOMAIN)
            except exception.Conflict:
                # the root domain already exists, skip now.
                pass
            for domain in fixtures.DOMAINS:
                rv = PROVIDERS.resource_api.create_domain(domain['id'], domain)
                attrname = 'domain_%s' % domain['id']
                setattr(self, attrname, rv)
                fixtures_to_cleanup.append(attrname)

            for project in fixtures.PROJECTS:
                project_attr_name = 'project_%s' % project['name'].lower()
                rv = PROVIDERS.resource_api.create_project(
                    project['id'], project)
                setattr(self, project_attr_name, rv)
                fixtures_to_cleanup.append(project_attr_name)

            for role in fixtures.ROLES:
                rv = PROVIDERS.role_api.create_role(role['id'], role)
                attrname = 'role_%s' % role['name']
                setattr(self, attrname, rv)
                fixtures_to_cleanup.append(attrname)

            for user in fixtures.USERS:
                user_copy = user.copy()
                projects = user_copy.pop('projects')

                # For users, the manager layer will generate the ID
                user_copy = PROVIDERS.identity_api.create_user(user_copy)
                # Our tests expect that the password is still in the user
                # record so that they can reference it, so put it back into
                # the dict returned.
                user_copy['password'] = user['password']

                # fixtures.ROLES[2] is the _member_ role.
                for project_id in projects:
                    PROVIDERS.assignment_api.add_role_to_user_and_project(
                        user_copy['id'], project_id, fixtures.ROLES[2]['id'])

                # Use the ID from the fixture as the attribute name, so
                # that our tests can easily reference each user dict, while
                # the ID in the dict will be the real public ID.
                attrname = 'user_%s' % user['name']
                setattr(self, attrname, user_copy)
                fixtures_to_cleanup.append(attrname)

            for role_assignment in fixtures.ROLE_ASSIGNMENTS:
                role_id = role_assignment['role_id']
                user = role_assignment['user']
                project_id = role_assignment['project_id']
                user_id = getattr(self, 'user_%s' % user)['id']
                PROVIDERS.assignment_api.add_role_to_user_and_project(
                    user_id, project_id, role_id)

            self.addCleanup(self.cleanup_instance(*fixtures_to_cleanup))

    def assertCloseEnoughForGovernmentWork(self, a, b, delta=3):
        """Assert that two datetimes are nearly equal within a small delta.

        :param delta: Maximum allowable time delta, defined in seconds.
        """
        if a == b:
            # Short-circuit if the values are the same.
            return

        msg = '%s != %s within %s delta' % (a, b, delta)

        self.assertLessEqual(abs(a - b).seconds, delta, msg)

    def assertTimestampEqual(self, expected, value):
        # Compare two timestamps but ignore the microseconds part
        # of the expected timestamp. Keystone does not track microseconds and
        # is working to eliminate microseconds from it's datetimes used.
        expected = timeutils.parse_isotime(expected).replace(microsecond=0)
        value = timeutils.parse_isotime(value).replace(microsecond=0)
        self.assertEqual(
            expected,
            value,
            "%s != %s" % (expected, value))

    def assertNotEmpty(self, iterable):
        self.assertGreater(len(iterable), 0)

    def assertUserDictEqual(self, expected, observed, message=''):
        """Assert that a user dict is equal to another user dict.

        User dictionaries have some variable values that should be ignored in
        the comparison. This method is a helper that strips those elements out
        when comparing the user dictionary. This normalized these differences
        that should not change the comparison.
        """
        # NOTE(notmorgan): An empty option list is the same as no options being
        # specified in the user_ref. This removes options if it is empty in
        # observed if options is not specified in the expected value.
        if ('options' in observed and not observed['options'] and
                'options' not in expected):
            observed = observed.copy()
            del observed['options']

        self.assertDictEqual(expected, observed, message)

    @property
    def ipv6_enabled(self):
        if socket.has_ipv6:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET6)
                # NOTE(Mouad): Try to bind to IPv6 loopback ip address.
                sock.bind(("::1", 0))
                return True
            except socket.error:
                pass
            finally:
                if sock:
                    sock.close()
        return False

    def skip_if_no_ipv6(self):
        if not self.ipv6_enabled:
            raise self.skipTest("IPv6 is not enabled in the system")


class SQLDriverOverrides(object):
    """A mixin for consolidating sql-specific test overrides."""

    def config_overrides(self):
        super(SQLDriverOverrides, self).config_overrides()
        # SQL specific driver overrides
        self.config_fixture.config(group='catalog', driver='sql')
        self.config_fixture.config(group='identity', driver='sql')
        self.config_fixture.config(group='policy', driver='sql')
        self.config_fixture.config(group='trust', driver='sql')
