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

from __future__ import absolute_import
import atexit
import functools
import logging
import os
import re
import shutil
import socket
import sys
import warnings

import fixtures
from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslo_log import log
import oslotest.base as oslotest
from oslotest import mockpatch
import six
from sqlalchemy import exc
from testtools import testcase
import webob

# NOTE(ayoung)
# environment.use_eventlet must run before any of the code that will
# call the eventlet monkeypatching.
from keystone.common import environment  # noqa
environment.use_eventlet()

from keystone import auth
from keystone.common import config as common_cfg
from keystone.common import dependency
from keystone.common import kvs
from keystone.common.kvs import core as kvs_core
from keystone import config
from keystone import controllers
from keystone import exception
from keystone import notifications
from keystone.policy.backends import rules
from keystone.server import common
from keystone import service
from keystone.tests.unit import ksfixtures


config.configure()

LOG = log.getLogger(__name__)
PID = six.text_type(os.getpid())
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

CONF = cfg.CONF
log.register_options(CONF)
rules.init()

IN_MEM_DB_CONN_STRING = 'sqlite://'

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


# keystone.common.sql.initialize() for testing.
DEFAULT_TEST_DB_FILE = dirs.tmp('test.db')


@atexit.register
def remove_test_databases():
    db = dirs.tmp('test.db')
    if os.path.exists(db):
        os.unlink(db)
    pristine = dirs.tmp('test.db.pristine')
    if os.path.exists(pristine):
        os.unlink(pristine)


def generate_paste_config(extension_name):
    # Generate a file, based on keystone-paste.ini, that is named:
    # extension_name.ini, and includes extension_name in the pipeline
    with open(dirs.etc('keystone-paste.ini'), 'r') as f:
        contents = f.read()

    new_contents = contents.replace(' service_v3',
                                    ' %s service_v3' % (extension_name))

    new_paste_file = dirs.tmp(extension_name + '.ini')
    with open(new_paste_file, 'w') as f:
        f.write(new_contents)

    return new_paste_file


def remove_generated_paste_config(extension_name):
    # Remove the generated paste config file, named extension_name.ini
    paste_file_to_remove = dirs.tmp(extension_name + '.ini')
    os.remove(paste_file_to_remove)


def skip_if_cache_disabled(*sections):
    """This decorator is used to skip a test if caching is disabled either
    globally or for the specific section.

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
    this decorator makes the same assumption as the `should_cache_fn` in
    keystone.common.cache that caching should be enabled.
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


def skip_if_no_multiple_domains_support(f):
    """This decorator is used to skip a test if an identity driver
    does not support multiple domains.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        test_obj = args[0]
        if not test_obj.identity_api.multiple_domains_supported:
            raise testcase.TestSkipped('No multiple domains support')
        return f(*args, **kwargs)
    return wrapper


class UnexpectedExit(Exception):
    pass


class BadLog(Exception):
    """Raised on invalid call to logging (parameter mismatch)."""
    pass


class TestClient(object):
    def __init__(self, app=None, token=None):
        self.app = app
        self.token = token

    def request(self, method, path, headers=None, body=None):
        if headers is None:
            headers = {}

        if self.token:
            headers.setdefault('X-Auth-Token', self.token)

        req = webob.Request.blank(path)
        req.method = method
        for k, v in six.iteritems(headers):
            req.headers[k] = v
        if body:
            req.body = body
        return req.get_response(self.app)

    def get(self, path, headers=None):
        return self.request('GET', path=path, headers=headers)

    def post(self, path, headers=None, body=None):
        return self.request('POST', path=path, headers=headers, body=body)

    def put(self, path, headers=None, body=None):
        return self.request('PUT', path=path, headers=headers, body=body)


class BaseTestCase(oslotest.BaseTestCase):
    """Light weight base test class.

    This is a placeholder that will eventually go away once the
    setup/teardown in TestCase is properly trimmed down to the bare
    essentials. This is really just a play to speed up the tests by
    eliminating unnecessary work.
    """

    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.useFixture(mockpatch.PatchObject(sys, 'exit',
                                              side_effect=UnexpectedExit))

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


@dependency.requires('revoke_api')
class TestCase(BaseTestCase):

    def config_files(self):
        return []

    def config_overrides(self):
        signing_certfile = 'examples/pki/certs/signing_cert.pem'
        signing_keyfile = 'examples/pki/private/signing_key.pem'
        self.config_fixture.config(group='oslo_policy',
                                   policy_file=dirs.etc('policy.json'))
        self.config_fixture.config(
            # TODO(morganfainberg): Make Cache Testing a separate test case
            # in tempest, and move it out of the base unit tests.
            group='cache',
            backend='dogpile.cache.memory',
            enabled=True,
            proxies=['keystone.tests.unit.test_cache.CacheIsolatingProxy'])
        self.config_fixture.config(
            group='catalog',
            driver='keystone.catalog.backends.templated.Catalog',
            template_file=dirs.tests('default_catalog.templates'))
        self.config_fixture.config(
            group='identity',
            driver='keystone.identity.backends.sql.Identity')
        self.config_fixture.config(
            group='kvs',
            backends=[
                ('keystone.tests.unit.test_kvs.'
                 'KVSBackendForcedKeyMangleFixture'),
                'keystone.tests.unit.test_kvs.KVSBackendFixture'])
        self.config_fixture.config(
            group='revoke',
            driver='keystone.contrib.revoke.backends.kvs.Revoke')
        self.config_fixture.config(
            group='signing', certfile=signing_certfile,
            keyfile=signing_keyfile,
            ca_certs='examples/pki/certs/cacert.pem')
        self.config_fixture.config(
            group='token',
            driver='keystone.token.persistence.backends.kvs.Token')
        self.config_fixture.config(
            group='trust',
            driver='keystone.trust.backends.sql.Trust')
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
                'keystone.common._memcache_pool=INFO',
                'keystone.common.ldap=INFO',
            ])
        self.auth_plugin_config_override()

    def auth_plugin_config_override(self, methods=None, **method_classes):
        if methods is None:
            methods = ['external', 'password', 'token', ]
            if not method_classes:
                method_classes = dict(
                    external='keystone.auth.plugins.external.DefaultDomain',
                    password='keystone.auth.plugins.password.Password',
                    token='keystone.auth.plugins.token.Token',
                )
        self.config_fixture.config(group='auth', methods=methods)
        common_cfg.setup_authentication()
        if method_classes:
            self.config_fixture.config(group='auth', **method_classes)

    def setUp(self):
        super(TestCase, self).setUp()
        self.addCleanup(self.cleanup_instance('config_fixture', 'logger'))

        self.addCleanup(CONF.reset)

        self.useFixture(mockpatch.PatchObject(logging.Handler, 'handleError',
                                              side_effect=BadLog))
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.config(self.config_files())

        # NOTE(morganfainberg): mock the auth plugin setup to use the config
        # fixture which automatically unregisters options when performing
        # cleanup.
        def mocked_register_auth_plugin_opt(conf, opt):
            self.config_fixture.register_opt(opt, group='auth')
        self.register_auth_plugin_opt_patch = self.useFixture(
            mockpatch.PatchObject(common_cfg, '_register_auth_plugin_opt',
                                  new=mocked_register_auth_plugin_opt))

        self.config_overrides()

        self.logger = self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))

        # NOTE(morganfainberg): This code is a copy from the oslo-incubator
        # log module. This is not in a function or otherwise available to use
        # without having a CONF object to setup logging. This should help to
        # reduce the log size by limiting what we log (similar to how Keystone
        # would run under mod_wsgi or eventlet).
        for pair in CONF.default_log_levels:
            mod, _sep, level_name = pair.partition('=')
            logger = logging.getLogger(mod)
            logger.setLevel(level_name)

        warnings.filterwarnings('error', category=DeprecationWarning,
                                module='^keystone\\.')
        warnings.simplefilter('error', exc.SAWarning)
        self.addCleanup(warnings.resetwarnings)

        self.useFixture(ksfixtures.Cache())

        # Clear the registry of providers so that providers from previous
        # tests aren't used.
        self.addCleanup(dependency.reset)

        self.addCleanup(kvs.INMEMDB.clear)

        # Ensure Notification subscriptions and resource types are empty
        self.addCleanup(notifications.clear_subscribers)
        self.addCleanup(notifications.reset_notifier)

        # Reset the auth-plugin registry
        self.addCleanup(self.clear_auth_plugin_registry)

        self.addCleanup(setattr, controllers, '_VERSIONS', [])

    def config(self, config_files):
        CONF(args=[], project='keystone', default_config_files=config_files)

    def load_backends(self):
        """Initializes each manager and assigns them to an attribute."""

        # TODO(blk-u): Shouldn't need to clear the registry here, but some
        # tests call load_backends multiple times. These should be fixed to
        # only call load_backends once.
        dependency.reset()

        # TODO(morganfainberg): Shouldn't need to clear the registry here, but
        # some tests call load_backends multiple times.  Since it is not
        # possible to re-configure a backend, we need to clear the list.  This
        # should eventually be removed once testing has been cleaned up.
        kvs_core.KEY_VALUE_STORE_REGISTRY.clear()

        self.clear_auth_plugin_registry()
        drivers, _unused = common.setup_backends(
            load_extra_backends_fn=self.load_extra_backends)

        for manager_name, manager in six.iteritems(drivers):
            setattr(self, manager_name, manager)
        self.addCleanup(self.cleanup_instance(*drivers.keys()))

    def load_extra_backends(self):
        """Override to load managers that aren't loaded by default.

        This is useful to load managers initialized by extensions. No extra
        backends are loaded by default.

        :return: dict of name -> manager
        """
        return {}

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
            for domain in fixtures.DOMAINS:
                try:
                    rv = self.resource_api.create_domain(domain['id'], domain)
                except exception.Conflict:
                    rv = self.resource_api.get_domain(domain['id'])
                except exception.NotImplemented:
                    rv = domain
                attrname = 'domain_%s' % domain['id']
                setattr(self, attrname, rv)
                fixtures_to_cleanup.append(attrname)

            for tenant in fixtures.TENANTS:
                if hasattr(self, 'tenant_%s' % tenant['id']):
                    try:
                        # This will clear out any roles on the project as well
                        self.resource_api.delete_project(tenant['id'])
                    except exception.ProjectNotFound:
                        pass
                rv = self.resource_api.create_project(
                    tenant['id'], tenant)

                attrname = 'tenant_%s' % tenant['id']
                setattr(self, attrname, rv)
                fixtures_to_cleanup.append(attrname)

            for role in fixtures.ROLES:
                try:
                    rv = self.role_api.create_role(role['id'], role)
                except exception.Conflict:
                    rv = self.role_api.get_role(role['id'])
                attrname = 'role_%s' % role['id']
                setattr(self, attrname, rv)
                fixtures_to_cleanup.append(attrname)

            for user in fixtures.USERS:
                user_copy = user.copy()
                tenants = user_copy.pop('tenants')
                try:
                    existing_user = getattr(self, 'user_%s' % user['id'], None)
                    if existing_user is not None:
                        self.identity_api.delete_user(existing_user['id'])
                except exception.UserNotFound:
                    pass

                # For users, the manager layer will generate the ID
                user_copy = self.identity_api.create_user(user_copy)
                # Our tests expect that the password is still in the user
                # record so that they can reference it, so put it back into
                # the dict returned.
                user_copy['password'] = user['password']

                for tenant_id in tenants:
                    try:
                        self.assignment_api.add_user_to_project(
                            tenant_id, user_copy['id'])
                    except exception.Conflict:
                        pass
                # Use the ID from the fixture as the attribute name, so
                # that our tests can easily reference each user dict, while
                # the ID in the dict will be the real public ID.
                attrname = 'user_%s' % user['id']
                setattr(self, attrname, user_copy)
                fixtures_to_cleanup.append(attrname)

            self.addCleanup(self.cleanup_instance(*fixtures_to_cleanup))

    def _paste_config(self, config):
        if not config.startswith('config:'):
            test_path = os.path.join(TESTSDIR, config)
            etc_path = os.path.join(ROOTDIR, 'etc', config)
            for path in [test_path, etc_path]:
                if os.path.exists('%s-paste.ini' % path):
                    return 'config:%s-paste.ini' % path
        return config

    def loadapp(self, config, name='main'):
        return service.loadapp(self._paste_config(config), name=name)

    def clear_auth_plugin_registry(self):
        auth.controllers.AUTH_METHODS.clear()
        auth.controllers.AUTH_PLUGINS_LOADED = False

    def assertCloseEnoughForGovernmentWork(self, a, b, delta=3):
        """Asserts that two datetimes are nearly equal within a small delta.

        :param delta: Maximum allowable time delta, defined in seconds.
        """
        msg = '%s != %s within %s delta' % (a, b, delta)

        self.assertTrue(abs(a - b).seconds <= delta, msg)

    def assertNotEmpty(self, l):
        self.assertTrue(len(l))

    def assertDictEqual(self, d1, d2, msg=None):
        self.assertIsInstance(d1, dict)
        self.assertIsInstance(d2, dict)
        self.assertEqual(d1, d2, msg)

    def assertRaisesRegexp(self, expected_exception, expected_regexp,
                           callable_obj, *args, **kwargs):
        """Asserts that the message in a raised exception matches a regexp.
        """
        try:
            callable_obj(*args, **kwargs)
        except expected_exception as exc_value:
            if isinstance(expected_regexp, six.string_types):
                expected_regexp = re.compile(expected_regexp)

            if isinstance(exc_value.args[0], unicode):
                if not expected_regexp.search(unicode(exc_value)):
                    raise self.failureException(
                        '"%s" does not match "%s"' %
                        (expected_regexp.pattern, unicode(exc_value)))
            else:
                if not expected_regexp.search(str(exc_value)):
                    raise self.failureException(
                        '"%s" does not match "%s"' %
                        (expected_regexp.pattern, str(exc_value)))
        else:
            if hasattr(expected_exception, '__name__'):
                excName = expected_exception.__name__
            else:
                excName = str(expected_exception)
            raise self.failureException("%s not raised" % excName)

    def assertDictContainsSubset(self, expected, actual, msg=None):
        """Checks whether actual is a superset of expected."""

        def safe_repr(obj, short=False):
            _MAX_LENGTH = 80
            try:
                result = repr(obj)
            except Exception:
                result = object.__repr__(obj)
            if not short or len(result) < _MAX_LENGTH:
                return result
            return result[:_MAX_LENGTH] + ' [truncated]...'

        missing = []
        mismatched = []
        for key, value in six.iteritems(expected):
            if key not in actual:
                missing.append(key)
            elif value != actual[key]:
                mismatched.append('%s, expected: %s, actual: %s' %
                                  (safe_repr(key), safe_repr(value),
                                   safe_repr(actual[key])))

        if not (missing or mismatched):
            return

        standardMsg = ''
        if missing:
            standardMsg = 'Missing: %s' % ','.join(safe_repr(m) for m in
                                                   missing)
        if mismatched:
            if standardMsg:
                standardMsg += '; '
            standardMsg += 'Mismatched values: %s' % ','.join(mismatched)

        self.fail(self._formatMessage(msg, standardMsg))

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

    def skip_if_env_not_set(self, env_var):
        if not os.environ.get(env_var):
            self.skipTest('Env variable %s is not set.' % env_var)


class SQLDriverOverrides(object):
    """A mixin for consolidating sql-specific test overrides."""
    def config_overrides(self):
        super(SQLDriverOverrides, self).config_overrides()
        # SQL specific driver overrides
        self.config_fixture.config(
            group='catalog',
            driver='keystone.catalog.backends.sql.Catalog')
        self.config_fixture.config(
            group='identity',
            driver='keystone.identity.backends.sql.Identity')
        self.config_fixture.config(
            group='policy',
            driver='keystone.policy.backends.sql.Policy')
        self.config_fixture.config(
            group='revoke',
            driver='keystone.contrib.revoke.backends.sql.Revoke')
        self.config_fixture.config(
            group='token',
            driver='keystone.token.persistence.backends.sql.Token')
        self.config_fixture.config(
            group='trust',
            driver='keystone.trust.backends.sql.Trust')
