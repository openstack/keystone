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
import copy
import functools
import os
import re
import shutil
import socket
import sys
import time
import warnings

import fixtures
import logging
from paste import deploy
import six
import testtools
from testtools import testcase
import webob

from keystone.openstack.common.fixture import mockpatch
from keystone.openstack.common import gettextutils

# NOTE(ayoung)
# environment.use_eventlet must run before any of the code that will
# call the eventlet monkeypatching.
from keystone.common import environment
environment.use_eventlet()

from keystone import auth
from keystone.common import dependency
from keystone.common import kvs
from keystone.common.kvs import core as kvs_core
from keystone.common import sql
from keystone.common.sql import migration_helpers
from keystone.common import utils as common_utils
from keystone import config
from keystone import exception
from keystone import notifications
from keystone.openstack.common.db import options as db_options
from keystone.openstack.common.db.sqlalchemy import migration
from keystone.openstack.common.fixture import config as config_fixture
from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import log
from keystone import service
from keystone.tests import ksfixtures

# NOTE(dstanek): Tests inheriting from TestCase depend on having the
#   policy_file command-line option declared before setUp runs. Importing the
#   oslo policy module automatically declares the option.
from keystone.openstack.common import policy as common_policy  # noqa


config.configure()


LOG = log.getLogger(__name__)
PID = six.text_type(os.getpid())
TESTSDIR = os.path.dirname(os.path.abspath(__file__))
TESTCONF = os.path.join(TESTSDIR, 'config_files')
ROOTDIR = os.path.normpath(os.path.join(TESTSDIR, '..', '..'))
VENDOR = os.path.join(ROOTDIR, 'vendor')
ETCDIR = os.path.join(ROOTDIR, 'etc')


def _calc_tmpdir():
    env_val = os.environ.get('KEYSTONE_TEST_TEMP_DIR')
    if not env_val:
        return os.path.join(TESTSDIR, 'tmp', PID)
    return os.path.join(env_val, PID)


TMPDIR = _calc_tmpdir()

CONF = config.CONF

exception._FATAL_EXCEPTION_FORMAT_ERRORS = True
os.makedirs(TMPDIR)
atexit.register(shutil.rmtree, TMPDIR)


class dirs:
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


def _initialize_sql_session():
    # Make sure the DB is located in the correct location, in this case set
    # the default value, as this should be able to be overridden in some
    # test cases.
    db_file = DEFAULT_TEST_DB_FILE
    db_options.set_defaults(
        sql_connection='sqlite:///%s' % db_file,
        sqlite_db=db_file)


_initialize_sql_session()


def checkout_vendor(repo, rev):
    # TODO(termie): this function is a good target for some optimizations :PERF
    name = repo.split('/')[-1]
    if name.endswith('.git'):
        name = name[:-4]

    working_dir = os.getcwd()
    revdir = os.path.join(VENDOR, '%s-%s' % (name, rev.replace('/', '_')))
    modcheck = os.path.join(VENDOR, '.%s-%s' % (name, rev.replace('/', '_')))
    try:
        if os.path.exists(modcheck):
            mtime = os.stat(modcheck).st_mtime
            if int(time.time()) - mtime < 10000:
                return revdir

        if not os.path.exists(revdir):
            common_utils.git('clone', repo, revdir)

        os.chdir(revdir)
        common_utils.git('checkout', '-q', 'master')
        common_utils.git('pull', '-q')
        common_utils.git('checkout', '-q', rev)

        # write out a modified time
        with open(modcheck, 'w') as fd:
            fd.write('1')
    except environment.subprocess.CalledProcessError:
        LOG.warning(_('Failed to checkout %s'), repo)
    os.chdir(working_dir)
    return revdir


def setup_database():
    db = dirs.tmp('test.db')
    pristine = dirs.tmp('test.db.pristine')

    if os.path.exists(db):
        os.unlink(db)
    if not os.path.exists(pristine):
        migration.db_sync(sql.get_engine(),
                          migration_helpers.find_migrate_repo())
        migration_helpers.sync_database_to_version(extension='revoke')
        shutil.copyfile(db, pristine)
    else:
        shutil.copyfile(pristine, db)


def teardown_database():
    sql.cleanup()


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


class UnexpectedExit(Exception):
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


class NoModule(object):
    """A mixin class to provide support for unloading/disabling modules."""

    def setUp(self):
        super(NoModule, self).setUp()

        self._finders = []

        def cleanup_finders():
            for finder in self._finders:
                sys.meta_path.remove(finder)
            del self._finders
        self.addCleanup(cleanup_finders)

        self._cleared_modules = {}

        def cleanup_modules():
            sys.modules.update(self._cleared_modules)
            del self._cleared_modules
        self.addCleanup(cleanup_modules)

    def clear_module(self, module):
        cleared_modules = {}
        for fullname in sys.modules.keys():
            if fullname == module or fullname.startswith(module + '.'):
                cleared_modules[fullname] = sys.modules.pop(fullname)
        return cleared_modules

    def disable_module(self, module):
        """Ensure ImportError for the specified module."""

        # Clear 'module' references in sys.modules
        self._cleared_modules.update(self.clear_module(module))

        # Disallow further imports of 'module'
        class NoModule(object):
            def find_module(self, fullname, path):
                if fullname == module or fullname.startswith(module + '.'):
                    raise ImportError

        finder = NoModule()
        self._finders.append(finder)
        sys.meta_path.insert(0, finder)


class BaseTestCase(testtools.TestCase):
    """Light weight base test class.

    This is a placeholder that will eventually go away once thc
    setup/teardown in TestCase is properly trimmed down to the bare
    essentials. This is really just a play to speed up the tests by
    eliminating unnecessary work.
    """

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


@dependency.optional('revoke_api')
class TestCase(BaseTestCase):

    _config_file_list = []

    def config_files(self):
        return copy.copy(self._config_file_list)

    def config_overrides(self):
        self.config_fixture.config(policy_file=dirs.etc('policy.json'))
        self.config_fixture.config(
            group='auth',
            methods=['keystone.auth.plugins.external.DefaultDomain',
                     'keystone.auth.plugins.password.Password',
                     'keystone.auth.plugins.token.Token',
                     'keystone.auth.plugins.oauth1.OAuth',
                     'keystone.auth.plugins.saml2.Saml2'])
        self.config_fixture.config(
            # TODO(morganfainberg): Make Cache Testing a separate test case
            # in tempest, and move it out of the base unit tests.
            group='cache',
            backend='dogpile.cache.memory',
            enabled=True,
            proxies=['keystone.tests.test_cache.CacheIsolatingProxy'])
        self.config_fixture.config(
            group='catalog',
            driver='keystone.catalog.backends.templated.Catalog',
            template_file=dirs.tests('default_catalog.templates'))
        self.config_fixture.config(
            group='identity',
            driver='keystone.identity.backends.kvs.Identity')
        self.config_fixture.config(
            group='kvs',
            backends=[
                'keystone.tests.test_kvs.KVSBackendForcedKeyMangleFixture',
                'keystone.tests.test_kvs.KVSBackendFixture'])
        self.config_fixture.config(
            group='revoke',
            driver='keystone.contrib.revoke.backends.kvs.Revoke')
        self.config_fixture.config(
            group='signing',
            certfile='examples/pki/certs/signing_cert.pem',
            keyfile='examples/pki/private/signing_key.pem',
            ca_certs='examples/pki/certs/cacert.pem')
        self.config_fixture.config(
            group='token',
            driver='keystone.token.backends.kvs.Token')
        self.config_fixture.config(
            group='trust',
            driver='keystone.trust.backends.kvs.Trust')

    def setUp(self):
        super(TestCase, self).setUp()
        self.addCleanup(self.cleanup_instance(
            '_paths', '_memo', '_overrides', '_group_overrides', 'maxDiff',
            'exit_patch', 'config_fixture', 'logger'))

        self._paths = []

        def _cleanup_paths():
            for path in self._paths:
                if path in sys.path:
                    sys.path.remove(path)
        self.addCleanup(_cleanup_paths)

        self._memo = {}
        self._overrides = []
        self._group_overrides = {}

        # show complete diffs on failure
        self.maxDiff = None

        self.addCleanup(CONF.reset)

        self.exit_patch = self.useFixture(mockpatch.PatchObject(sys, 'exit'))
        self.exit_patch.mock.side_effect = UnexpectedExit
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.config(self.config_files())

        self.config_overrides()

        self.logger = self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))
        warnings.filterwarnings('ignore', category=DeprecationWarning)
        self.useFixture(ksfixtures.Cache())

        # Clear the registry of providers so that providers from previous
        # tests aren't used.
        self.addCleanup(dependency.reset)

        self.addCleanup(kvs.INMEMDB.clear)

        # Ensure Notification subscriotions and resource types are empty
        self.addCleanup(notifications.SUBSCRIBERS.clear)
        self.addCleanup(notifications._reset_notifier)

        # Reset the auth-plugin registry
        self.addCleanup(self.clear_auth_plugin_registry)

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
        drivers = service.load_backends()

        drivers.update(dependency.resolve_future_dependencies())

        for manager_name, manager in six.iteritems(drivers):
            setattr(self, manager_name, manager)
        self.addCleanup(self.cleanup_instance(*drivers.keys()))

        # The credential backend only supports SQL, so we always have to load
        # the tables.
        self.engine = sql.get_engine()
        self.addCleanup(sql.cleanup)
        self.addCleanup(self.cleanup_instance('engine'))

        sql.ModelBase.metadata.create_all(bind=self.engine)
        self.addCleanup(sql.ModelBase.metadata.drop_all, bind=self.engine)

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
        if hasattr(self, 'identity_api') and hasattr(self, 'assignment_api'):
            for domain in fixtures.DOMAINS:
                try:
                    rv = self.assignment_api.create_domain(domain['id'],
                                                           domain)
                except exception.Conflict:
                    rv = self.assignment_api.get_domain(domain['id'])
                except exception.NotImplemented:
                    rv = domain
                attrname = 'domain_%s' % domain['id']
                setattr(self, attrname, rv)
                fixtures_to_cleanup.append(attrname)

            for tenant in fixtures.TENANTS:
                try:
                    rv = self.assignment_api.create_project(
                        tenant['id'], tenant)
                except exception.Conflict:
                    rv = self.assignment_api.get_project(tenant['id'])
                attrname = 'tenant_%s' % tenant['id']
                setattr(self, attrname, rv)
                fixtures_to_cleanup.append(attrname)

            for role in fixtures.ROLES:
                try:
                    rv = self.assignment_api.create_role(role['id'], role)
                except exception.Conflict:
                    rv = self.assignment_api.get_role(role['id'])
                attrname = 'role_%s' % role['id']
                setattr(self, attrname, rv)
                fixtures_to_cleanup.append(attrname)

            for user in fixtures.USERS:
                user_copy = user.copy()
                tenants = user_copy.pop('tenants')
                try:
                    self.identity_api.create_user(user['id'], user_copy)
                except exception.Conflict:
                    pass
                for tenant_id in tenants:
                    try:
                        self.assignment_api.add_user_to_project(tenant_id,
                                                                user['id'])
                    except exception.Conflict:
                        pass
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
        return deploy.loadapp(self._paste_config(config), name=name)

    def client(self, app, *args, **kw):
        return TestClient(app, *args, **kw)

    def add_path(self, path):
        sys.path.insert(0, path)
        self._paths.append(path)

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

            if isinstance(exc_value.args[0], gettextutils.Message):
                if not expected_regexp.search(six.text_type(exc_value)):
                    raise self.failureException(
                        '"%s" does not match "%s"' %
                        (expected_regexp.pattern, six.text_type(exc_value)))
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

    def assertSetEqual(self, set1, set2, msg=None):
        # TODO(morganfainberg): Remove this and self._assertSetEqual once
        # support for python 2.6 is no longer needed.
        if (sys.version_info < (2, 7)):
            return self._assertSetEqual(set1, set2, msg=None)
        else:
            # use the native assertSetEqual
            return super(TestCase, self).assertSetEqual(set1, set2, msg=msg)

    def _assertSetEqual(self, set1, set2, msg=None):
        """A set-specific equality assertion.

        Args:
            set1: The first set to compare.
            set2: The second set to compare.
            msg: Optional message to use on failure instead of a list of
                    differences.

        assertSetEqual uses ducktyping to support different types of sets, and
        is optimized for sets specifically (parameters must support a
        difference method).
        """
        try:
            difference1 = set1.difference(set2)
        except TypeError as e:
            self.fail('invalid type when attempting set difference: %s' % e)
        except AttributeError as e:
            self.fail('first argument does not support set difference: %s' % e)

        try:
            difference2 = set2.difference(set1)
        except TypeError as e:
            self.fail('invalid type when attempting set difference: %s' % e)
        except AttributeError as e:
            self.fail('second argument does not support set difference: %s' %
                      e)

        if not (difference1 or difference2):
            return

        lines = []
        if difference1:
            lines.append('Items in the first set but not the second:')
            for item in difference1:
                lines.append(repr(item))
        if difference2:
            lines.append('Items in the second set but not the first:')
            for item in difference2:
                lines.append(repr(item))

        standardMsg = '\n'.join(lines)
        self.fail(self._formatMessage(msg, standardMsg))


class SQLDriverOverrides(object):
    """A mixin for consolidating sql-specific test overrides."""
    def config_overrides(self):
        super(SQLDriverOverrides, self).config_overrides()
        # SQL specific driver overrides
        self.config_fixture.config(
            group='catalog',
            driver='keystone.catalog.backends.sql.Catalog')
        self.config_fixture.config(
            group='ec2',
            driver='keystone.contrib.ec2.backends.sql.Ec2')
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
            driver='keystone.token.backends.sql.Token')
        self.config_fixture.config(
            group='trust',
            driver='keystone.trust.backends.sql.Trust')
