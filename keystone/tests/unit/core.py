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
import datetime
import functools
import logging
import os
import re
import shutil
import socket
import sys
import uuid
import warnings

import fixtures
from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslo_log import fixture as log_fixture
from oslo_log import log
from oslo_utils import timeutils
import oslotest.base as oslotest
from oslotest import mockpatch
from paste.deploy import loadwsgi
import six
from sqlalchemy import exc
from testtools import testcase

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
from keystone.common import sql
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

TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

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


class EggLoader(loadwsgi.EggLoader):
    _basket = {}

    def find_egg_entry_point(self, object_type, name=None):
        egg_key = '%s:%s' % (object_type, name)
        egg_ep = self._basket.get(egg_key)
        if not egg_ep:
            egg_ep = super(EggLoader, self).find_egg_entry_point(
                object_type, name=name)
            self._basket[egg_key] = egg_ep
        return egg_ep


# NOTE(dstanek): class paths were remove from the keystone-paste.ini in
# favor of using entry points. This caused tests to slow to a crawl
# since we reload the application object for each RESTful test. This
# monkey-patching adds caching to paste deploy's egg lookup.
loadwsgi.EggLoader = EggLoader


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
    """This decorator is used to skip a test if caching is disabled.

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


def new_ref():
    """Populates a ref with attributes common to some API entities."""
    return {
        'id': uuid.uuid4().hex,
        'name': uuid.uuid4().hex,
        'description': uuid.uuid4().hex,
        'enabled': True}


def new_region_ref():
    ref = new_ref()
    # Region doesn't have name or enabled.
    del ref['name']
    del ref['enabled']
    ref['parent_region_id'] = None
    return ref


def new_service_ref():
    ref = new_ref()
    ref['type'] = uuid.uuid4().hex
    return ref


def new_endpoint_ref(service_id, interface='public', default_region_id=None,
                     **kwargs):
    ref = new_ref()
    del ref['enabled']  # enabled is optional
    ref['interface'] = interface
    ref['service_id'] = service_id
    ref['url'] = 'https://' + uuid.uuid4().hex + '.com'
    ref['region_id'] = default_region_id
    ref.update(kwargs)
    return ref


def new_domain_ref():
    ref = new_ref()
    return ref


def new_project_ref(domain_id=None, parent_id=None, is_domain=False):
    ref = new_ref()
    ref['domain_id'] = domain_id
    ref['parent_id'] = parent_id
    ref['is_domain'] = is_domain
    return ref


def new_user_ref(domain_id, project_id=None):
    ref = new_ref()
    ref['domain_id'] = domain_id
    ref['email'] = uuid.uuid4().hex
    ref['password'] = uuid.uuid4().hex
    if project_id:
        ref['default_project_id'] = project_id
    return ref


def new_group_ref(domain_id):
    ref = new_ref()
    ref['domain_id'] = domain_id
    return ref


def new_credential_ref(user_id, project_id=None, cred_type=None):
    ref = dict()
    ref['id'] = uuid.uuid4().hex
    ref['user_id'] = user_id
    if cred_type == 'ec2':
        ref['type'] = 'ec2'
        ref['blob'] = uuid.uuid4().hex
    else:
        ref['type'] = 'cert'
        ref['blob'] = uuid.uuid4().hex
    if project_id:
        ref['project_id'] = project_id
    return ref


def new_role_ref():
    ref = new_ref()
    # Roles don't have a description or the enabled flag
    del ref['description']
    del ref['enabled']
    return ref


def new_policy_ref():
    ref = new_ref()
    ref['blob'] = uuid.uuid4().hex
    ref['type'] = uuid.uuid4().hex
    return ref


def new_trust_ref(trustor_user_id, trustee_user_id, project_id=None,
                  impersonation=None, expires=None, role_ids=None,
                  role_names=None, remaining_uses=None,
                  allow_redelegation=False):
    ref = dict()
    ref['id'] = uuid.uuid4().hex
    ref['trustor_user_id'] = trustor_user_id
    ref['trustee_user_id'] = trustee_user_id
    ref['impersonation'] = impersonation or False
    ref['project_id'] = project_id
    ref['remaining_uses'] = remaining_uses
    ref['allow_redelegation'] = allow_redelegation

    if isinstance(expires, six.string_types):
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

    return ref


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
        self.useFixture(log_fixture.get_logging_handle_error_fixture())

        warnings.filterwarnings('error', category=DeprecationWarning,
                                module='^keystone\\.')
        warnings.simplefilter('error', exc.SAWarning)
        self.addCleanup(warnings.resetwarnings)

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


class TestCase(BaseTestCase):

    def config_files(self):
        return []

    def config_overrides(self):
        # NOTE(morganfainberg): enforce config_overrides can only ever be
        # called a single time.
        assert self.__config_overrides_called is False
        self.__config_overrides_called = True

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
            driver='templated',
            template_file=dirs.tests('default_catalog.templates'))
        self.config_fixture.config(
            group='kvs',
            backends=[
                ('keystone.tests.unit.test_kvs.'
                 'KVSBackendForcedKeyMangleFixture'),
                'keystone.tests.unit.test_kvs.KVSBackendFixture'])
        self.config_fixture.config(group='revoke', driver='kvs')
        self.config_fixture.config(
            group='signing', certfile=signing_certfile,
            keyfile=signing_keyfile,
            ca_certs='examples/pki/certs/cacert.pem')
        self.config_fixture.config(group='token', driver='kvs')
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
        if methods is not None:
            self.config_fixture.config(group='auth', methods=methods)
            common_cfg.setup_authentication()
        if method_classes:
            self.config_fixture.config(group='auth', **method_classes)

    def _assert_config_overrides_called(self):
        assert self.__config_overrides_called is True

    def setUp(self):
        super(TestCase, self).setUp()
        self.__config_overrides_called = False
        self.addCleanup(CONF.reset)
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.addCleanup(delattr, self, 'config_fixture')
        self.config(self.config_files())

        # NOTE(morganfainberg): mock the auth plugin setup to use the config
        # fixture which automatically unregisters options when performing
        # cleanup.
        def mocked_register_auth_plugin_opt(conf, opt):
            self.config_fixture.register_opt(opt, group='auth')
        self.useFixture(mockpatch.PatchObject(
            common_cfg, '_register_auth_plugin_opt',
            new=mocked_register_auth_plugin_opt))

        self.config_overrides()
        # NOTE(morganfainberg): ensure config_overrides has been called.
        self.addCleanup(self._assert_config_overrides_called)

        self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))

        # NOTE(morganfainberg): This code is a copy from the oslo-incubator
        # log module. This is not in a function or otherwise available to use
        # without having a CONF object to setup logging. This should help to
        # reduce the log size by limiting what we log (similar to how Keystone
        # would run under mod_wsgi or eventlet).
        for pair in CONF.default_log_levels:
            mod, _sep, level_name = pair.partition('=')
            logger = logging.getLogger(mod)
            logger.setLevel(level_name)

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
        sql.initialize()
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

        for manager_name, manager in drivers.items():
            setattr(self, manager_name, manager)
        self.addCleanup(self.cleanup_instance(*list(drivers.keys())))

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

    def assertRaisesRegexp(self, expected_exception, expected_regexp,
                           callable_obj, *args, **kwargs):
        """Asserts that the message in a raised exception matches a regexp."""
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
        self.config_fixture.config(group='catalog', driver='sql')
        self.config_fixture.config(group='identity', driver='sql')
        self.config_fixture.config(group='policy', driver='sql')
        self.config_fixture.config(group='revoke', driver='sql')
        self.config_fixture.config(group='token', driver='sql')
        self.config_fixture.config(group='trust', driver='sql')
