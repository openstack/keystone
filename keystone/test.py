# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import datetime
import errno
import os
import shutil
import socket
import StringIO
import sys
import time

import gettext
from lxml import etree
import mox
import nose.exc
from paste import deploy
import stubout
import unittest2 as unittest

gettext.install('keystone', unicode=1)

from keystone.common import environment
environment.use_eventlet()

from keystone import assignment
from keystone import catalog
from keystone.common import kvs
from keystone.common import logging
from keystone.common import sql
from keystone.common import utils
from keystone.common import wsgi
from keystone import config
from keystone import credential
from keystone import exception
from keystone import identity
from keystone.openstack.common import timeutils
from keystone import policy
from keystone import token
from keystone import trust


LOG = logging.getLogger(__name__)
ROOTDIR = os.path.dirname(os.path.abspath(os.curdir))
VENDOR = os.path.join(ROOTDIR, 'vendor')
TESTSDIR = os.path.join(ROOTDIR, 'tests')
ETCDIR = os.path.join(ROOTDIR, 'etc')
TMPDIR = os.path.join(TESTSDIR, 'tmp')

CONF = config.CONF

cd = os.chdir


logging.getLogger('routes.middleware').level = logging.WARN


def rootdir(*p):
    return os.path.join(ROOTDIR, *p)


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


def testsdir(*p):
    return os.path.join(TESTSDIR, *p)


def tmpdir(*p):
    return os.path.join(TMPDIR, *p)


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
            utils.git('clone', repo, revdir)

        cd(revdir)
        utils.git('checkout', '-q', 'master')
        utils.git('pull', '-q')
        utils.git('checkout', '-q', rev)

        # write out a modified time
        with open(modcheck, 'w') as fd:
            fd.write('1')
    except environment.subprocess.CalledProcessError:
        LOG.warning(_('Failed to checkout %s'), repo)
    cd(working_dir)
    return revdir


def setup_test_database():
    db = tmpdir('test.db')
    pristine = tmpdir('test.db.pristine')

    try:
        if os.path.exists(db):
            os.unlink(db)
        if not os.path.exists(pristine):
            sql.migration.db_sync()
            shutil.copyfile(db, pristine)
        else:
            shutil.copyfile(pristine, db)
    except Exception:
        pass


def teardown_test_database():
    sql.core.set_global_engine(None)


class TestClient(object):
    def __init__(self, app=None, token=None):
        self.app = app
        self.token = token

    def request(self, method, path, headers=None, body=None):
        if headers is None:
            headers = {}

        if self.token:
            headers.setdefault('X-Auth-Token', self.token)

        req = wsgi.Request.blank(path)
        req.method = method
        for k, v in headers.iteritems():
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

    def __init__(self, *args, **kw):
        super(NoModule, self).__init__(*args, **kw)
        self._finders = []
        self._cleared_modules = {}

    def tearDown(self):
        super(NoModule, self).tearDown()
        for finder in self._finders:
            sys.meta_path.remove(finder)
        sys.modules.update(self._cleared_modules)

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


class TestCase(NoModule, unittest.TestCase):
    def __init__(self, *args, **kw):
        super(TestCase, self).__init__(*args, **kw)
        self._paths = []
        self._memo = {}
        self._overrides = []
        self._group_overrides = {}

        # show complete diffs on failure
        self.maxDiff = None

    def setUp(self):
        super(TestCase, self).setUp()
        self.config([etcdir('keystone.conf.sample'),
                     testsdir('test_overrides.conf')])
        self.mox = mox.Mox()
        self.opt(policy_file=etcdir('policy.json'))
        self.stubs = stubout.StubOutForTesting()
        self.stubs.Set(exception, '_FATAL_EXCEPTION_FORMAT_ERRORS', True)

    def config(self, config_files):
        CONF(args=[], project='keystone', default_config_files=config_files)

    def tearDown(self):
        try:
            timeutils.clear_time_override()
            self.mox.UnsetStubs()
            self.stubs.UnsetAll()
            self.stubs.SmartUnsetAll()
            self.mox.VerifyAll()
            super(TestCase, self).tearDown()
        finally:
            for path in self._paths:
                if path in sys.path:
                    sys.path.remove(path)
            kvs.INMEMDB.clear()
            CONF.reset()

    def opt_in_group(self, group, **kw):
        for k, v in kw.iteritems():
            CONF.set_override(k, v, group)

    def opt(self, **kw):
        for k, v in kw.iteritems():
            CONF.set_override(k, v)

    def load_backends(self):
        """Initializes each manager and assigns them to an attribute."""
        for manager in [assignment, catalog, credential, identity, policy,
                        token, trust]:
            manager_name = '%s_api' % manager.__name__.split('.')[-1]
            setattr(self, manager_name, manager.Manager())

    def load_fixtures(self, fixtures):
        """Hacky basic and naive fixture loading based on a python module.

        Expects that the various APIs into the various services are already
        defined on `self`.

        """
        # TODO(termie): doing something from json, probably based on Django's
        #               loaddata will be much preferred.
        if hasattr(self, 'identity_api'):
            for domain in fixtures.DOMAINS:
                try:
                    rv = self.identity_api.create_domain(domain['id'], domain)
                except (exception.Conflict, exception.NotImplemented):
                    pass
                setattr(self, 'domain_%s' % domain['id'], domain)

            for tenant in fixtures.TENANTS:
                try:
                    rv = self.identity_api.create_project(tenant['id'], tenant)
                except exception.Conflict:
                    rv = self.identity_api.get_project(tenant['id'])
                    pass
                setattr(self, 'tenant_%s' % tenant['id'], rv)

            for role in fixtures.ROLES:
                try:
                    rv = self.identity_api.create_role(role['id'], role)
                except exception.Conflict:
                    rv = self.identity_api.get_role(role['id'])
                    pass
                setattr(self, 'role_%s' % role['id'], rv)

            for user in fixtures.USERS:
                user_copy = user.copy()
                tenants = user_copy.pop('tenants')
                try:
                    rv = self.identity_api.create_user(user['id'],
                                                       user_copy.copy())
                except exception.Conflict:
                    pass
                for tenant_id in tenants:
                    try:
                        self.identity_api.add_user_to_project(tenant_id,
                                                              user['id'])
                    except exception.Conflict:
                        pass
                setattr(self, 'user_%s' % user['id'], user_copy)

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

    def appconfig(self, config):
        return deploy.appconfig(self._paste_config(config))

    def serveapp(self, config, name=None, cert=None, key=None, ca=None,
                 cert_required=None, host="127.0.0.1", port=0):
        app = self.loadapp(config, name=name)
        server = environment.Server(app, host, port)
        if cert is not None and ca is not None and key is not None:
            server.set_ssl(certfile=cert, keyfile=key, ca_certs=ca,
                           cert_required=cert_required)
        server.start(key='socket')

        # Service catalog tests need to know the port we ran on.
        port = server.socket_info['socket'][1]
        self.opt(public_port=port, admin_port=port)
        return server

    def client(self, app, *args, **kw):
        return TestClient(app, *args, **kw)

    def add_path(self, path):
        sys.path.insert(0, path)
        self._paths.append(path)

    def assertCloseEnoughForGovernmentWork(self, a, b, delta=3):
        """Asserts that two datetimes are nearly equal within a small delta.

        :param delta: Maximum allowable time delta, defined in seconds.
        """
        self.assertAlmostEqual(a, b, delta=datetime.timedelta(seconds=delta))

    def assertNotEmpty(self, l):
        self.assertTrue(len(l))

    def assertDictContainsSubset(self, expected, actual, msg=None):
        """Checks whether actual is a superset of expected."""
        safe_repr = unittest.util.safe_repr
        missing = []
        mismatched = []
        for key, value in expected.iteritems():
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

    def assertEqualXML(self, a, b):
        """Parses two XML documents from strings and compares the results.

        This provides easy-to-read failures from nose.

        """
        parser = etree.XMLParser(remove_blank_text=True)

        def canonical_xml(s):
            s = s.strip()

            fp = StringIO.StringIO()
            dom = etree.fromstring(s, parser)
            dom.getroottree().write_c14n(fp)
            s = fp.getvalue()

            dom = etree.fromstring(s, parser)
            return etree.tostring(dom, pretty_print=True)

        a = canonical_xml(a)
        b = canonical_xml(b)
        self.assertEqual(a.split('\n'), b.split('\n'))

    @staticmethod
    def skip_if_no_ipv6():
        try:
            s = socket.socket(socket.AF_INET6)
        except socket.error as e:
            if e.errno == errno.EAFNOSUPPORT:
                raise nose.exc.SkipTest("IPv6 is not enabled in the system")
            else:
                raise
        else:
            s.close()
