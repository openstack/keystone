# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

# Colorizer Code is borrowed from Twisted:
# Copyright (c) 2001-2010 Twisted Matrix Laboratories.
#
#    Permission is hereby granted, free of charge, to any person obtaining
#    a copy of this software and associated documentation files (the
#    "Software"), to deal in the Software without restriction, including
#    without limitation the rights to use, copy, modify, merge, publish,
#    distribute, sublicense, and/or sell copies of the Software, and to
#    permit persons to whom the Software is furnished to do so, subject to
#    the following conditions:
#
#    The above copyright notice and this permission notice shall be
#    included in all copies or substantial portions of the Software.
#
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
#    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
#    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
#    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
#    WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
#   Code copied from Nova and other OpenStack projects:
#       Colorizers
#       Classes starting with Nova
#       other setup and initialization code
#
""" Module that handles starting the Keystone server and running
test suites"""

import heapq
import logging
from nose import config as noseconfig
from nose import core
from nose import result
import optparse
import os
import sys
import tempfile
import time
import unittest

import keystone
import keystone.server
import keystone.version
from keystone import config as config_module
from keystone.common import config
from keystone.test import utils
from keystone.test import client as client_tests
from keystone import utils as main_utils

TEST_DIR = os.path.abspath(os.path.dirname(__file__))
BASE_DIR = os.path.abspath(os.path.join(TEST_DIR, os.pardir, os.pardir))
TEST_CERT = os.path.join(BASE_DIR, 'examples/ssl/certs/middleware-key.pem')

logger = logging.getLogger(__name__)

CONF = config_module.CONF


class _AnsiColorizer(object):
    """
    A colorizer is an object that loosely wraps around a stream, allowing
    callers to write text to the stream in a particular color.

    Colorizer classes must implement C{supported()} and C{write(text, color)}.
    """
    _colors = dict(black=30, red=31, green=32, yellow=33,
                   blue=34, magenta=35, cyan=36, white=37)

    def __init__(self, stream):
        self.stream = stream

    def supported(cls, stream=sys.stdout):
        """
        A class method that returns True if the current platform supports
        coloring terminal output using this method. Returns False otherwise.
        """
        if not stream.isatty():
            return False  # auto color only on TTYs
        try:
            import curses
        except ImportError:
            return False
        else:
            try:
                try:
                    return curses.tigetnum("colors") > 2
                except curses.error:
                    curses.setupterm()
                    return curses.tigetnum("colors") > 2
            except:
                raise
                # guess false in case of error
                return False
    supported = classmethod(supported)

    def write(self, text, color):
        """
        Write the given text to the stream in the given color.

        @param text: Text to be written to the stream.

        @param color: A string label for a color. e.g. 'red', 'white'.
        """
        color = self._colors[color]
        self.stream.write('\x1b[%s;1m%s\x1b[0m' % (color, text))


class _Win32Colorizer(object):
    """
    See _AnsiColorizer docstring.
    """
    def __init__(self, stream):
        from win32console import GetStdHandle, STD_OUT_HANDLE, \
             FOREGROUND_RED, FOREGROUND_BLUE, FOREGROUND_GREEN, \
             FOREGROUND_INTENSITY
        red, green, blue, bold = (FOREGROUND_RED, FOREGROUND_GREEN,
                                  FOREGROUND_BLUE, FOREGROUND_INTENSITY)
        self.stream = stream
        self.screenBuffer = GetStdHandle(STD_OUT_HANDLE)
        self._colors = {
            'normal': red | green | blue,
            'red': red | bold,
            'green': green | bold,
            'blue': blue | bold,
            'yellow': red | green | bold,
            'magenta': red | blue | bold,
            'cyan': green | blue | bold,
            'white': red | green | blue | bold
            }

    def supported(cls, stream=sys.stdout):
        try:
            import win32console
            screenBuffer = win32console.GetStdHandle(
                win32console.STD_OUT_HANDLE)
        except ImportError:
            return False
        import pywintypes
        try:
            screenBuffer.SetConsoleTextAttribute(
                win32console.FOREGROUND_RED |
                win32console.FOREGROUND_GREEN |
                win32console.FOREGROUND_BLUE)
        except pywintypes.error:
            return False
        else:
            return True
    supported = classmethod(supported)

    def write(self, text, color):
        color = self._colors[color]
        self.screenBuffer.SetConsoleTextAttribute(color)
        self.stream.write(text)
        self.screenBuffer.SetConsoleTextAttribute(self._colors['normal'])


class _NullColorizer(object):
    """
    See _AnsiColorizer docstring.
    """
    def __init__(self, stream):
        self.stream = stream

    def supported(cls, stream=sys.stdout):
        return True
    supported = classmethod(supported)

    def write(self, text, color):
        self.stream.write(text)


def get_elapsed_time_color(elapsed_time):
    if elapsed_time > 1.0:
        return 'red'
    elif elapsed_time > 0.25:
        return 'yellow'
    else:
        return 'green'


class NovaTestResult(result.TextTestResult):
    def __init__(self, *args, **kw):
        self.show_elapsed = kw.pop('show_elapsed')
        result.TextTestResult.__init__(self, *args, **kw)
        self.num_slow_tests = 5
        self.slow_tests = []  # this is a fixed-sized heap
        self._last_case = None
        self.colorizer = None
        # NOTE(vish): reset stdout for the terminal check
        stdout = sys.stdout
        sys.stdout = sys.__stdout__
        for colorizer in [_Win32Colorizer, _AnsiColorizer, _NullColorizer]:
            if colorizer.supported():
                self.colorizer = colorizer(self.stream)
                break
        sys.stdout = stdout

        # NOTE(lorinh): Initialize start_time in case a sqlalchemy-migrate
        # error results in it failing to be initialized later. Otherwise,
        # _handleElapsedTime will fail, causing the wrong error message to
        # be outputted.
        self.start_time = time.time()

    def getDescription(self, test):
        return str(test)

    def _handleElapsedTime(self, test):
        self.elapsed_time = time.time() - self.start_time
        item = (self.elapsed_time, test)
        # Record only the n-slowest tests using heap
        if len(self.slow_tests) >= self.num_slow_tests:
            heapq.heappushpop(self.slow_tests, item)
        else:
            heapq.heappush(self.slow_tests, item)

    def _writeElapsedTime(self, test):
        color = get_elapsed_time_color(self.elapsed_time)
        self.colorizer.write("  %.2f" % self.elapsed_time, color)

    def _writeResult(self, test, long_result, color, short_result, success):
        if self.showAll:
            self.colorizer.write(long_result, color)
            if self.show_elapsed and success:
                self._writeElapsedTime(test)
            self.stream.writeln()
        elif self.dots:
            self.stream.write(short_result)
            self.stream.flush()

    # NOTE(vish): copied from unittest with edit to add color
    def addSuccess(self, test):
        unittest.TestResult.addSuccess(self, test)
        self._handleElapsedTime(test)
        self._writeResult(test, 'OK', 'green', '.', True)

    # NOTE(vish): copied from unittest with edit to add color
    def addFailure(self, test, err):
        unittest.TestResult.addFailure(self, test, err)
        self._handleElapsedTime(test)
        self._writeResult(test, 'FAIL', 'red', 'F', False)

    # NOTE(vish): copied from nose with edit to add color
    def addError(self, test, err):
        """Overrides normal addError to add support for
        errorClasses. If the exception is a registered class, the
        error will be added to the list for that class, not errors.
        """
        self._handleElapsedTime(test)
        stream = getattr(self, 'stream', None)
        ec, ev, tb = err
        try:
            exc_info = self._exc_info_to_string(err, test)
        except TypeError:
            # 2.3 compat
            exc_info = self._exc_info_to_string(err)
        for cls, (storage, label, isfail) in self.errorClasses.items():
            if result.isclass(ec) and issubclass(ec, cls):
                if isfail:
                    test.passed = False
                storage.append((test, exc_info))
                # Might get patched into a streamless result
                if stream is not None:
                    if self.showAll:
                        message = [label]
                        detail = result._exception_detail(err[1])
                        if detail:
                            message.append(detail)
                        stream.writeln(": ".join(message))
                    elif self.dots:
                        stream.write(label[:1])
                return
        self.errors.append((test, exc_info))
        test.passed = False
        if stream is not None:
            self._writeResult(test, 'ERROR', 'red', 'E', False)

    def startTest(self, test):
        unittest.TestResult.startTest(self, test)
        self.start_time = time.time()
        current_case = test.test.__class__.__name__

        if self.showAll:
            if current_case != self._last_case:
                self.stream.writeln(current_case)
                self._last_case = current_case

            self.stream.write(
                '    %s' % str(test.test._testMethodName).ljust(60))
            self.stream.flush()


class NovaTestRunner(core.TextTestRunner):
    def __init__(self, *args, **kwargs):
        self.show_elapsed = kwargs.pop('show_elapsed')
        core.TextTestRunner.__init__(self, *args, **kwargs)

    def _makeResult(self):
        return NovaTestResult(self.stream,
                              self.descriptions,
                              self.verbosity,
                              self.config,
                              show_elapsed=self.show_elapsed)

    def _writeSlowTests(self, result_):
        # Pare out 'fast' tests
        slow_tests = [item for item in result_.slow_tests
                      if get_elapsed_time_color(item[0]) != 'green']
        if slow_tests:
            slow_total_time = sum(item[0] for item in slow_tests)
            self.stream.writeln("Slowest %i tests took %.2f secs:"
                                % (len(slow_tests), slow_total_time))
            for elapsed_time, test in sorted(slow_tests, reverse=True):
                time_str = "%.2f" % elapsed_time
                self.stream.writeln("    %s %s" % (time_str.ljust(10), test))

    def run(self, test):
        result_ = core.TextTestRunner.run(self, test)
        if self.show_elapsed:
            self._writeSlowTests(result_)
        return result_


class KeystoneTest(object):
    """Primary test class for invoking keystone tests. Controls
    initialization of environment with temporary configuration files,
    starts keystone admin and service API WSIG servers, and then uses
    :py:mod:`unittest2` to discover and iterate over existing tests.

    :py:class:`keystone.test.KeystoneTest` is expected to be
    subclassed and invoked in ``run_tests.py`` where subclasses define
    a config_name (that matches a template existing in
    ``keystone/test/etc``) and test_files (that are cleared at the
    end of test execution from the temporary space used to run these
    tests).
    """
    config_params = {'test_dir': TEST_DIR, 'base_dir': BASE_DIR}
    isSsl = False
    hpidmDisabled = False
    config_name = None
    test_files = None
    server = None
    admin_server = None
    conf_fp = None
    directory_base = None

    def clear_database(self):
        """Remove any test databases or files generated by previous tests."""
        if self.test_files:
            for fname in self.test_files:
                paths = [os.path.join(os.curdir, fname),
                          os.path.join(os.getcwd(), fname),
                          os.path.join(TEST_DIR, fname)]
                for fpath in paths:
                    if os.path.exists(fpath):
                        logger.debug("Removing test file %s" % fname)
                        os.unlink(fpath)

    def construct_temp_conf_file(self):
        """Populates a configuration template, and writes to a file pointer."""
        template_fpath = os.path.join(TEST_DIR, 'etc', self.config_name)
        conf_contents = open(template_fpath).read()
        self.config_params['service_port'] = utils.get_unused_port()
        logger.debug("Assigned port %s to service" %
                     self.config_params['service_port'])
        self.config_params['admin_port'] = utils.get_unused_port()
        logger.debug("Assigned port %s to admin" %
                     self.config_params['admin_port'])

        conf_contents = conf_contents % self.config_params
        self.conf_fp = tempfile.NamedTemporaryFile()
        self.conf_fp.write(conf_contents)
        self.conf_fp.flush()
        logger.debug("Create test configuration file: %s" % self.conf_fp.name)
        client_tests.TEST_CONFIG_FILE_NAME = self.conf_fp.name

    def setUp(self):
        pass

    def startServer(self):
        """ Starts a Keystone server on random ports for testing """
        self.server = None
        self.admin_server = None

        self.construct_temp_conf_file()

        # Set client certificate for test client
        if self.isSsl:
            logger.debug("SSL testing will use cert_file %s" % TEST_CERT)
            os.environ['cert_file'] = TEST_CERT
        else:
            if 'cert_file' in os.environ:
                del os.environ['cert_file']

        # indicating HP-IDM is disabled
        if self.hpidmDisabled:
            logger.debug("HP-IDM extensions is disabled")
            os.environ['HP-IDM_Disabled'] = 'True'
        else:
            if 'HP-IDM_Disabled' in os.environ:
                del os.environ['HP-IDM_Disabled']

        # run the keystone server
        logger.info("Starting the keystone server...")

        class SilentOptParser(optparse.OptionParser):
            """ Class used to prevent OptionParser from exiting when it detects
            options coming in for nose/testing """
            def exit():
                pass

            def error(self, msg):
                pass

        parser = SilentOptParser(version='%%prog %s' %
                                       keystone.version.version())
        common_group = config.add_common_options(parser)
        config.add_log_options(parser)

        # Handle a special argument to support starting two endpoints
        common_group.add_option(
            '-a', '--admin-port', dest="admin_port", metavar="PORT",
            help="specifies port for Admin API to listen "
                 "on (default is 35357)")

        # Parse arguments and load config
        (options, args) = config.parse_options(parser)
        options['config_file'] = self.conf_fp.name

        # Populate the CONF module
        CONF.reset()
        CONF(config_files=[self.conf_fp.name])

        try:
            # Load Service API Server
            service = keystone.server.Server(name="Service API",
                                            config_name='keystone-legacy-auth',
                                            args=args)
            service.start(wait=False)

            # Client tests will use these globals to find out where
            # the server is
            client_tests.TEST_TARGET_SERVER_SERVICE_PROTOCOL = service.protocol
            client_tests.TEST_TARGET_SERVER_SERVICE_ADDRESS = service.host
            client_tests.TEST_TARGET_SERVER_SERVICE_PORT = service.port

        except RuntimeError, e:
            logger.exception(e)
            raise e

        try:
            # Load Admin API server
            port = int(CONF.admin_port or
                    client_tests.TEST_TARGET_SERVER_ADMIN_PORT)
            host = (CONF.admin_host or
                    client_tests.TEST_TARGET_SERVER_ADMIN_ADDRESS)
            admin = keystone.server.Server(name='Admin API',
                    config_name='admin', args=args)
            admin.start(host=host, port=port, wait=False)

            # Client tests will use these globals to find out where
            # the server is
            client_tests.TEST_TARGET_SERVER_ADMIN_PROTOCOL = admin.protocol
            client_tests.TEST_TARGET_SERVER_ADMIN_ADDRESS = admin.host
            client_tests.TEST_TARGET_SERVER_ADMIN_PORT = admin.port

        except RuntimeError, e:
            logger.exception(e)
            raise e

        self.server = service
        self.admin_server = admin

        # Load bootstrap data
        from keystone import manage
        manage_args = ['--config-file', self.conf_fp.name]
        manage.parse_args(args=manage_args)

        #TODO(zns): this should end up being run by a 'bootstrap' script
        fixtures = [
            ('role', 'add', CONF.keystone_admin_role),
            ('user', 'add', 'admin', 'secrete'),
            ('role', 'grant', CONF.keystone_admin_role, 'admin'),
            ('role', 'add', CONF.keystone_service_admin_role),
            ('role', 'add', 'Member'),
            ]
        for cmd in fixtures:
            manage.process(*cmd)

    def tearDown(self):
        try:
            if self.server is not None:
                print "Stopping the Service API..."
                self.server.stop()
                self.server = None
            if self.admin_server is not None:
                print "Stopping the Admin API..."
                self.admin_server.stop()
                self.admin_server = None
            if self.conf_fp:
                self.conf_fp.close()
                self.conf_fp = None
        except Exception as e:
            logger.exception(e)
            print "Error cleaning up %s" % e
            raise e
        finally:
            self.clear_database()
            if 'cert_file' in os.environ:
                del os.environ['cert_file']
            if 'HP-IDM_Disabled' in os.environ:
                del os.environ['HP-IDM_Disabled']
            reload(client_tests)

    def run(self, args=None):
        try:
            print 'Running test suite: %s' % self.__class__.__name__

            self.setUp()

            # discover and run tests

            # If any argument looks like a test name but doesn't have
            # "keystone.test" in front of it, automatically add that so we
            # don't have to type as much
            show_elapsed = True
            argv = []
            if args is None:
                args = sys.argv
            has_base = False
            for x in args:
                if x.startswith(('functional', 'unit', 'client')):
                    argv.append('keystone.test.%s' % x)
                    has_base = True
                elif x.startswith('--hide-elapsed'):
                    show_elapsed = False
                elif x.startswith('-'):
                    argv.append(x)
                else:
                    argv.append(x)
                    if x != args[0]:
                        has_base = True

            if not has_base and self.directory_base is not None:
                argv.append(self.directory_base)
            argv = ['--no-path-adjustment'] + argv[1:]
            logger.debug("Running set of tests with args=%s" % argv)

            c = noseconfig.Config(stream=sys.stdout,
                              env=os.environ,
                              verbosity=3,
                              workingDir=TEST_DIR,
                              plugins=core.DefaultPluginManager(),
                              args=argv)

            runner = NovaTestRunner(stream=c.stream,
                                    verbosity=c.verbosity,
                                    config=c,
                                    show_elapsed=show_elapsed)

            result = not core.run(config=c, testRunner=runner, argv=argv)
            return int(result)  # convert to values applicable to sys.exit()
        except Exception, exc:
            logger.exception(exc)
            raise exc
        finally:
            self.tearDown()


def runtests():
    """This function can be called from 'python setup.py test'."""
    return SQLTest().run()


class UnitTests(KeystoneTest):
    """ Class that runs unit tests """
    directory_base = 'unit'

    def run(self):
        """ Run unit tests

        Filters arguments and leaves only ones relevant to unit tests
        """

        argv = []
        scoped_to_unit = False
        for x in sys.argv:
            if x.startswith(('functional', 'client')):
                # Skip, since we're not running unit tests
                return
            elif x.startswith('unit'):
                argv.append('keystone.test.%s' % x)
                scoped_to_unit = True
            else:
                argv.append(x)

        if not scoped_to_unit:
            argv.append('keystone.test.unit')

        return super(UnitTests, self).run(args=argv)


class ClientTests(KeystoneTest):
    """ Class that runs client tests

    Client tests are the tests that need a running http[s] server running
    and make web service calls to that server

    """
    config_name = 'sql.conf.template'
    directory_base = 'client'

    def run(self):
        """ Run client tests

        Filters arguments and leaves only ones relevant to client tests
        """

        argv = []
        scoped_to_client = False
        for x in sys.argv:
            if x.startswith(('functional', 'unit')):
                # Skip, since we're not running client tests
                return
            elif x.startswith('client'):
                argv.append('keystone.test.%s' % x)
                scoped_to_client = True
            else:
                argv.append(x)

        if not scoped_to_client:
            argv.append('keystone.test.client')

        self.startServer()

        return super(ClientTests, self).run(args=argv)


class SQLTest(KeystoneTest):
    """Test defined using only SQLAlchemy back-end"""
    config_name = 'sql.conf.template'
    test_files = ('keystone.sqltest.db',)
    directory_base = 'functional'

    def run(self):
        """ Run client tests

        Filters arguments and leaves only ones relevant to client tests
        """

        argv = []
        scoped_to_functional = False
        for x in sys.argv:
            if x.startswith(('client', 'unit')):
                # Skip, since we're not running functional tests
                return
            elif x.startswith('functional'):
                argv.append('keystone.test.%s' % x)
                scoped_to_functional = True
            else:
                argv.append(x)

        if not scoped_to_functional:
            argv.append('keystone.test.functional')

        return super(SQLTest, self).run(args=argv)

    def clear_database(self):
        # Disconnect the database before deleting
        from keystone.backends import sqlalchemy
        sqlalchemy.unregister_models()

        super(SQLTest, self).clear_database()


class SSLTest(ClientTests):
    config_name = 'ssl.conf.template'
    isSsl = True
    test_files = ('keystone.ssltest.db',)


class MemcacheTest(SQLTest):
    """Test defined using only SQLAlchemy and Memcache back-end"""
    config_name = 'memcache.conf.template'
    test_files = ('keystone.memcachetest.db',)


class LDAPTest(SQLTest):
    """Test defined using only SQLAlchemy and LDAP back-end"""
    config_name = 'ldap.conf.template'
    test_files = ('keystone.ldaptest.db', 'ldap.db', 'ldap.db.db',)

    def clear_database(self):
        super(LDAPTest, self).clear_database()
        from keystone.backends.ldap.fakeldap import FakeShelve
        db = FakeShelve().get_instance()
        db.clear()


class ClientWithoutHPIDMTest(ClientTests):
    """Test with HP-IDM disabled to make sure it is backward compatible"""
    config_name = 'sql_no_hpidm.conf.template'
    hpidmDisabled = True
    test_files = ('keystone.nohpidm.db',)
