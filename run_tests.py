#!/usr/bin/env python

"""
To run all tests
    python run_tests.py

To run a single test:
    python run_tests.py
        functional.test_extensions:TestExtensions.test_extensions_json

To run a single test module:
    python run_tests.py functional.test_extensions

"""
import logging
import os
import sys
import subprocess

import keystone.tools.tracer  # @UnusedImport # module runs on import
from keystone import test

logger = logging.getLogger(__name__)

TESTS = [
    test.UnitTests,
    test.ClientTests,
    test.SQLTest,
    test.SSLTest,
    test.ClientWithoutHPIDMTest,
    test.LDAPTest,
    # Waiting on instructions on how to start memcached in jenkins:
    # But tests pass
    # MemcacheTest,
]


def parse_suite_filter():
    """ Parses out -O or --only argument and returns the value after it as the
    filter. Removes it from sys.argv in the process. """

    filter = None
    if '-O' in sys.argv or '--only' in sys.argv:
        for i in range(len(sys.argv)):
            if sys.argv[i] in ['-O', '--only']:
                if len(sys.argv) > i + 1:
                    # Remove -O/--only settings from sys.argv
                    sys.argv.pop(i)
                    filter = sys.argv.pop(i)
                    break
    return filter


if __name__ == '__main__':
    filter = parse_suite_filter()
    if filter:
        TESTS = [t for t in TESTS if filter in str(t)]
        if not TESTS:
            print 'No test configuration by the name %s found' % filter
            sys.exit(2)
    #Run test suites
    if len(TESTS) > 1:
        directory = os.getcwd()
        for test_num, test_cls in enumerate(TESTS):
            try:
                result = test_cls().run()
                if result:
                    logger.error("Run returned %s for test %s. Exiting" %
                                 (result, test_cls.__name__))
                    sys.exit(result)
            except Exception, e:
                print "Error:", e
                logger.exception(e)
                sys.exit(1)
            # Collect coverage from each run. They'll be combined later in .sh
            if '--with-coverage' in sys.argv:
                coverage_file = os.path.join(directory, ".coverage")
                target_file = "%s.%s" % (coverage_file, test_cls.__name__)
                try:
                    if os.path.exists(target_file):
                        logger.info("deleting %s" % target_file)
                        os.unlink(target_file)
                    if os.path.exists(coverage_file):
                        logger.info("Saving %s to %s" % (coverage_file,
                                                         target_file))
                        os.rename(coverage_file, target_file)
                except Exception, e:
                    logger.exception(e)
                    print ("Failed to move coverage file while running test"
                           ": %s. Error reported was: %s" %
                           (test_cls.__name__, e))
                    sys.exit(1)
    else:
        for test_num, test_cls in enumerate(TESTS):
            try:
                result = test_cls().run()
                if result:
                    logger.error("Run returned %s for test %s. Exiting" %
                                 (result, test_cls.__name__))
                    sys.exit(result)
            except Exception, e:
                print "Error:", e
                logger.exception(e)
                sys.exit(1)
