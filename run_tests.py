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
import sys
import subprocess

import keystone.tools.tracer  # @UnusedImport # module runs on import
from keystone import test


TESTS = [
    test.SQLTest,
    test.LDAPTest,
    # Waiting on instructions on how to start memcached in jenkins:
    # But tests pass
    # MemcacheTest,
    test.SSLTest,
]


if __name__ == '__main__':
    if '-O' in sys.argv:
        filter = None
        for i in range(len(sys.argv)):
            if sys.argv[i] == '-O':
                if len(sys.argv) > i + 1:
                    filter = sys.argv[i + 1]
                    # Remove -O settings from sys.argv
                    argv = sys.argv[0:i]
                    if len(sys.argv) > i:
                        argv += sys.argv[i + 2:]
                    sys.argv = argv[:]
                    break
        if filter:
            TESTS = [t for t in TESTS if filter in str(t)]
            if not TESTS:
                print 'No tests by the name %s found' % filter
                exit()

    if len(TESTS) > 1:
        # We have a problem with resetting SQLAlchemy, so we need to fire
        # off a separate process for each test now
        for test_num, test_cls in enumerate(TESTS):
            params = ["python", __file__, '-O',
                      str(test_cls.__name__)] + sys.argv[1:]
            p = subprocess.Popen(params)
            result = p.wait()
            if result:
                sys.exit(result)

    else:
        for test_num, test_cls in enumerate(TESTS):
            print 'Starting test %d of %d with config: %s' % \
                (test_num + 1, len(TESTS), test_cls.config_name)
            if test_cls().run():
                exit(1)
