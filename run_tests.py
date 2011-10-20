#!/usr/bin/env python

"""Manages execution of keystone test suites"""
from keystone.test import KeystoneTest


class SQLTest(KeystoneTest):
    """Test defined using only SQLAlchemy back-end"""
    config_name = 'sql.conf.template'
    test_files = ('keystone.db',)


class SSLTest(KeystoneTest):
    config_name = 'ssl.conf.template'
    test_files = ('keystone.db',)
    isSsl = True


class MemcacheTest(KeystoneTest):
    """Test defined using only SQLAlchemy and Memcache back-end"""
    config_name = 'memcache.conf.template'
    test_files = ('keystone.db',)


class LDAPTest(KeystoneTest):
    """Test defined using only SQLAlchemy and LDAP back-end"""
    config_name = 'ldap.conf.template'
    test_files = ('keystone.db', 'ldap.db', 'ldap.db.db',)

TESTS = [
    SQLTest,
    # currently failing, and has yet to pass in jenkins: MemcacheTest,
    LDAPTest,
    SSLTest,
]

if __name__ == '__main__':
    for test_num, test_cls in enumerate(TESTS):
        print 'Starting test %d of %d with config: %s' % \
            (test_num + 1, len(TESTS), test_cls.config_name)
        test_cls().run()
