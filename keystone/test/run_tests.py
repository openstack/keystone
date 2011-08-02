"""Manages execution of keystone test suites"""
import os
import sys
import subprocess
import time

TEST_DIR = os.path.dirname(__file__)

CONFIG_FILES = (
    'keystone.sql.conf',
    'keystone.memcache.conf',
    'keystone.ldap.conf')

TEMP_FILES = (
    'keystone.db',
    'keystone.token.db',
    'ldap.db',
    'ldap.db.db')

def delete_temp_files():
    """Quietly deletes any temp files in the test directory"""
    for path in TEMP_FILES:
        subprocess.call(['rm', '-f', os.path.join(TEST_DIR, path)])

if __name__ == '__main__':
    for config in CONFIG_FILES:
        # remove any pre-existing temp files
        delete_temp_files()

        # populate the test database
        subprocess.check_call([
            os.path.join(TEST_DIR, '..', '..', 'bin', 'sampledata.sh'),
            '-c', os.path.join(TEST_DIR, '..', '..', config)])

        try:
            # run the keystone SERVER
            SERVER = subprocess.Popen([
                os.path.join(TEST_DIR, '..', '..', 'bin', 'keystone'),
                '-c', os.path.join(TEST_DIR, '..', '..', config)])

            # blatent hack.
            time.sleep(3)
            if SERVER.poll() is not None:
                print >> sys.stderr, 'Failed to start SERVER'
                sys.exit(-1)

            try:
                # run tests
                subprocess.check_call(['unit2', 'discover', 'keystone.test'])
            finally:
                #kill the keystone SERVER
                SERVER.kill()
        finally:
            delete_temp_files()
