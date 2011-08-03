import os
import sys
import subprocess
import time

if __name__ == '__main__':
    test_dir = os.path.dirname(__file__)

    #remove pre-existing test databases
    subprocess.call(['rm', os.path.join(test_dir, 'keystone.db')])
    subprocess.call(['rm', os.path.join(test_dir, 'keystone.token.db')])
    subprocess.call(['rm', os.path.join(test_dir, 'ldap.db')])
    subprocess.call(['rm', os.path.join(test_dir, 'ldap.db.db')])

    # populate the test database
    subprocess.check_call([os.path.join(test_dir, '../../bin/sampledata.sh')])

    try:
        # run the keystone server
        server = subprocess.Popen([os.path.join(test_dir,
                                                '../../bin/keystone')])

        # blatent hack.
        time.sleep(3)
        if server.poll() is not None:
            print >> sys.stderr, 'Failed to start server'
            sys.exit(-1)

        try:
            # run unit tests
            subprocess.check_call(
                ['python', os.path.join(test_dir, 'unit/test_keystone.py')])

            # run system tests
            subprocess.check_call(
                ['unit2', 'discover', 'keystone.test.system'])
        finally:
            #kill the keystone server
            server.kill()
    finally:
        # remove test databases
        subprocess.call(['rm', os.path.join(test_dir, 'keystone.db')])
        subprocess.call(['rm', os.path.join(test_dir, 'keystone.token.db')])
        subprocess.call(['rm', os.path.join(test_dir, 'ldap.db')])
        subprocess.call(['rm', os.path.join(test_dir, 'ldap.db.db')])
