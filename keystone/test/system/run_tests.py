import os
import sys
import subprocess
import time

if __name__ == '__main__':
    test_dir = os.path.dirname(__file__)

    # remove pre-existing test databases
    subprocess.call(['rm', os.path.join(test_dir, 'keystone.db')])
    subprocess.call(['rm', os.path.join(test_dir, 'keystone.token.db')])

    # populate the test database
    subprocess.check_call([os.path.join(test_dir,
        '../../../bin/bootstrap.sh')])

    try:
        # run the keystone server
        server = subprocess.Popen([os.path.join(test_dir,
            '../../../bin/keystone')])

        # blatent hack to wait for the server to start
        time.sleep(1)
        if server.poll() is not None:
            print >> sys.stderr, 'Failed to start server'
            sys.exit(-1)

        try:
            # run system tests
            subprocess.call(
                ['unit2', 'discover', 'keystone.test.system'])
        finally:
            #kill the keystone server
            server.kill()
    finally:
        # remove test databases
        subprocess.call(['rm', os.path.join(test_dir, 'keystone.db')])
        subprocess.call(['rm', os.path.join(test_dir, 'keystone.token.db')])
