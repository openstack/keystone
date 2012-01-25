import os
import subprocess
import sys
import unittest2 as unittest

import keystone.test.client as client_tests
from keystone.test import sampledata
from keystone import manage

# Calculate root path so ewe call files in bin
possible_topdir = os.path.normpath(os.path.join(os.path.abspath(__file__),
                                   os.pardir,
                                   os.pardir,
                                   os.pardir,
                                   os.pardir))


class TestKeystoneManage(unittest.TestCase):
    """
    Tests for the keystone-manage client.
    """

    def test_check_can_call_keystone_manage(self):
        """
        Test that we can call keystone-manage
        """
        cmd = [
            os.path.join(possible_topdir, 'bin', 'keystone-manage'),
            '--help',
        ]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        result = process.communicate()[0]
        self.assertIn('usage', result.lower())

    def test_keystone_manage_calls(self):
        """
        Test that we can call keystone-manage and all sampledata calls work
        """
        cmd = [
            os.path.join(possible_topdir, 'bin', 'keystone-manage'),
            '-c', client_tests.TEST_CONFIG_FILE_NAME,
            '--log-file', os.path.join(possible_topdir, 'bin', 'keystone.log'),
            'service', 'list'
        ]
        # This will init backends
        manage.parse_args(cmd[1:])

        # Loop through and try sampledata calls
        sampledata_calls = sampledata.DEFAULT_FIXTURE
        for call in sampledata_calls:
            manage.process(*call)

if __name__ == '__main__':
    unittest.main()
