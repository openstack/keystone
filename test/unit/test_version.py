import os
import sys
# Need to access identity module
sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__),
                                '..', '..', '..', '..', 'keystone')))
import unittest
import httplib2
import test_common as utils

class version_test(unittest.TestCase):

    #Given _a_ to make inherited test cases in an order.
    #here to call below method will call as last test case

    def test_a_get_version_json(self):
        header = httplib2.Http(".cache")
        resp, content = header.request(utils.URL, "GET", body="",
                                  headers={"Content-Type": "application/json"})
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', utils.content_type(resp))

    def test_a_get_version_xml(self):
        header = httplib2.Http(".cache")
        resp, content = header.request(utils.URL, "GET", body="",
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))



if __name__ == '__main__':
    unittest.main()
