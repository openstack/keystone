import os
import sys
# Need to access identity module
sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__),
                                '..', '..', '..', '..', 'keystone')))
import unittest
from webtest import TestApp
import httplib2
import json
from lxml import etree
import unittest
from webtest import TestApp
from test_common import *

class version_test(unittest.TestCase):

    #Given _a_ to make inherited test cases in an order.
    #here to call below method will call as last test case

    def test_a_get_version_json(self):
        h = httplib2.Http(".cache")
        url = URL
        resp, content = h.request(url, "GET", body="",
                                  headers={"Content-Type":"application/json"})
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', content_type(resp))

    def test_a_get_version_xml(self):
        h = httplib2.Http(".cache")
        url = URL
        resp, content = h.request(url, "GET", body="",
                                  headers={"Content-Type": "application/xml",
                                           "ACCEPT": "application/xml"})

        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/xml', content_type(resp))
        
def run():
    unittest.main()
    
if __name__ == '__main__':
    unittest.main()
