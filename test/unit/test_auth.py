import bottle
import unittest
import os
import sys
import json



TOP_DIR =  os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                        os.pardir,
                                        os.pardir))

if os.path.exists(os.path.join(TOP_DIR, 'keystone', '__init__.py')):
    sys.path.insert(0, TOP_DIR)
    
from keystone import server
import keystone.logic.types.auth as auth
import keystone.logic.types.fault as fault

from StringIO import StringIO
from bottle import HTTPError
from bottle import request
from datetime import date
from lxml import etree

    
class TestAuth(unittest.TestCase):
    '''Unit tests for auth.py.'''
    
    pwd_xml = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="secret" username="disabled" \
                />'
    
    def test_pwd_cred_marshall(self):
        creds = auth.PasswordCredentials.from_xml(self.pwd_xml)
        self.assertTrue(creds.password,"secret")
        self.assertTrue(creds.username,"username")
    
        
if __name__ == '__main__':
    unittest.main()