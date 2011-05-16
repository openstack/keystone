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

    
class TestServer(unittest.TestCase):
    '''Unit tests for server.py.'''
    
    request = bottle.Request()
    response = bottle.Response()
    auth_data = auth.AuthData(auth.Token(date.today(),"2231312"), auth.User("username","12345",auth.Groups([],[])))
    
    def setUp(self):
        server.request = self.request
        server.response = self.response
        
    #def tearDown(self):
    
    def test_error(self):
        msg = 'Access denied!'
        error = HTTPError(401, msg)
        retVal = server.error_handler(error)
        self.assertEqual(retVal,msg)
    
    def test_is_xml_response(self):
        self.assertFalse(server.is_xml_response())
        self.request.header["Accept"] = "application/xml"
        self.assertTrue(server.is_xml_response())
    
    def test_send_result_xml(self):
        self.request.header["Accept"] = "application/xml"
        xml_str = server.send_result(200,self.auth_data);
        self.assertTrue(self.response.content_type=="application/xml")
        xml = etree.fromstring(xml_str)

        user = xml.find("{http://docs.openstack.org/idm/api/v1.0}user")
        token = xml.find("{http://docs.openstack.org/idm/api/v1.0}token")
        
        self.assertTrue(user.get("username"),"username")
        self.assertTrue(user.get("tenantId"),'12345');
        self.assertTrue(token.get("id"),'2231312');
        self.assertTrue(token.get("expires"),date.today());
        
    def test_send_result_json(self):
        self.request.header["Accept"] = "application/json"
        json_str = server.send_result(200,self.auth_data);
        self.assertTrue(self.response.content_type=="application/json")
        dict = json.loads(json_str)
        self.assertTrue(dict['auth']['user']['username'],'username');
        self.assertTrue(dict['auth']['user']['tenantId'],'12345');
        self.assertTrue(dict['auth']['token']['id'],'2231312');
        self.assertTrue(dict['auth']['token']['expires'],date.today());
        
    def test_get_auth_token(self):
        self.request.header["X-Auth-Token"]="Test token"
        self.assertTrue(server.get_auth_token(),"Test Token")
    
    def test_get_normalized_request_content_exception(self):
        self.assertRaises(fault.IDMFault,server.get_normalized_request_content,None)
    
    def test_get_normalized_request_content_xml(self):
        self.request.environ["CONTENT_TYPE"]="application/xml"
        pwd_cred = auth.PasswordCredentials("username","password","1")
        body = '<?xml version="1.0" encoding="UTF-8"?> \
                <passwordCredentials \
                xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="secret" username="disabled" \
                />'
        str=StringIO()
        str.write(body)
        self.request.environ["wsgi.input"]=str
        self.request.environ["CONTENT_LENGTH"] = str.len
        #TODO: I THINK THIS belongs in a test for auth.py. 
    
        
if __name__ == '__main__':
    unittest.main()