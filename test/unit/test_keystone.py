import unittest
from webtest import TestApp
import httplib2
import pprint
import bottle
from keystone.identity import app_factory
try:
    import simplejson as json
except ImportError:
    import json

class identity_test(unittest.TestCase):
    def setUp(self):
        self.url='http://localhost:8080'
        self.tenant=143134
        self.tenant_dumb=143000
        self.tenant_group='Admin_Tenant_Group'
        
            
    def tearDown(self):
         
         pass
    #given _a_ to make inherited test cases in an order. 
    #here to call below method will call as last test case
    def test_a_create_tenant(self):
        h = httplib2.Http(".cache")
        url= '%s/tenants' % self.url
        body='{"tenant": { "id": "%s", \
                "description": "A description ...", "enabled"\
                :true  } }' % self.tenant
        resp,content= h.request(url,"POST",body=body,\
                                headers={"Content-Type":"application/json"})
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', resp['content-type'])
        
    
        
    #given _z_ to make inherited test cases in an order. 
    #here  below method will call as last test case    
    
    def test_z_delete_tenant(self):
        h = httplib2.Http(".cache")
        url='%s/tenants/%s' % (self.url,self.tenant)
        resp,content= h.request(url,"DELETE", body='{}',\
                                headers={"Content-Type":"application/json"})
        self.assertEqual(200, int(resp['status']))
        

class create_tenants(identity_test):
           
   
    def test_create_tenant_create_again(self):
        
        h = httplib2.Http(".cache")
        url='%s/tenants' % self.url
        body='{"tenant": { "id": "%s", \
                "description": "A description ...", "enabled"\
                :true  } }' % self.tenant
        #test for Content-Type = application/json
        resp,content= h.request(url,"POST",body=body,\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(403, int(resp['status']))
    
    def test_create_tenant_wrong_url(self):
        
        h = httplib2.Http(".cache")
        url='%s/tenant' % self.url
        body='{"tenant": { "id": "%s", \
                "description": "A description ...", "enabled"\
                :true  } }' % self.tenant
        #test for Content-Type = application/json
        resp,content= h.request(url,"POST",body=body,\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(404, int(resp['status']))
    
    
    def test_create_tenant_wrong_method(self):
        
        h = httplib2.Http(".cache")
        url='%s/tenants' % self.url
        body='{"tenant": { "id": "%s", \
                "description": "A description ...", "enabled"\
                :true  } }' % self.tenant
        #test for Content-Type = application/json
        resp,content= h.request(url,"PUT",body=body,\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(405, int(resp['status']))
    
    def test_create_tenant_wrong_data(self):
        
        h = httplib2.Http(".cache")
        url='%s/tenants'%self.url
        body='{"tenant": { "id": "%s", \
                "description_wrong": "A description ...", "enabled"\
                :"asdf" } }' % self.tenant
        #test for Content-Type = application/json
        resp,content= h.request(url,"POST",body=body,\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(400, int(resp['status']))
            

               
    

class get_tenants(identity_test):
    
    def test_get_tenants(self):
        h = httplib2.Http(".cache")
        url='%s/tenants' % (self.url)
        #test for Content-Type = application/json
        resp,content= h.request(url,"GET", body={},\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(200, int(resp['status']))
    
        
class get_tenant(identity_test):
    
    
    
    def test_get_tenant(self):
        h = httplib2.Http(".cache")
        url='%s/tenants/%s' % (self.url, self.tenant)
        #test for Content-Type = application/json
        resp,content= h.request(url,"GET", body='{}',\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(200, int(resp['status']))
    
    def test_get_tenant_bad(self):
        h = httplib2.Http(".cache")
        url='%s/tenants/%s' % (self.url, self.tenant)
        #test for Content-Type = application/json
        resp,content= h.request(url,"GET", body='{',\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(400, int(resp['status']))
    
    def test_get_tenant_not_found(self):
        h = httplib2.Http(".cache")
        url='%s/tenants/NonexistingID' % (self.url)
        #test for Content-Type = application/json
        resp,content= h.request(url,"GET", body='{}',\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(404, int(resp['status']))
    
    
class update_tenant(identity_test):
    
    def test_update_tenant(self):
        h = httplib2.Http(".cache")
        url='%s/tenants/%s' % (self.url, self.tenant)
        data='{"tenant": { "description": "A NEW description..."  }}'
        #test for Content-Type = application/json
        resp,content= h.request(url,"PUT", body=data,\
                                headers={"Content-Type": "application/json"})
        body = json.loads(content)
        self.assertEqual(200, int(resp['status']))    
        self.assertEqual(self.tenant, int(body['tenant']['id']))
        self.assertEqual('A NEW description...', \
                         body['tenant']['description'])
    
    def test_update_tenant_bad(self):
        h = httplib2.Http(".cache")
        url='%s/tenants/%s' % (self.url, self.tenant)
        data='{"tenant": { "description_bad": "A NEW description..."  }}'
        #test for Content-Type = application/json
        resp,content= h.request(url,"PUT", body=data,\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(400, int(resp['status']))
    
    def test_update_tenant_not_found(self):
        h = httplib2.Http(".cache")
        url='%s/tenants/NonexistingID' % (self.url)
        data='{"tenant": { "description": "A NEW description..."  }}'
        #test for Content-Type = application/json
        resp,content= h.request(url,"GET", body=data,\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(404, int(resp['status']))    
       
class delete_tenant(identity_test):
    
    def test_delete_tenant_not_found(self):
        h = httplib2.Http(".cache")
        url='%s/tenants/nonexisting' % (self.url)
        #test for Content-Type = application/json
        resp,content= h.request(url,"DELETE", body='{}',\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(404, int(resp['status']))
    

class tenant_group(identity_test):  
    
    def test_b_tenant_group(self):
        h = httplib2.Http(".cache")
        url='%s/tenant/%s/groups' % (self.url,self.tenant)
        body='{"group": { "id" : "%s", \
                "description" : "A Description of the group..."} } ' \
                % self.tenant_group        
        resp,content= h.request(url,"POST", body=body,\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(200, int(resp['status']))
    def test_a_create_tenant_dumb(self):
        h = httplib2.Http(".cache")
        url= '%s/tenants' % self.url
        body='{"tenant": { "id": "%s", \
                "description": "A dumb description ...", "enabled"\
                :false  } }' % self.tenant_dumb
        resp,content= h.request(url,"POST",body=body,\
                                headers={"Content-Type":"application/json"})
        self.assertEqual(200, int(resp['status']))
        self.assertEqual('application/json', resp['content-type'])
    def test_z_delete_tenant_dumb(self):
        h = httplib2.Http(".cache")
        url='%s/tenants/%s' % (self.url,self.tenant_dumb)
        resp,content= h.request(url,"DELETE", body='{}',\
                                headers={"Content-Type":"application/json"})
        self.assertEqual(200, int(resp['status']))    
    def test_y_tenant_group_delete(self):
        h = httplib2.Http(".cache")
        url='%s/tenant/%s/groups/%s' % (self.url,self.tenant,self.tenant_group)
        body='{}'        
        resp,content= h.request(url,"DELETE", body=body,\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(200, int(resp['status']))
        
class create_tenant_group(tenant_group):     

    def test_tenant_group_forbidden(self):
        #tenant_id enabled=false
        h = httplib2.Http(".cache")
        url='%s/tenant/%s/groups' % (self.url,self.tenant_dumb)
        body='{"group": { "id" : "%s", \
                "description" : "A Description of the group..."} } '\
                % self.tenant_group       
        resp,content= h.request(url,"POST",body=body,\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(403, int(resp['status']))
    
    
    def test_tenant_group_wrong_url(self):
        
        h = httplib2.Http(".cache")
        url='%s/tenants/%s/groups_wrong' % (self.url,self.tenant)
        body='{"group": { "id" : "%s", \
                "description" : "A Description of the group..."} } '\
                % self.tenant_group        
        resp,content= h.request(url,"POST",body=body,\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(404, int(resp['status']))
    
    
    def test_tenant_group_method_not_allowed(self):
        
        h = httplib2.Http(".cache")
        url='%s/tenant/%s/groups' % (self.url,self.tenant)
        body='{"group": { "id" : "%s", \
                "description" : "A Description of the group..."} } '\
                % self.tenant_group 
                
        resp,content= h.request(url,"PUT",body=body,\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(405, int(resp['status']))
    
    def test_tenant_group_bad_request(self):
        
        h = httplib2.Http(".cache")
        url='%s/tenant/%s/groups' % (self.url,self.tenant)
        body='{"group": { "id" : "%s", \
                "description_bad" : "A Description of the group..."} } '\
                % self.tenant_group 
        resp,content= h.request(url,"POST",body=body,\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(400, int(resp['status']))  
    
    def test_tenant_group_conflict(self):
        h = httplib2.Http(".cache")
        url='%s/tenant/%s/groups' % (self.url,self.tenant)
        body='{"group": { "id" : "%s", \
                "description" : "A Description of the group..."} } ' \
                % self.tenant_group        
        resp,content= h.request(url,"POST", body=body,\
                                headers={"Content-Type": "application/json"})
        self.assertEqual(409, int(resp['status']))


def tgs_template(self,tenant,group,method,body="{}"):
        h = httplib2.Http(".cache")
        url='%s/tenant/%s/groups' % (self.url,tenant)
        
        resp,content= h.request(url,method,body=body,\
                                headers={"Content-Type": "application/json"})
        return (resp,content)
    
class get_tenant_groups(tenant_group):       

    def test_get_tenant_groups(self):
        resp,content=tgs_template(self,self.tenant,self.tenant_group,"GET")
        
        self.assertEqual(200, int(resp['status']))
    
    def test_get_tenant_groups_forbidden(self):

        resp,content=tgs_template(self,self.tenant_dumb,self.tenant_group,"GET")
        self.assertEqual(403, int(resp['status']))
    def test_get_tenant_group_bad_method(self):
        resp,content=tgs_template(self,self.tenant,self.tenant_group,"PUT")
        self.assertEqual(405, int(resp['status']))

def tg_template(self,tenant,group,method,body="{}"):
        h = httplib2.Http(".cache")
        url='%s/tenant/%s/groups/%s' % (self.url,tenant,group)
        resp,content= h.request(url,method,body=body,\
                                headers={"Content-Type": "application/json"})
        return (resp,content)

class get_tenant_group(tenant_group):       
    
    def test_get_tenant_group(self):
        resp,content=tg_template(self,self.tenant,self.tenant_group,"GET")
        self.assertEqual(200, int(resp['status']))
    
    def test_get_tenant_group_no_group(self):
        resp,content=tg_template(self,self.tenant,'non_existing',"GET")
        self.assertEqual(404, int(resp['status']))
    
    
    def test_get_tenant_group_forbidden(self):
        resp,content=tg_template(self,self.tenant_dumb,self.tenant_group,"GET")
        self.assertEqual(403, int(resp['status']))
    
    
    def test_get_tenant_group_no_tenant(self):
        resp,content=tg_template(self,'non_existing',self.tenant_group,"GET")
        self.assertEqual(401, int(resp['status']))
        
    def test_get_tenant_group_bad_method(self):
        resp,content=tg_template(self,'non_existing',self.tenant_group,"POST")
        self.assertEqual(405, int(resp['status']))
     
    
def utg_template(self,tenant,group,method):
        h = httplib2.Http(".cache")
        body='{"group":{"tenantId" : "%s","id" : "%s",\
            "description" : "A New description of the group..." \
            }}' % (tenant,group)

        url='%s/tenant/%s/groups/%s' % (self.url,tenant,group)
        resp,content= h.request(url,method,body=body,\
                                headers={"Content-Type": "application/json"})
        
        return (resp,content)

class update_tenant_group(tenant_group):       
    
    def test_update_tenant_group(self):
        resp,content=utg_template(self,self.tenant,self.tenant_group,"PUT")
        self.assertEqual(200, int(resp['status']))
    
    def test_update_tenant_group_no_group(self):
        resp,content=utg_template(self,self.tenant,'non_existing',"PUT")
        self.assertEqual(404, int(resp['status']))
    
    
    def test_update_tenant_group_forbidden(self):
        resp,content=utg_template(self,self.tenant_dumb,self.tenant_group,"PUT")
        
        self.assertEqual(403, int(resp['status']))
    
    
    def test_update_tenant_group_no_tenant(self):
        resp,content=utg_template(self,'non_existing',self.tenant_group,"PUT")
        self.assertEqual(404, int(resp['status']))
        
    def test_update_tenant_group_bad_method(self):
        resp,content=utg_template(self,'non_existing',self.tenant_group,"POST")
        self.assertEqual(405, int(resp['status']))
        
if __name__ == '__main__':
    unittest.main()