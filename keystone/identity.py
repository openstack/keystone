# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Not Yet PEP8 standardized

import bottle
from bottle import route
from bottle import run
from bottle import request
from bottle import debug
from bottle import abort
from bottle import Bottle
from bottle import EventletServer
import ConfigParser
from datetime import datetime
from datetime import timedelta
import eventlet
from eventlet import wsgi
import hashlib
from httplib2 import Http
import os
from paste.deploy import loadapp
try:
    import simplejson as json
except ImportError:
    import json
import sqlite3
import urllib
import uuid


"""
Identity: a pluggable auth server concept for OpenStack
"""
class Identity(object):
    def __init__(self, environ, start_response):
        self.envr  = environ
        self.start = start_response

    class Tenants:
        # Tenant functionality
        @route('/tenants', method='POST')
        @route('/v1.0/tenants', method='POST')
        def create_tenant():
            '''
                Creating Tenants by doing a POST on /tenants
                Request Body:
                {"tenant":
                    {
                        "id": "1234",
                            "description": "A description ...",
                            "enabled": true
                    }
                }
            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                                 'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE']
                if content in content_types:
                    if content == 'application/json':
                        body = json.loads(request.body.readline())
                        tenant_id = body['tenant']['id']
                        tenant_desc = body['tenant']['description']
                        tenant_enabled = body['tenant']['enabled']


                        dbpath = os.path.abspath(
                            os.path.join(os.path.dirname(__file__),
                                '../db/keystone.db'))
                        con = sqlite3.connect(dbpath)
                        cur = con.cursor()
                        try:
                            cur.execute(
                                "INSERT INTO tenants VALUES ('%s', '%s', %d)" %
                                (tenant_id, tenant_desc, tenant_enabled))
                        except IntegrityError:
                            abort(403, "tenant id already exists")
                        con.commit()
                        con.close()

                    elif content == 'application/xml':
                        #TODO: Implement XML support
                        return "whatever, we don't have XML yet"

                    accept_header = request.header.get('Accept')
                    if accept_header in content_types:
                        if accept_header == 'application/json':
                            return body
                        elif accept_header == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"
                    else:
                        # If there is no Accept header, the default is JSON.
                        #TODO: Make sure that the body is actually JSON.
                        return body

            return 'it did NOT work\n'

        @route('/tenants/:tenantId', method='GET')
        @route('/v1.0/tenants', method='POST')
        def get_tenant(tenantId):
            '''
                Getting/Retrieving Tenants by doing a GET on /tenants
            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE']
                if content in content_types:
                    if content == 'application/json':
                        body = json.loads(request.body.readline())
                        dbpath = os.path.abspath(
                            os.path.join(os.path.dirname(__file__),
                                         '../db/keystone.db'))

                        con = sqlite3.connect(dbpath)
                        cur = con.cursor()
                        cur.execute(
                                     "SELECT * FROM tenants WHERE tenant_id='%s'" %
                                     (str(tenantId)))
                        a = cur.fetchone()
                        if a:
                            enabled = a[2]
                            if enabled == 0:
                                enabled = "false"
                            if enabled == 1:
                                enabled = "true"
                        con.close()

                    elif content == 'application/xml':
                        #TODO: Implement XML support
                        return "whatever, we don't have XML yet"

                    accept_header = request.header.get('Accept')
                    if accept_header in content_types:
                        if accept_header == 'application/json':
                            return '{"tenant" : { "id":"%s", "description":\
                                "%s", "enabled": "%s"}}' % (a[0], a[1], enabled)
                        elif accept_header == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"
                    else:
                        # If there is no Accept header, the default is JSON.
                        #TODO: Make sure that the body is actually JSON.
                        #return body
                        return '{"tenant" : { "id":"%s", "description":\
                                "%s", "enabled": "%s"}}' % (a[0], a[1], enabled)

            return 'it did NOT work\n'

        @route('/tenants', method='GET')
        @route('/v1.0/tenants', method='GET')
        def get_tenants():
            '''
                Getting/Retrieving all Tenants by doing a GET on /tenants
            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE']
                if content in content_types:
                    if content == 'application/json':
                        dbpath = os.path.abspath(
                            os.path.join(os.path.dirname(__file__),
                                '../db/keystone.db'))
                        con = sqlite3.connect(dbpath)
                        cur = con.cursor()
                        cur.execute("SELECT * FROM tenants")
                        #a=cur.fetchone()
                        tenant_str = ""

                        for a in cur:
                            enabled = a[2]
                            if enabled == 0:
                                enabled = "false"
                            if enabled == 1:
                                enabled = "true"
                            tenant_str = tenant_str + '{"id": "%s",\
                            "description": "%s", "enabled":"%s" }' %(a[0],\
                                    a[1], enabled)
                            #if cur.fetchone():
                            #    tenant_str=tenant_str+","

                        #con.commit()
                        con.close()

                    elif content == 'application/xml':
                        #TODO: Implement XML support
                        return "whatever, we don't have XML yet"

                    accept_header = request.header.get('Accept')
                    if accept_header in content_types:
                        if accept_header == 'application/json':
                            ret_str = ""

                            ret_str = ret_str + '{"tenants": { "values": [ "' \
                                    + tenant_str +'"]}}'
                            return ret_str
                        elif accept_header == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"
                    else:
                        # If there is no Accept header, the default is JSON.
                        #TODO: Make sure that the body is actually JSON.
                        #return body
                        ret_str = ""

                        ret_str = ret_str + '{ "tenants": { "values": [ "'\
                                + tenant_str + '"]}}'
                        return ret_str

            return 'it did NOT work\n'


        @route ('/tenants/:tenantId', method='PUT')
        @route ('/v1.0/tenants/:tenantId', method='PUT')
        def update_tenant(tenantId):
            '''
                Updating Tenants by doing a PUT on /tenants
                Request Body:
                {"tenant":
                    {

                            "description": "A  New description ...",

                    }
                }
            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE']
                if content in content_types:
                    if content == 'application/json':
                        body = json.loads(request.body.readline())
                        tenant_desc = body['tenant']['description']
                        dbpath = os.path.abspath(
                            os.path.join(os.path.dirname(__file__),
                                '../db/keystone.db'))
                        con = sqlite3.connect(dbpath)
                        cur = con.cursor()
                        cur.execute(
                            "UPDATE tenants SET tenant_desc='%s' WHERE tenant_id='%s'" %
                            (tenant_desc, tenantId))
                        con.commit()
                        con.close()

                    elif content == 'application/xml':
                        #TODO: Implement XML support
                        return "whatever, we don't have XML yet"

                    accept_header = request.header.get('Accept')
                    if accept_header in content_types:
                        if accept_header == 'application/json':
                            return body
                        elif accept_header == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"
                    else:
                        # If there is no Accept header, the default is JSON.
                        #TODO: Make sure that the body is actually JSON.
                        return body

            return 'it did NOT work\n'

        @route ('/tenants/:tenantId', method='DELETE')
        @route ('/v1.0/tenants/:tenantId', method='DELETE')
        def delete_tenant(tenantId):
            '''
                Deleting Tenants by doing a Delete on /tenants
                Request Body:
                {"tenant":
                    {
                        "id": "1234"
                    }
                }
            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE']
                if content in content_types:
                    if content == 'application/json':
                        body = json.loads(request.body.readline())
                        dbpath = os.path.abspath(
                            os.path.join(os.path.dirname(__file__),
                                '../db/keystone.db'))
                        con = sqlite3.connect(dbpath)
                        cur = con.cursor()
                        cur.execute(
                            "DELETE FROM tenants WHERE tenant_id='%s'" %
                            (tenantId))
                        con.commit()
                        con.close()

                    elif content == 'application/xml':
                        #TODO: Implement XML support
                        return "whatever, we don't have XML yet"

                    accept_header = request.header.get('Accept')
                    if accept_header in content_types:
                        if accept_header == 'application/json':
                            return "Tenant Successfully deleted"
                        elif accept_header == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"
                    else:
                        # If there is no Accept header, the default is JSON.
                        #TODO: Make sure that the body is actually JSON.
                        return "Tenant Successfully deleted"

            return 'it did NOT work\n'



        #Tenant Group Functionalities

        @route('tenant/:tenantId/groups', method='POST')
        @route('/v1.0/tenant/:tenantId/groups', method='POST')
        def create_tenant_group(tenantId):
            """
                Creating tenant by doing a POST on /tenant/:tenantId/groups
                {"group":
                            {
                            "id" : "Admin",
                            "description"  : "A Description of the group..."
                            }
                }

            """

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json','application/xml','text/xml']
                content = request.environ['CONTENT_TYPE']
                if content in content_types:
                        if content == 'application/json':
                            if tenantId:
                                    body = json.loads(request.body.readline())
                                    try:
                                        group_id = body['group']['id']
                                        group_desc = body['group']['description']
                                    except:
                                        return abort(400, "Bad Request")

                                    dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__),'../db/keystone.db'))
                                    con = sqlite3.connect(dbpath)
                                    con.row_factory = sqlite3.Row
                                    cur = con.cursor()
                                    cur.execute("SELECT * FROM tenants WHERE tenant_id='%s'" % (tenantId))
                                    t = cur.fetchone()
                                    print t
                                    if t is not None:
                                        if not t['tenant_enabled']:
                                            abort(403, "Tenant Disabled")
                                    else:
                                        abort(401, "unauthorized")
                                    # Finding group Exists or not
                                    cur.execute("SELECT * FROM groups WHERE tenant_id='%s' AND group_id='%s' " % (tenantId,group_id))
                                    a=cur.fetchone()


                                    if a is not None:
                                        return  abort(409, "Group already exists")

                                    else:
                                            try:
                                                cur.execute("INSERT INTO groups ('group_id','tenant_id','group_desc') VALUES ('%s','%s', '%s')" % (group_id.strip(),tenantId,group_desc))
                                                con.commit()

                                                return '{"group":{"tenantId" : "%s","id" : "%s","description" : "%s"}}' % (group_id.strip(),tenantId,group_desc)
                                            except Exception,e:
                                                return abort(500,"IDM Fault Creation Failed")
                                    con.close()


                        elif content == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"

            return 'it did NOT work\n'


        @route('/tenant/:tenantId/groups/:groupId', method='PUT')
        @route('/v1.0/tenant/:tenantId/groups/:groupId', method='PUT')
        def update_tenant_group(tenantId, groupId):


            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE']
                if content in content_types:
                        if content == 'application/json':
                            if tenantId and groupId:
                                body = json.loads(request.body.readline())
                                dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__),'../db/keystone.db'))
                                group_desc = body['group']['description']
                                con = sqlite3.connect(dbpath)
                                cur = con.cursor()
                                # Finding group Exists or not
                                tenant=cur.execute("SELECT * FROM tenants WHERE tenant_id='%s'" % (tenantId))
                                t=cur.fetchone()
                                resp=''
                                #count=tenant.rowcount
                                if t is not None:
                                    #if not t[2] == 1:
                                        # checking Tenant Enabled  or not
                                    #    return  abort(403, "Tenant disabled")

                                    cur.execute("SELECT * FROM groups WHERE tenant_id='%s' AND group_id='%s' " % (tenantId,groupId))
                                    group=cur.fetchone()

                                    if group is not None:
                                        cur.execute("UPDATE groups SET group_desc='%s' WHERE tenant_id='%s' AND group_id='%s' " % (group_desc,tenantId,groupId))
                                        con.commit()
                                        resp='{"group": { "tenantId" : "%s","id" : "%s","description" : "%s"}}' % (group[2],group[0],group[1])
                                        return resp
                                    else:

                                        return  abort(404, "Group Not Found")
                                else:
                                    return  abort(401, "unauthorized")
                                con.close()
                            else:
                                return  abort(400, "Bad Request")
                        elif content == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"
            return 'it did NOT work\n'

        @route('/v1.0/tenant/:tenantId/groups/:groupId', method='DELETE')
        @route('/tenant/:tenantId/groups/:groupId', method='DELETE')
        def delete_tenant_group(tenantId, groupId):
            '''
                Deleting Tenant Group /tenants/tenantId/groups/groupId
                given curl url has /tenants/:1234/groups/:Admin
                Response looks like this:
                   Sucessfully Deleted

            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE'];
                if content in content_types:

                        if content == 'application/json':
                            if tenantId and groupId:


                                dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__),'../db/keystone.db'))
                                con = sqlite3.connect(dbpath)
                                con.row_factory = sqlite3.Row
                                cur = con.cursor()
                                # Finding group Exists or not
                                tenant=cur.execute("SELECT * FROM tenants WHERE tenant_id='%s'" % (tenantId))
                                t=cur.fetchone()
                                resp=''
                                #count=tenant.rowcount
                                if t is not None:
                                    if t['tenant_enabled'] == 0:
                                        # checking Tenant Enabled  or not
                                        return  abort(403, "Tenant disabled")

                                    cur.execute("SELECT * FROM groups WHERE tenant_id='%s' AND group_id='%s' " % (tenantId,groupId))
                                    group=cur.fetchone()

                                    if group is not None:
                                        cur.execute("DELETE FROM groups WHERE tenant_id='%s' AND group_id='%s' " % (tenantId,groupId))
                                        con.commit()
                                        resp='Group Successfully Deleted'
                                        return resp
                                    else:

                                        return  abort(404, "Group Not Found")
                                else:
                                    return  abort(401, "unauthorized")
                                con.close()
                            else:
                                return  abort(400, "Bad Request")
                        elif content == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"
            return 'it did NOT work\n'

        @route('/tenant/:tenantId/groups', method='GET')
        @route('/v1.0/tenant/:tenantId/groups', method='GET')
        def get_tenant_groups(tenantId):
            '''
                Getting all Tenant Groups /tenant/tenantId/groups GET

               Response will be like

                {"groups": {
                            "values" : [
                                {
                                "tenantId" : "1234",
                                "id" : "Admin",
                                "description" : "A description ..."
                                },
                                {
                                "tenantId" : "1234",
                                "id" : "Technical",
                                "description" : "Another description ..."
                                }
                                        ]
                            }
                }

            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE'];
                if content in content_types:
                        if content == 'application/json':
                            if tenantId:
                                dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__),'../db/keystone.db'))
                                con = sqlite3.connect(dbpath)
                                con.row_factory = sqlite3.Row
                                cur = con.cursor()
                                # Finding group Exists or not
                                tenant=cur.execute("SELECT * FROM tenants WHERE tenant_id='%s'" % (tenantId))
                                t=cur.fetchone()
                                resp=''

                                if t is not None:
                                    print t['tenant_enabled']
                                    if int(t['tenant_enabled']) < 0:
                                         # checking Tenant Enabled  or not
                                        return  abort(403, "Tenant disabled")

                                    groups_exec=cur.execute("SELECT * FROM groups WHERE tenant_id='%s'" % (tenantId))
                                    groups=groups_exec.fetchall()

                                    if groups.rowcount > 100:
                                        return abort(413,"Over Limit")

                                    else:
                                        print "in here"
                                        resp+='{"groups": { "values" : ['
                                        gresp=''
                                        for group in groups:
                                            if gresp=='':
                                                gresp+='{"tenantId" : "%s","id" : "%s","description" : "%s"}' % (group['tenant_id'],group['group_id'],group['group_desc'])
                                            else:
                                                gresp+=',{"tenantId" : "%s","id" : "%s","description" : "%s"}'  % (group['tenant_id'],group['group_id'],group['group_desc'])
                                        resp+=gresp+']}}'
                                        return resp


                                else:
                                    return  abort(401, "unauthorized")
                                con.close()
                            else:
                                return  abort(400, "Bad Request")
                        elif content == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"

            return 'it did NOT work\n'


        @route('/v1.0/tenant/:tenantId/groups/:groupId', method='GET')
        @route('/tenant/:tenantId/groups/:groupId', method='GET')
        def get_tenant_group(tenantId, groupId):
            '''
                Getting Tenant Group /tenant/tenantId/groups/groupId
            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE']
                if content in content_types:
                        if content == 'application/json':
                            if tenantId and groupId:
                                dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__),'../db/keystone.db'))
                                con = sqlite3.connect(dbpath)
                                con.row_factory = sqlite3.Row
                                cur = con.cursor()
                                # Finding group Exists or not
                                tenant=cur.execute("SELECT * FROM tenants WHERE tenant_id='%s'" % (tenantId))
                                t=cur.fetchone()
                                resp=''
                                if t is not None:
                                    if int(t['tenant_enabled']) < 0:
                                        # checking Tenant Enabled  or not
                                        return  abort(403, "Tenant disabled")

                                    cur.execute("SELECT * FROM groups WHERE tenant_id='%s' AND group_id='%s' " % (tenantId,groupId))
                                    group=cur.fetchone()

                                    if not group == None:
                                        resp='{"group": { "tenantId" : "%s","id" : "%s","description" : "%s"}}' % (group['tenant_id'],group['group_id'],group['group_desc'])
                                        return resp
                                    else:

                                        return  abort(404, "Group Not Found")
                                else:
                                    return  abort(401, "unauthorized")
                                con.close()
                            else:
                                return  abort(400, "Bad Request")
                        elif content == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"

            return 'it did NOT work\n'

        @route('/v1.0/:tenantId/groups/:groupId/users', method='GET')
        @route('/tenants/:tenantId/groups/:groupId/users', method='GET')
        def get_group_users(tenantId, groupId):
            '''
                Getting Tenant Group /tenant/tenantId/groups/groupId
            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE']
                if content in content_types:
                        if content == 'application/json':
                            if tenantId and groupId:
                                dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__),'../db/keystone.db'))
                                con = sqlite3.connect(dbpath)
                                con.row_factory = sqlite3.Row
                                cur = con.cursor()
                                # Finding group Exists or not
                                tenant = cur.execute("SELECT * FROM tenants WHERE tenant_id='%s'" % (tenantId))
                                t = cur.fetchone()
                                resp = ''
                                count = tenant.rowcount
                                if count:
                                    if int( t['tenant_enabled']) < 0:
                                        # checking Tenant Enabled  or not
                                        return  abort(403, "Tenant disabled")

                                    users=cur.execute("SELECT u.* FROM users u INNER JOIN user_group ug ON u.id=ug.user_id where ug.group_id='%s' " %(groupId))


                                    if users.rowcount > 100:
                                        return abort(413,"Over Limit")

                                    else:
                                        print 'in here'
                                        resp+='{"users": { "values" : ['
                                        uresp=''
                                        for user in users:
                                            if uresp=='':
                                                uresp+='{"id":"%s","tenantId" : "%s","email" : "%s","enabled" : "%s"}' % (user['id'],tenantId,user['email'],user['enabled'])
                                            else:
                                                uresp+='{"id":"%s","tenantId" : "%s","email" : "%s","enabled" : "%s"}' % (user['id'],tenantId,user['email'],user['enabled'])
                                        resp+=uresp+']}}'

                                        return resp


                                else:
                                    return  abort(401, "unauthorized")
                                con.close()
                            else:
                                return  abort(400, "Bad Request")
                        elif content == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"
            return 'it did NOT work\n'

        @route('/tenants/:tenantId/groups/:groupId/users', method='PUT')
        @route('/v1.0/tenants/:tenantId/groups/:groupId/users', method='PUT')
        def add_group_user(tenantId, groupId):
            '''
                Getting Tenant Group /tenant/tenantId/groups/groupId
            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE'];
                if content in content_types:
                        if content == 'application/json':
                            body = json.loads(request.body.readline())
                            username = body['username']
                            print username
                            if tenantId and groupId and username:
                                dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__),'../db/keystone.db'))
                                con = sqlite3.connect(dbpath)
                                con.row_factory = sqlite3.Row
                                cur = con.cursor()
                                # Finding group Exists or not
                                tenant=cur.execute("SELECT * FROM tenants WHERE tenant_id='%s'" % (tenantId))
                                t=cur.fetchone()

                                if t is not None:
                                    if int(t['tenant_enabled']) < 0:
                                        # checking Tenant Enabled  or not
                                        return  abort(403, "Tenant disabled")
                                    cur.execute("SELECT count(*) FROM groups WHERE tenant_id='%s' AND group_id='%s' " % (tenantId,groupId))
                                    tenant_group=cur.fetchone()

                                    if tenant_group is None:
                                        return  abort(409, "NO such group exists ")
                                    cur.execute(
                                        "SELECT * FROM users WHERE id='%s'" %
                                        (username)
                                        )
                                    result=cur.fetchone()
                                    if result is None:
                                        return abort(409,"User doesn't exists")

                                    cur.execute("select COUNT(*) from user_group where user_id='%s' AND group_id='%s'" % (username,groupId))
                                    username_conflict=cur.fetchone()
                                    if(int(username_conflict[0]) > 0):
                                        abort(409,"Username Conflict")
                                    cur.execute(
                                       "INSERT INTO user_group(user_id,group_id) VALUES ('%s','%s')" %
                                        (username,groupId))
                                    con.commit()
                                    con.close()
                                    return '{"user_id":'+ username+',"group_id": '+groupId+'}'
                                else:
                                    return  abort(401, "unauthorized")
                                con.close()
                            else:
                                return  abort(400, "Bad Request")
                        elif content == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"
            return 'it did NOT work\n'

        @route('/v1.0/tenants/:tenantId/groups/:groupId/users', method='DELETE')
        @route('/tenants/:tenantId/groups/:groupId/users', method='DELETE')
        def remove_group_user(tenantId, groupId):
            '''
                Getting Tenant Group /tenant/tenantId/groups/groupId
            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE']
                if content in content_types:
                        if content == 'application/json':
                            body = json.loads(request.body.readline())
                            try:

                                username = body['username']
                            except:
                                return  abort(400, "Bad Request")
                            if tenantId and groupId:
                                dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__),'../db/keystone.db'))
                                con = sqlite3.connect(dbpath)
                                con.row_factory = sqlite3.Row
                                cur = con.cursor()
                                # Finding group Exists or not
                                tenant=cur.execute("SELECT * FROM tenants WHERE tenant_id='%s'" % (tenantId))
                                t=cur.fetchone()
                                resp=''

                                if t is not None:
                                    if not t['tenant_enabled']:
                                        # checking Tenant Enabled  or not
                                        return  abort(403, "Tenant disabled")
                                    cur.execute("SELECT count(*) FROM groups WHERE tenant_id='%s' AND group_id='%s' " % (tenantId,groupId))
                                    a=cur.fetchone()

                                    if a is None:
                                        return  abort(409, "NO such group exists ")
                                    cur.execute(
                                        "SELECT * FROM users WHERE id='%s'" %
                                        (username)
                                        )
                                    result=cur.fetchone()
                                    if result is None:
                                        return abort(409,"User doesn't exists")
                                    cur.execute("select COUNT(*) from user_group where user_id='%s' AND group_id='%s'" % (username,groupId))
                                    user_group=cur.fetchone()
                                    if user_group is  None:
                                        abort(409,"user doesn't exists in the group")
                                    cur.execute("DELETE from user_group where user_id='%s' AND group_id='%s'" % (username,groupId))
                                    con.commit()
                                    con.close()
                                    return '{"User":""%s" removed from "%s" successfully" }' % (username,groupId)
                                else:
                                    return  abort(401, "unauthorized")
                                con.close()
                            else:
                                return  abort(400, "Bad Request")
                        elif content == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"

            return 'it did NOT work\n'

        # User Functionalities

        """
            Created a simple create user functionality for testing
            will be updated to after testing
        """

        @route ('/v1.0/tenants/:tenantId/users', method='POST')
        @route ('/tenants/:tenantId/users', method='POST')
        def create_user(tenantId):
            '''
                Creating users by doing a POST on /users
            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE'];
                if content in content_types:

                    if content == 'application/json':
                        body = json.loads(request.body.readline())

                        try:
                            username = body['user']['username']
                            password = body['user']['password']
                            email=body['user'] ['email']
                            enabled=body['user']['enabled']
                        except:
                            return abort(400,'Bad Request')

                    elif content == 'application/xml':
                        #TODO: Implement XML support
                        return "whatever, we don't have XML yet"
                    dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__), '../db/keystone.db'))
                    con = sqlite3.connect(dbpath)
                    cur = con.cursor()
                    cur.execute("select * from tenants where tenant_id='%s'" % (str(tenantId)))
                    result=cur.fetchone()

                    if result is not None:

                        if (int(result[2]) == 0):
                            return abort(403,"Forbidden")
                    else:
                        return abort(401,"Unauthorised")

                    cur.execute("select COUNT(*) from users where id='%s'" % (username))
                    username_conflict=cur.fetchone()

                    if(int(username_conflict[0]) > 0):
                        abort(409,"Username Conflict")
                    cur.execute("select count(*) from users where email='%s'"%(email))
                    email_conflict=cur.fetchone()
                    if( int(email_conflict[0]) > 0):
                        abort(409,"Email Conflict")
                    cur.execute(
                       "INSERT INTO users VALUES ('%s','%s','%s','%d')" %
                        (username,password,email,enabled))
                    con.commit()
                    con.close()

                    accept_header = request.header.get('Accept')
                    if accept_header in content_types:
                        if accept_header == 'application/json':
                            return '{"User":"created successfully" }'
                        elif accept_header == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have  XML yet"
                    else:
                        # If there is no Accept header, the default is JSON.
                        #TODO: Make sure that the body is actually JSON.

                        return '{"User":"created successfully" }'

            return 'it did NOT work\n'

        # Token Functionalities

        @route ('/v1.0/tokens', method='POST')
        @route ('/tokens', method='POST')
        def create_token():
            '''
            Creating token by doing a POST on /tokens
            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                                 'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE']
                if content in content_types:
                        if content == 'application/json':
                            dbpath = os.path.abspath(os.path.join(os.path.dirname(__file__),'../db/keystone.db'))
                            body = json.loads(request.body.readline())

                            try:
                                username = body['username']
                                password = body['password']

                                if 'tenant_id' in body:
                                    tenant_id= body['tenant_id']
                            except:

                                return abort(400,'Bad Request')

                        elif content == 'application/xml':
                            #TODO: Implement XML support
                            return "whatever, we don't have XML yet"
                        con = sqlite3.connect(dbpath)
                        con.row_factory = sqlite3.Row
                        cur = con.cursor()
                        cur.execute(
                                    "SELECT * FROM users WHERE id='%s' AND password='%s'" %
                                    (username, password)
                                    )

                        result=cur.fetchone()
                        if result is not None:

                            if (int(result['enabled']) == 0):
                                return abort(403,"UserDisabled")
                            accept_header = request.header.get('Accept')
                            token=hashlib.sha224(str(username+password)+str(datetime.now())).hexdigest()[:21]
                            expires=datetime.now()+timedelta(minutes=1)
                            con = sqlite3.connect(dbpath,detect_types=sqlite3.PARSE_DECLTYPES)
                            cur = con.cursor()
                            cur.execute(
                               'insert into token(token_id,expires,user_id) values(?, ?, ?)',(token, expires,username))

                            con.commit()
                            con.close()
                            if accept_header in content_types:
                                if accept_header == 'application/json':

                                    return '{"token":'+token+',"expires": '+str(expires)+'}'
                                elif accept_header == 'application/xml':
                                    #TODO: Implement XML support
                                    return "whatever, we don't have XML yet"
                            else:
                                # If there is no Accept header, the default is JSON.
                                #TODO: Make sure that the body is actually JSON.

                                return '{"token":'+ token+',"expires": '+str(expires)+'}'
                        else:

                            return  abort(401, "Unauthorised user")

            return 'it did NOT work\n'

        @route('/v1.0/token/:token_id', method='POST')
        @route('/token/:token_id', method='POST')
        def validate_token(token_id):
            '''
                Validating token by doing a GET on /token/token_id
            '''

            if('belongsto' in request.GET):
                tenantid=request.GET.get('belongsto')

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE'];
                if content in content_types:
                        dbpath = os.path.abspath(
                            os.path.join(os.path.dirname(__file__),
                                '../db/keystone.db'))
                        con = sqlite3.connect(dbpath)
                        con.row_factory = sqlite3.Row
                        cur = con.cursor()
                        cur.execute(
                            "SELECT * FROM token WHERE token_id='%s' " %
                            (token_id))
                        row=cur.fetchone()
                        if row is None:
                            abort(401, "Token doesnot exists")
                        else:
                            user=row['user_id']
                            cur.execute(
                            "SELECT * FROM users WHERE id='%s' " %
                            (user))
                            result=cur.fetchone()
                            if (int(result['enabled']) == 0):
                                return abort(403,"UserDisabled")
                            expires=datetime.strptime(row['expires'],"%Y-%m-%d %H:%M:%S.%f")
                            if(expires<datetime.now()):
                                abort(401, "Token Expired")
                            else:
                                groups=cur.execute("SELECT * FROM groups WHERE tenant_id='%s'" % (tenantid))
                                resp=''
                                if groups.rowcount > 100:
                                    return abort(413,"Over Limit")
                                else:
                                    resp+='{"groups": { "values" : ['
                                    gresp=''
                                    for group in groups:
                                        if gresp=='':
                                            gresp+='{"tenantId" : "%s","id" : "%s","description" : "%s"}' % (group['tenant_id'],group['group_id'],group['group_desc'])
                                        else:
                                            gresp+=',{"tenantId" : "%s","id" : "%s","description" : "%s"}' % (group['tenant_id'],group['group_id'],group['group_desc'])
                                    resp+=gresp+']}}'


                            #return '{ "token": {"id": "'+a[0]+'", "expires": "2010-11-01T03:32:15-05:00"}}'
                                return '{"auth" : { "token": {"id": "%s", "expires": "%s"}, "user" :{"%s", "username": "%s", "tenantId": "%s"}}}' % (str(row['token_id']),str(row['expires']),resp,user,tenantid)

            return 'it did NOT work\n'

        @route('/v1.0/token/:token_id', method='DELETE')
        @route('/token/:token_id', method='DELETE')
        def revoke_token(token_id):
            '''
                Revoking token by doing a DELETE on /token/token_id
            '''

            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE']

                if content in content_types:
                    try:
                        dbpath = os.path.abspath(
                            os.path.join(os.path.dirname(__file__),
                                '../db/keystone.db'))
                        con = sqlite3.connect(dbpath)
                        con.row_factory = sqlite3.Row
                        cur = con.cursor()
                        cur.execute(
                            "SELECT * FROM token WHERE token_id='%s' " %
                            (token_id))
                        row=cur.fetchone()
                        if row is None:
                            abort(401, "Token doesnot exists")
                        else:
                            user=row['user_id']
                            cur.execute(
                            "SELECT * FROM users WHERE id='%s' " %
                            (user))
                            result=cur.fetchone()
                            if (int(result['enabled']) == 0):
                                return abort(403,"UserDisabled")
                            expires=datetime.strptime(row['expires'],"%Y-%m-%d %H:%M:%S.%f")
                            if(expires<datetime.now()):
                                abort(401, "Token Expired")
                            else:

                                cur.execute(
                            "DELETE FROM token WHERE token_id='%s' " %
                            (token_id))
                            con.commit()
                            con.close()
                            #return '{ "token": {"id": "'+a[0]+'", "expires": "2010-11-01T03:32:15-05:00"}}'
                            return abort(204, 'Token revoked')
                    except:
                        return abort(500, "IDM fault")

            return 'it did NOT work\n'




        # Version functionality

        @route('/version', method='GET')
        def getVersion():
            if 'CONTENT_TYPE' in request.environ:
                content_types = ['text/plain', 'application/json',
                    'application/xml', 'text/xml']
                content = request.environ['CONTENT_TYPE']
                if content in content_types:

                    if content == 'application/json':
                        config = ConfigParser.ConfigParser()
                        config.read('keystone.ini')
                        return "{'version':'%s'}" % config.get('DEFAULT', 'version')

                    elif content == 'application/xml':
                        #TODO: Implement XML support
                        return "whatever, we don't have XML yet"

            return 'it did NOT work\n'


def app_factory(global_conf, **local_conf):
    return Identity

if __name__ == "__main__":
    app = loadapp('config:keystone.ini', relative_to=".", \
       global_conf={"log_name":"keystone.log"})
    bottle.run(host='localhost', port=8080, reloader=True)
