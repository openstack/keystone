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
"""
Implement a client for Echo service using Identity service
"""

import httplib
import simplejson


def get_auth_token(username, password, tenant):
    headers = {"Content-type": "application/json", "Accept": "text/json"}
    params = '{"passwordCredentials": { "username": "' + username + '", "password": "' + password + '", "tenantId": "1"}}'
    conn = httplib.HTTPConnection("localhost:8080")
    conn.request("POST", "/v1.0/token", params, headers=headers)
    response = conn.getresponse()
    data = response.read()
    ret = data
    return ret

def call_service(token):
    headers = {"X-Auth-Token": token, "Content-type": "application/json", "Accept": "text/json"}
    params = '{"ping": "abcdefg"}'
    conn = httplib.HTTPConnection("localhost:8090")
    conn.request("POST", "/", params, headers=headers)
    response = conn.getresponse()
    data = response.read()
    ret = data
    return ret

if __name__ == '__main__':
    # Call the keystone service to get a token (assumes the test_setup.sql script has loaded this user)
    auth = get_auth_token("joeuser", "secrete", "1")
    obj = simplejson.loads(auth)
    token = obj["auth"]["token"]["id"]
    print "Token:", token

    # Use that token to call an OpenStack service (we're using the Echo sample service for now)
    data = call_service(token)
    print "Response:", data
    