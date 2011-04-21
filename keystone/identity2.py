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

@route('/v1.0/token', method='POST')
def authenticate():
    return "Authenticate"

@route('/v1.0/token/:token_id', method='GET')
def validate_token(token_id):
    return "Good token "+token_id+" is good!"

@route('/v1.0/token/:token_id', method='DELETE')
def delete_token(token_id):
    return "Deleting "+token_id

run(host='localhost', port=8080)
