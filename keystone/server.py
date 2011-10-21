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
Service that stores identities and issues and manages tokens

HEADERS
-------

* HTTP\_ is a standard http header
* HTTP_X is an extended http header

Coming in from initial call
^^^^^^^^^^^^^^^^^^^^^^^^^^^

HTTP_X_AUTH_TOKEN
    the client token being passed in

HTTP_X_STORAGE_TOKEN
    the client token being passed in (legacy Rackspace use) to support
    cloud files

Used for communication between components
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

www-authenticate
    only used if this component is being used remotely

HTTP_AUTHORIZATION
    basic auth password used to validate the connection

What we add to the request for use by the OpenStack SERVICE
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HTTP_X_AUTHORIZATION
    the client identity being passed in

"""
from keystone.routers.service import ServiceApi
from keystone.routers.admin import AdminApi


def service_app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating OpenStack API server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)
    return ServiceApi(conf)


def admin_app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating OpenStack API server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)
    return AdminApi(conf)
