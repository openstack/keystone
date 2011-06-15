#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# Tenants
./keystone-manage $* tenant add 1234
./keystone-manage $* tenant add ANOTHER:TENANT
./keystone-manage $* tenant add 0000
./keystone-manage $* tenant disable 0000

# Users
./keystone-manage $* user add joeuser secrete 1234
./keystone-manage $* user add joeadmin secrete 1234
./keystone-manage $* user add admin secrete
./keystone-manage $* user add disabled secrete 1234
./keystone-manage $* user disable disabled

# Roles
./keystone-manage $* role add Admin
./keystone-manage $* role grant Admin admin
./keystone-manage $* role grant Admin joeadmin 1234
./keystone-manage $* role grant Admin joeadmin ANOTHER:TENANT

#BaseURLs
./keystone-manage $* baseURLs add RegionOne swift http://swift.publicinternets.com/v1/AUTH_%tenant_id% http://swift.admin-nets.local:8080/ http://127.0.0.1:8080/v1/AUTH_%tenant_id% 1
./keystone-manage $* baseURLs add RegionOne nova http://nova.publicinternets.com/v1.1/%tenant_id% http://nova.admin-nets.local/v1.1/%tenant_id% http://127.0.0.1:8774/v1.1/%tenant_id% 1
./keystone-manage $* baseURLs add RegionOne glance http://glance.publicinternets.com/v1.1/%tenant_id% http://nova.admin-nets.local/v1.1/%tenant_id% http://127.0.0.1:9292/v1.1/%tenant_id% 1
./keystone-manage $* baseURLs add RegionOne cdn http://cdn.publicinternets.com/v1.1/%tenant_id% http://cdn.admin-nets.local/v1.1/%tenant_id% http://127.0.0.1:7777/v1.1/%tenant_id% 1

# Groups
#./keystone-manage $* group add Admin 1234
#./keystone-manage $* group add Default 1234
#./keystone-manage $* group add Empty 0000

# User Group Associations
#./keystone-manage $* user joeuser join Default
#./keystone-manage $* user disabled join Default
#./keystone-manage $* user admin join Admin

# Tokens
./keystone-manage $* token add 887665443383838 joeuser 1234 2012-02-05T00:00
./keystone-manage $* token add 999888777666 admin 1234 2015-02-05T00:00
./keystone-manage $* token add 000999 admin 1234 2010-02-05T00:00
./keystone-manage $* token add 999888777 disabled 1234 2015-02-05T00:00

#Tenant Role
./keystone-manage $* tenant_baseURL add 1234 1
./keystone-manage $* tenant_baseURL add 1234 2
./keystone-manage $* tenant_baseURL add 1234 3
