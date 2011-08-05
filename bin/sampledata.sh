#!/bin/bash -e
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
`dirname $0`/keystone-manage $* tenant add 1234
`dirname $0`/keystone-manage $* tenant add ANOTHER:TENANT
`dirname $0`/keystone-manage $* tenant add 0000
`dirname $0`/keystone-manage $* tenant disable 0000

# Users
`dirname $0`/keystone-manage $* user add joeuser secrete 1234
`dirname $0`/keystone-manage $* user add joeadmin secrete 1234
`dirname $0`/keystone-manage $* user add admin secrete 1234
`dirname $0`/keystone-manage $* user add serviceadmin secrete 1234
`dirname $0`/keystone-manage $* user add disabled secrete 1234
`dirname $0`/keystone-manage $* user disable disabled

# Roles
`dirname $0`/keystone-manage $* role add Admin
`dirname $0`/keystone-manage $* role add KeystoneServiceAdmin
`dirname $0`/keystone-manage $* role grant Admin admin
`dirname $0`/keystone-manage $* role grant KeystoneServiceAdmin serviceadmin
`dirname $0`/keystone-manage $* role grant Admin joeadmin 1234
`dirname $0`/keystone-manage $* role grant Admin joeadmin ANOTHER:TENANT

`dirname $0`/keystone-manage $* role add Member
`dirname $0`/keystone-manage $* role grant Member joeuser 1234


#Keeping for compatibility for a while till dashboard catches up - endpointTemplates
`dirname $0`/keystone-manage $* endpointTemplates add RegionOne swift http://swift.publicinternets.com/v1/AUTH_%tenant_id% http://swift.admin-nets.local:8080/ http://127.0.0.1:8080/v1/AUTH_%tenant_id% 1 0
`dirname $0`/keystone-manage $* endpointTemplates add RegionOne nova_compat http://nova.publicinternets.com/v1.0/ http://127.0.0.1:8774/v1.0  http://localhost:8774/v1.0 1 0
`dirname $0`/keystone-manage $* endpointTemplates add RegionOne nova http://nova.publicinternets.com/v1.1/ http://127.0.0.1:8774/v1.1  http://localhost:8774/v1.1 1 0
`dirname $0`/keystone-manage $* endpointTemplates add RegionOne glance http://glance.publicinternets.com/v1.1/%tenant_id% http://nova.admin-nets.local/v1.1/%tenant_id% http://127.0.0.1:9292/v1.1/%tenant_id% 1 0
`dirname $0`/keystone-manage $* endpointTemplates add RegionOne cdn http://cdn.publicinternets.com/v1.1/%tenant_id% http://cdn.admin-nets.local/v1.1/%tenant_id% http://127.0.0.1:7777/v1.1/%tenant_id% 1 0

#endpointTemplates
`dirname $0`/keystone-manage $* endpointTemplates add RegionOne object_store http://swift.publicinternets.com/v1/AUTH_%tenant_id% http://swift.admin-nets.local:8080/ http://127.0.0.1:8080/v1/AUTH_%tenant_id% 1 0
`dirname $0`/keystone-manage $* endpointTemplates add RegionOne compute http://nova.publicinternets.com/v1.0/ http://127.0.0.1:8774/v1.0  http://localhost:8774/v1.0 1 0
`dirname $0`/keystone-manage $* endpointTemplates add RegionOne compute_v1 http://nova.publicinternets.com/v1.1/ http://127.0.0.1:8774/v1.1  http://localhost:8774/v1.1 1 0
`dirname $0`/keystone-manage $* endpointTemplates add RegionOne image http://glance.publicinternets.com/v1.1/%tenant_id% http://nova.admin-nets.local/v1.1/%tenant_id% http://127.0.0.1:9292/v1.1/%tenant_id% 1 0
`dirname $0`/keystone-manage $* endpointTemplates add RegionOne cdn http://cdn.publicinternets.com/v1.1/%tenant_id% http://cdn.admin-nets.local/v1.1/%tenant_id% http://127.0.0.1:7777/v1.1/%tenant_id% 1 0
#Global endpointTemplate
`dirname $0`/keystone-manage $* endpointTemplates add RegionOne identity http://keystone.publicinternets.com/v2.0 http://127.0.0.1:5001/v2.0 http://127.0.0.1:5000/v2.0 1 1

# Tokens
`dirname $0`/keystone-manage $* token add 887665443383838 joeuser 1234 2012-02-05T00:00
`dirname $0`/keystone-manage $* token add 999888777666 admin 1234 2015-02-05T00:00
`dirname $0`/keystone-manage $* token add 111222333444 serviceadmin 1234 2015-02-05T00:00
`dirname $0`/keystone-manage $* token add 000999 admin 1234 2010-02-05T00:00
`dirname $0`/keystone-manage $* token add 999888777 disabled 1234 2015-02-05T00:00

#Tenant endpointsGlobal endpoint not added
`dirname $0`/keystone-manage $* endpoint add 1234 1
`dirname $0`/keystone-manage $* endpoint add 1234 2
`dirname $0`/keystone-manage $* endpoint add 1234 3
`dirname $0`/keystone-manage $* endpoint add 1234 4
`dirname $0`/keystone-manage $* endpoint add 1234 5

#Add Services
`dirname $0`/keystone-manage $* service add exampleservice
