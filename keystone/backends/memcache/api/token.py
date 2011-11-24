# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack LLC.
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
from keystone.backends.memcache import MEMCACHE_SERVER, models
from keystone.backends.api import BaseTokenAPI


class TokenAPI(BaseTokenAPI):
    def create(self, token):
        if not hasattr(token, 'tenant_id'):
            token.tenant_id = None
        if token.tenant_id is not None:
            tenant_user_key = "%s::%s" % (token.tenant_id, token.user_id)
        else:
            tenant_user_key = "U%s" % token.user_id

        MEMCACHE_SERVER.set(token.id, token)
        MEMCACHE_SERVER.set(tenant_user_key, token)

    def get(self, id):
        token = MEMCACHE_SERVER.get(id)
        if token is not None and not hasattr(token, 'tenant_id'):
            token.tenant_id = None
        return token

    def delete(self, id):
        token = self.get(id)
        if token is not None:
            MEMCACHE_SERVER.delete(id)
            if token is not None and not hasattr(token, 'tenant_id'):
                token.tenant_id = None
            if token.tenant_id is not None:
                MEMCACHE_SERVER.delete("%s::%s" % (token.tenant_id,
                                                   token.user_id))
            else:
                MEMCACHE_SERVER.delete(token.id)
                MEMCACHE_SERVER.delete("U%s" % token.user_id)

    def get_for_user(self, user_id):
        token = MEMCACHE_SERVER.get("U%s" % user_id)
        if token is not None and not hasattr(token, 'tenant_id'):
            token.tenant_id = None
        return  token

    def get_for_user_by_tenant(self, user_id, tenant_id):
        if tenant_id is not None:
            token = MEMCACHE_SERVER.get("%s::%s" % (tenant_id, user_id))
        else:
            token = MEMCACHE_SERVER.get("U%s" % user_id)
        if token is not None and not hasattr(token, 'tenant_id'):
            token.tenant_id = None
        return  token


def get():
    return TokenAPI()
