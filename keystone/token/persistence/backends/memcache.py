# Copyright 2013 Metacloud, Inc.
# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg

from keystone.token.persistence.backends import kvs


CONF = cfg.CONF


class Token(kvs.Token):
    kvs_backend = 'openstack.kvs.Memcached'
    memcached_backend = 'memcached'

    def __init__(self, *args, **kwargs):
        kwargs['memcached_backend'] = self.memcached_backend
        kwargs['no_expiry_keys'] = [self.revocation_key]
        kwargs['memcached_expire_time'] = CONF.token.expiration
        kwargs['url'] = CONF.memcache.servers
        super(Token, self).__init__(*args, **kwargs)
