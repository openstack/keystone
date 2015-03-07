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

from keystoneclient.common import cms
from oslo_config import cfg


def generate_unique_id(token_id):
    """Return a unique ID for a token.

    The returned value is useful as the primary key of a database table,
    memcache store, or other lookup table.

    :returns: Given a PKI token, returns it's hashed value. Otherwise,
              returns the passed-in value (such as a UUID token ID or an
              existing hash).
    """
    return cms.cms_hash_token(token_id, mode=cfg.CONF.token.hash_algorithm)
