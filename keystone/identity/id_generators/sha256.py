# Copyright 2014 IBM Corp.
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

import hashlib
from keystone.identity import generator


class Generator(generator.IDGenerator):

    def generate_public_ID(self, mapping):
        m = hashlib.sha256()
        for key in sorted(mapping.keys()):
            # python-ldap >3.0 returns bytes data type for attribute values
            # except distinguished names, relative distinguished names,
            # attribute names, queries on python3.
            # Please see Bytes/text management in python-ldap module.
            if isinstance(mapping[key], bytes):
                m.update(mapping[key])
            else:
                m.update(mapping[key].encode('utf-8'))
        return m.hexdigest()
