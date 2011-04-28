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

import optparse
import keystone.db.sqlalchemy.api as db_api
from keystone.db.sqlalchemy import models


def main():
    usage = "usage: %prog group_id group_desc"
    parser = optparse.OptionParser(usage)
    options, args = parser.parse_args()
    if len(args) != 2:
        parser.error("Incorrect number of arguments")
    else:
        group = args[0]
        desc = args[1]
        try:
            g = db_api.group_get(group)
            if g == None:
                raise IndexError("Group not found")
            else:
                values = {'desc': desc}
                db_api.group_update(group, values)
            print 'Group', g.id, 'updated.'
        except Exception, e:
            print 'Error updating user', group, ':', str(e)

if __name__ == '__main__':
    main()
