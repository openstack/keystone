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


def main():
    usage = "usage: %prog username enabled"
    parser = optparse.OptionParser(usage)
    options, args = parser.parse_args()
    if len(args) != 2:
        parser.error("Incorrect number of arguments")
    else:
        username = args[0]
        enabled = args[1].capitalize().strip()

        if enabled == 'True' or enabled == '1':
            enabled = 1
        elif enabled == 'False' or enabled == '0':
            enabled = 0
        else:
            parser.error("Incorrect arguments value")

        try:
            u = db_api.user_get(username)
            if u == None:
                raise IndexError("User not found")
            else:
                values = {'enabled': enabled}
                db_api.user_update(username, values)
            print 'User', u.id, 'updated. Enabled =', enabled
        except Exception, e:
            print 'Error updating user', username, ':', str(e)

if __name__ == '__main__':
    main()
