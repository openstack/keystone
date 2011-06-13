#!/usr/bin/python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2011 OpenStack, LLC.
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

import base
try:
    import dtest
except:
    print "DTest framework needed. Try running 'pip install dtest'"
    exit()
import sys


def add_opts(opts):
    """Adds options specific to this test suite."""

    opts.add_option("-u", "--username",
                    action="store", type="string", dest="username",
                    help="The username to use to access Keystone.")
    opts.add_option("-p", "--password",
                    action="store", type="string", dest="password",
                    help="The password to use to access Keystone.")

    opts.add_option("-U", "--adminuser",
                    action="store", type="string", dest="adminuser",
                    help="The admin username to use to access Keystone.")
    opts.add_option("-P", "--adminpass",
                    action="store", type="string", dest="adminpass",
                    help="The admin password to use to access Keystone.")

    opts.add_option("-k", "--keystone",
                    action="store", type="string", dest="keystone",
                    help="The URL to use to access the Keystone service.")
    opts.add_option("-K", "--keystone-admin",
                    action="store", type="string", dest="keystone_admin",
                    help="The URL to use to access the Keystone admin "
                    "service.")

    return opts


if __name__ == '__main__':
    # Obtain the options
    opts = add_opts(dtest.optparser(usage="%prog [options]"))

    # Process command-line arguments, saving them so tests can get to
    # them
    (base.options, args) = opts.parse_args()

    # Ensure required options are present
    if (not base.options.username or not base.options.password or
        not base.options.keystone):
        print >>sys.stderr, "Missing required options"
        print >>sys.stderr, ("At a minimum, --username, --password, and "
                             "--keystone must be specified.")
        opts.print_help(sys.stderr)
        sys.exit(1)

    # How about the admin stuff?
    if not base.options.adminuser:
        base.options.adminuser = base.options.username
    if not base.options.adminpass:
        base.options.adminpass = base.options.password
    if not base.options.keystone_admin:
        base.options.keystone_admin = base.options.keystone

    # Execute the test suite
    sys.exit(dtest.main(**dtest.opts_to_args(base.options)))
