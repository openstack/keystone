#!/usr/bin/env python
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

"""
Keystone Identity Server - CLI Management Interface
"""

import sys
import logging
import optparse

import keystone
from keystone.common import config
from keystone.manage.api import *


class RaisingOptionParser(optparse.OptionParser):
    def error(self, msg):
        self.print_usage(sys.stderr)
        raise optparse.OptParseError(msg)


def parse_args(args=None):
    usage = "usage: %prog [options] type command [id [attributes]]"

    # Initialize a parser for our configuration paramaters
    parser = RaisingOptionParser(usage, version='%%prog %s'
        % keystone.version())
    _common_group = config.add_common_options(parser)
    config.add_log_options(parser)

    # Parse command-line and load config
    (options, args) = config.parse_options(parser, args)
    _config_file, conf = config.load_paste_config('admin', options, args)

    config.setup_logging(options, conf)

    db.configure_backends(conf.global_conf)

    return args


def process(*args):
    """
    Usage: keystone-manage [options] type command [id [attributes]]
      type       : role, tenant, user, token, endpoint, endpointTemplates
      command    : add, list, disable, delete, grant, revoke
      id         : name or id
      attributes : depending on type...
        users    : password, tenant
        tokens   : user, tenant, expiration

      role list [tenant] will list roles granted on that tenant

    options
      -c | --config-file : config file to use
      -d | --debug : debug mode

    Example: keystone-manage user add Admin P@ssw0rd
    """
    # Check arguments
    if len(args) == 0:
        raise optparse.OptParseError(
            'No obj type specified for first argument')

    object_type = args[0]
    if object_type not in ['user', 'tenant', 'role', 'service',
            'endpointTemplates', 'token', 'endpoint', 'credentials']:
        raise optparse.OptParseError(
            '%s is not a supported obj type' % object_type)

    if len(args) == 1:
        raise optparse.OptParseError(
            'No command specified for second argument')
    command = args[1]
    if command not in ['add', 'list', 'disable', 'delete', 'grant', 'revoke']:
        raise optparse.OptParseError('add, disable, delete, and list are the '
            'only supported commands (right now)')

    if len(args) == 2:
        if command != 'list':
            raise optparse.OptParseError('No id specified for third argument')
    if len(args) > 2:
        object_id = args[2]

    # Helper functions

    def require_args(args, min, msg):
        """Ensure there are at least `min` arguments"""
        if len(args) < min:
            raise optparse.OptParseError(msg)

    optional_arg = (lambda x: len(args) > x and args[x] or None)

    def print_table(header_row, rows):
        """Prints a lists of lists as table in a human readable format"""
        print "\t".join(header_row)
        print '-' * 79
        rows = [[str(col) for col in row] for row in rows]
        print "\n".join(["\t".join(row) for row in rows])

    # Execute command

    if (object_type, command) == ('user', 'add'):
        require_args(args, 4, 'No password specified for fourth argument')
        if add_user(id=object_id, password=args[3], tenant=optional_arg(4)):
            print "SUCCESS: User %s created." % object_id

    elif (object_type, command) == ('user', 'disable'):
        if disable_user(id=object_id):
            print "SUCCESS: User %s disabled." % object_id

    elif (object_type, command) == ('user', 'list'):
        print_table(('id', 'enabled', 'tenant'), list_users())

    elif (object_type, command) == ('tenant', 'add'):
        if add_tenant(id=object_id):
            print "SUCCESS: Tenant %s created." % object_id

    elif (object_type, command) == ('tenant', 'list'):
        print_table(('tenant', 'enabled'), list_tenants())

    elif (object_type, command) == ('tenant', 'disable'):
        if disable_tenant(id=object_id):
            print "SUCCESS: Tenant %s disabled." % object_id

    elif (object_type, command) == ('role', 'add'):
        if add_role(id=object_id):
            print "SUCCESS: Role %s created successfully." % object_id

    elif (object_type, command) == ('role', 'list'):
        tenant = optional_arg(2)
        if tenant:
            # print with users
            print 'Role assignments for tenant %s' % tenant
            print_table(('User', 'Role'), list_roles(tenant=tenant))
        else:
            # print without tenants
            print_table(('id'), list_roles())

    elif (object_type, command) == ('role', 'grant'):
        require_args(args, 4, "Missing arguments: role grant 'role' 'user' "
            "'tenant (optional)'")
        tenant = len(args) > 4 and args[4] or None
        if grant_role(object_id, args[3], tenant):
            print("SUCCESS: Granted %s the %s role on %s." %
                (object_id, args[3], tenant))

    elif (object_type, command) == ('endpointTemplates', 'add'):
        require_args(args, 9, "Missing arguments: endpointTemplates add "
            "'region' 'service' 'publicURL' 'adminURL' 'internalURL' "
            "'enabled' 'global'")
        if add_endpoint_template(region=args[2], service=args[3],
                public_url=args[4], admin_url=args[5], internal_url=args[6],
                enabled=args[7], is_global=args[8]):
            print("SUCCESS: Created EndpointTemplates for %s pointing to %s." %
                (args[3], args[4]))

    elif (object_type, command) == ('endpointTemplates', 'list'):
        tenant = optional_arg(2)
        if tenant:
            print 'Endpoints for tenant %s' % tenant
            print_table(('service', 'region', 'Public URL'),
                list_tenant_endpoints())
        else:
            print 'All EndpointTemplates'
            print_table(('service', 'region', 'Public URL'),
                list_endpoint_templates())

    elif (object_type, command) == ('endpoint', 'add'):
        require_args(args, 4, "Missing arguments: endPoint add tenant "
            "endPointTemplate")
        if add_endpoint(tenant=args[2], endpoint_template=args[3]):
            print("SUCCESS: Endpoint %s added to tenant %s." %
                (args[3], args[2]))

    elif (object_type, command) == ('token', 'add'):
        require_args(args, 6, 'Creating a token requires a token id, user, '
            'tenant, and expiration')
        if add_token(token=object_id, user=args[3], tenant=args[4],
                expires=args[5]):
            print "SUCCESS: Token %s created." % (object_id,)

    elif (object_type, command) == ('token', 'list'):
        print_table(('token', 'user', 'expiration', 'tenant'), list_tokens())

    elif (object_type, command) == ('token', 'delete'):
        if delete_token(token=object_id):
            print 'SUCCESS: Token %s deleted.' % (object_id,)

    elif (object_type, command) == ('service', 'add'):
        if add_service(service=object_id):
            print "SUCCESS: Service %s created successfully." % (object_id,)

    elif (object_type, command) == ('service', 'list'):
        print_table(('service'), list_services())

    elif (object_type, command) == ('credentials', 'add'):
        require_args(args, 6, 'Creating a credentials requires a type, key, '
            'secret, and tenant_id (id is user_id)')
        if add_credentials(user=object_id, type=args[3], key=args[4],
                secrete=args[5], tenant=optional_arg(6)):
            print "SUCCESS: Credentials %s created." % object_id

    else:
        # Command not handled
        print ("ERROR: unrecognized command %s %s" % (object_type, command))


def main():
    try:
        process(*parse_args())
    except optparse.OptParseError as exc:
        print >> sys.stderr, exc
        sys.exit(2)
    except Exception as exc:
        try:
            info = exc.args[1]
        except IndexError:
            print "ERROR: %s" % (exc,)
            logging.error(str(exc))
        else:
            print "ERROR: %s: %s" % (exc.args[0], info)
            logging.error(exc.args[0], exc_info=info)
        sys.exit(1)


if __name__ == '__main__':
    main()
