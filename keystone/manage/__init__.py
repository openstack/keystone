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
import optparse  # deprecated in 2.7, in favor of argparse

from keystone import version
from keystone.common import config
from keystone.manage import api
import keystone.backends as db


# CLI feature set
OBJECTS = ['user', 'tenant', 'role', 'service',
    'endpointTemplates', 'token', 'endpoint', 'credentials']
ACTIONS = ['add', 'list', 'disable', 'delete', 'grant',
    'revoke']


# Messages
OBJECT_NOT_SPECIFIED = 'No object type specified for first argument'
ACTION_NOT_SPECIFIED = 'No action specified for second argument'
ID_NOT_SPECIFIED = 'No ID specified for third argument'
SUPPORTED_OBJECTS = "Supported objects: %s" % (", ".join(OBJECTS))
SUPPORTED_ACTIONS = "Supported actions: %s" % (", ".join(ACTIONS))
ACTION_NOT_SUPPORTED = 'Action not supported for %s'


class RaisingOptionParser(optparse.OptionParser):
    def error(self, msg):
        self.print_usage(sys.stderr)
        raise optparse.OptParseError(msg)


def parse_args(args=None):
    usage = """
    Usage: keystone-manage [options] type action [id [attributes]]
      type       : %s
      action     : %s
      id         : name or id
      attributes : depending on type...
        users    : password, tenant
        tokens   : user, tenant, expiration

      role list [tenant] will list roles granted on that tenant

    options
      -c | --config-file : config file to use
      -d | --debug : debug mode

    Example: keystone-manage user add Admin P@ssw0rd
    """ % (", ".join(OBJECTS), ", ".join(ACTIONS))

    # Initialize a parser for our configuration paramaters
    parser = RaisingOptionParser(usage, version='%%prog %s'
        % version.version())
    _common_group = config.add_common_options(parser)
    config.add_log_options(parser)

    # Parse command-line and load config
    (options, args) = config.parse_options(parser, args)
    _config_file, conf = config.load_paste_config('admin', options, args)

    config.setup_logging(options, conf)

    db.configure_backends(conf.global_conf)

    return args


def process(*args):
    # Check arguments
    if len(args) == 0:
        raise optparse.OptParseError(OBJECT_NOT_SPECIFIED)
    else:
        object_type = args[0]
        if object_type not in OBJECTS:
            raise optparse.OptParseError(SUPPORTED_OBJECTS)

    if len(args) == 1:
        raise optparse.OptParseError(ACTION_NOT_SPECIFIED)
    else:
        action = args[1]
        if action not in ACTIONS:
            raise optparse.OptParseError(SUPPORTED_ACTIONS)

    if action not in ['list']:
        if len(args) == 2:
            raise optparse.OptParseError(ID_NOT_SPECIFIED)
        else:
            object_id = args[2]

    # Helper functions
    def require_args(args, min, msg):
        """Ensure there are at least `min` arguments"""
        if len(args) < min:
            raise optparse.OptParseError(msg)

    optional_arg = (lambda args, x:
        len(args) > x and str(args[x]).strip() or None)

    def print_table(header_row, rows):
        """Prints a lists of lists as table in a human readable format"""
        print "\t".join(header_row)
        print '-' * 79
        rows = [[str(col) for col in row] for row in rows]
        print "\n".join(["\t".join(row) for row in rows])

    # Execute command
    if (object_type, action) == ('user', 'add'):
        require_args(args, 4, 'No password specified for fourth argument')
        if api.add_user(name=object_id, password=args[3],
                tenant=optional_arg(args, 4)):
            print "SUCCESS: User %s created." % object_id

    elif (object_type, action) == ('user', 'list'):
        print_table(('id', 'name', 'enabled', 'tenant'), api.list_users())

    elif (object_type, action) == ('user', 'disable'):
        if api.disable_user(name=object_id):
            print "SUCCESS: User %s disabled." % object_id

    elif object_type == 'user':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('users'))

    elif (object_type, action) == ('tenant', 'add'):
        if api.add_tenant(name=object_id):
            print "SUCCESS: Tenant %s created." % object_id

    elif (object_type, action) == ('tenant', 'list'):
        print_table(('id', 'name', 'enabled'), api.list_tenants())

    elif (object_type, action) == ('tenant', 'disable'):
        if api.disable_tenant(name=object_id):
            print "SUCCESS: Tenant %s disabled." % object_id

    elif object_type == 'tenant':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('tenants'))

    elif (object_type, action) == ('role', 'add'):
        if api.add_role(name=object_id):
            print "SUCCESS: Role %s created successfully." % object_id

    elif (object_type, action) == ('role', 'list'):
        tenant = optional_arg(args, 2)
        if tenant:
            # print with users
            print 'Role assignments for tenant %s' % tenant
            print_table(('User', 'Role'),
                api.list_roles(tenant=tenant))
        else:
            # print without tenants
            print_table(('id', 'name', 'service_id', 'description'),
                api.list_roles())

    elif (object_type, action) == ('role', 'grant'):
        require_args(args, 4, "Missing arguments: role grant 'role' 'user' "
            "'tenant (optional)'")
        tenant = optional_arg(args, 4)
        if api.grant_role(object_id, args[3], tenant):
            print("SUCCESS: Granted %s the %s role on %s." %
                (args[3], object_id, tenant))

    elif object_type == 'role':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('roles'))

    elif (object_type, action) == ('endpointTemplates', 'add'):
        require_args(args, 9, "Missing arguments: endpointTemplates add "
            "'region' 'service_name' 'publicURL' 'adminURL' 'internalURL' "
            "'enabled' 'global'")
        version_id = optional_arg(args, 9)
        version_list = optional_arg(args, 10)
        version_info = optional_arg(args, 11)
        if api.add_endpoint_template(region=args[2], service=args[3],
                public_url=args[4], admin_url=args[5], internal_url=args[6],
                enabled=args[7], is_global=args[8],
                version_id=version_id, version_list=version_list,
                version_info=version_info):
            print("SUCCESS: Created EndpointTemplates for %s pointing to %s." %
                (args[3], args[4]))

    elif (object_type, action) == ('endpointTemplates', 'list'):
        tenant = optional_arg(args, 2)
        if tenant:
            print 'Endpoints for tenant %s' % tenant
            print_table(('service', 'region', 'Public URL'),
                api.list_tenant_endpoints(tenant))
        else:
            print 'All EndpointTemplates'
            print_table(('id', 'service', 'type', 'region', 'enabled',
                         'is_global', 'Public URL', 'Admin URL'),
                api.list_endpoint_templates())

    elif (object_type, action) == ('endpoint', 'add'):
        require_args(args, 4, "Missing arguments: endPoint add tenant "
            "endPointTemplate")
        if api.add_endpoint(tenant=args[2], endpoint_template=args[3]):
            print("SUCCESS: Endpoint %s added to tenant %s." %
                (args[3], args[2]))

    elif object_type == 'endpoint':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('endpoints'))

    elif (object_type, action) == ('token', 'add'):
        require_args(args, 6, 'Creating a token requires a token id, user, '
            'tenant, and expiration')
        if api.add_token(token=object_id, user=args[3], tenant=args[4],
                expires=args[5]):
            print "SUCCESS: Token %s created." % (object_id,)

    elif (object_type, action) == ('token', 'list'):
        print_table(('token', 'user', 'expiration', 'tenant'),
            api.list_tokens())

    elif (object_type, action) == ('token', 'delete'):
        if api.delete_token(token=object_id):
            print 'SUCCESS: Token %s deleted.' % (object_id,)

    elif object_type == 'token':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('tokens'))

    elif (object_type, action) == ('service', 'add'):
        require_args(args, 4, "Missing arguments: service add <name> " \
                     "[type] [desc] [owner_id]"
            "type")
        type = optional_arg(args, 3)
        desc = optional_arg(args, 4)
        owner_id = optional_arg(args, 5)

        if api.add_service(name=object_id, type=type, desc=desc,
                           owner_id=owner_id):
            print "SUCCESS: Service %s created successfully." % (object_id,)

    elif (object_type, action) == ('service', 'list'):
        print_table(('id', 'name', 'type', 'owner_id', 'description'),
            api.list_services())

    elif object_type == 'service':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('services'))

    elif (object_type, action) == ('credentials', 'add'):
        require_args(args, 6, 'Creating a credentials requires a type, key, '
            'secret, and tenant_id (id is user_id)')
        if api.add_credentials(user=object_id, type=args[3], key=args[4],
                secrete=args[5], tenant=optional_arg(args, 6)):
            print "SUCCESS: Credentials %s created." % object_id

    elif object_type == 'credentials':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('credentials'))

    else:
        # Command recognized but not handled: should never reach this
        raise NotImplementedError()


def main(args=None):
    try:
        process(*parse_args(args))
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
        raise exc


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        sys.exit(1)
