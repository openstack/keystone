from keystone.manage2 import base
from keystone.manage2 import common
from keystone.backends import models


@common.arg('--user-id',
    required=True,
    help='identify the user to grant the role to by ID')
@common.arg('--role-id',
    required=True,
    help='identify the role to be granted by ID')
@common.arg('--tenant-id',
    required=False,
    help='identify the tenant for the granted role is valid (the role is '
        'global if a tenant is not specified)')
class Command(base.BaseBackendCommand):
    """Grants a role to a user, and optionally, for a specific tenant.

    If a tenant is not specified, the role is granted globally."""

    # pylint: disable=E1101,R0913
    def grant_role(self, user_id, role_id, tenant_id=None):
        self.get_user(user_id)
        self.get_role(role_id)
        self.get_tenant(tenant_id)

        # this is a bit of a hack to validate that the grant doesn't exist
        grant = self.grant_manager.rolegrant_get_by_ids(user_id, role_id,
                tenant_id)
        if grant is not None:
            raise KeyError('Grant already exists for User ID %s, '
                    'Role ID %s and Tenant ID %s' % (user_id, role_id,
                        tenant_id))

        obj = models.UserRoleAssociation()
        obj.user_id = user_id
        obj.role_id = role_id
        obj.tenant_id = tenant_id

        self.user_manager.user_role_add(obj)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.grant_role(user_id=args.user_id, role_id=args.role_id,
                tenant_id=args.tenant_id)
