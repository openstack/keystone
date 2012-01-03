from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--user-id',
    required=True,
    help='identify the user to revoke the role from by ID')
@common.arg('--role-id',
    required=True,
    help='identify the role to be revoked by ID')
@common.arg('--tenant-id',
    required=False,
    help='identify the tenant for the role to be revoked from by ID (the '
        'role is assumed to be global if a tenant is not specified)')
class Command(base.BaseBackendCommand):
    """Revoke a role from a user, and optionally, from a specific tenant.

    If a tenant is not specified, then the role is assumed to be global,
    and revoked as a global role.
    """

    # pylint: disable=E1101,R0913
    def revoke_role(self, user_id, role_id, tenant_id=None):
        self.get_user(user_id)
        self.get_role(role_id)
        self.get_tenant(tenant_id)

        grant = self.grant_manager.rolegrant_get_by_ids(user_id, role_id,
                tenant_id)

        if grant is None:
            raise KeyError('Grant not found for User ID %s, Role ID %s and '
                    'Tenant ID %s' % (user_id, role_id, tenant_id))

        self.grant_manager.rolegrant_delete(grant.id)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.revoke_role(user_id=args.user_id, role_id=args.role_id,
                tenant_id=args.tenant_id)
