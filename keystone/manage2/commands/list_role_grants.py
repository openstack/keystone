from keystone.manage2 import base
from keystone.manage2 import common
from keystone.manage2 import mixins


@common.arg('--where-user-id',
    required=False,
    help='lists roles granted to a specific user')
@common.arg('--where-role-id',
    required=False,
    help='lists users and tenants a role has been granted to')
@common.arg('--where-tenant-id',
    required=False,
    help='lists roles granted on a specific tenant')
@common.arg('--where-global',
    action='store_true',
    required=False,
    default=False,
    help="lists roles that have been granted globally")
class Command(base.BaseBackendCommand, mixins.ListMixin):
    """Lists the users and tenants a role has been granted to."""

    # pylint: disable=E1101,R0913
    def list_role_grants(self, role_id=None, user_id=None, tenant_id=None,
            is_global=False):
        self.get_user(user_id)
        self.get_role(role_id)
        self.get_tenant(tenant_id)

        if is_global:
            tenant_id = False

        return self.grant_manager.list_role_grants(user_id=user_id,
                role_id=role_id, tenant_id=tenant_id)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.true_or_false(args, 'where_tenant_id', 'where_global')

        table = self.build_table(["Role ID", "User ID", "Tenant ID",
            "Global"])

        for obj in self.list_role_grants(role_id=args.where_role_id,
                user_id=args.where_user_id, tenant_id=args.where_tenant_id,
                is_global=args.where_global):
            row = [obj.role_id, obj.user_id, obj.tenant_id,
                    obj.tenant_id is None]
            table.add_row(row)

        self.print_table(table)
