from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--where-id',
    required=True,
    help='identify the tenant to be deleted')
class Command(base.BaseBackendCommand):
    """Deletes the specified tenant.

    This command is irreversible! To simply disable a tenant,
    use `update_tenant --disable`."""

    # pylint: disable=E1101
    def delete_tenant(self, id):
        tenant = self.get_tenant(id)
        self.tenant_manager.delete(tenant.id)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.delete_tenant(id=args.where_id)
