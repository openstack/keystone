from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--where-id',
    required=True,
    help='identifies the tenant to update by ID')
@common.arg('--name',
    required=False,
    help="change the tenant's name")
@common.arg('--enable',
    action='store_true',
    required=False,
    default=False,
    help="enable the tenant")
@common.arg('--disable',
    action='store_true',
    required=False,
    default=False,
    help="disable the tenant")
class Command(base.BaseBackendCommand):
    """Updates the specified tenant."""

    # pylint: disable=E1101
    def update_tenant(self, id, name=None, enabled=None):
        tenant = self.get_tenant(id)

        if name is not None:
            tenant.name = name

        if enabled is not None:
            tenant.enabled = enabled

        self.tenant_manager.update(tenant)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        enabled = self.true_or_false(args, 'enable', 'disable')

        self.update_tenant(id=args.where_id, name=args.name, enabled=enabled)
