from keystone.manage2 import common
from keystone.manage2 import base
from keystone.backends import models


@common.arg('--id',
    required=False,
    help='a unique identifier used in URLs')
@common.arg('--name',
    required=True,
    help='a unique name')
@common.arg('--disabled',
    action='store_true',
    required=False,
    default=False,
    help="create the tenant in a disabled state (tenants are enabled by "
            "default)")
class Command(base.BaseBackendCommand):
    """Creates a new tenant, enabled by default.

    The tenant is enabled by default, but can optionally be disabled upon
    creation.
    """

    # pylint: disable=E1101
    def create_tenant(self, name, id=None, enabled=True):
        obj = models.Tenant()
        obj.id = id
        obj.name = name
        obj.enabled = enabled

        return self.tenant_manager.create(obj)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        tenant = self.create_tenant(id=args.id, name=args.name,
                enabled=(not args.disabled))
        print tenant.id
