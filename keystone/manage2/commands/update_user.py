from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--where-id',
    required=True,
    help='identifies the user to update by ID')
@common.arg('--name',
    required=False,
    help="change the user's name")
@common.arg('--password',
    required=False,
    help="change the user's password")
@common.arg('--email',
    required=False,
    help="change the user's email address")
@common.arg('--tenant_id',
    required=False,
    help="change the user's default tenant")
@common.arg('--enable',
    action='store_true',
    required=False,
    default=False,
    help="enable the user")
@common.arg('--disable',
    action='store_true',
    required=False,
    default=False,
    help="disable the user")
class Command(base.BaseBackendCommand):
    """Updates the specified user."""

    # pylint: disable=E1101,R0913
    def update_user(self, id, name=None, password=None, email=None,
            tenant_id=None, enabled=None):
        user = self.get_user(id)

        if name is not None:
            user.name = name

        if password is not None:
            user.password = password

        if email is not None:
            user.email = email

        if tenant_id is not None:
            tenant = self.get_tenant(tenant_id)
            user.tenant = tenant.id

        if enabled is not None:
            user.enabled = enabled

        self.user_manager.update(user)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        enabled = self.true_or_false(args, 'enable', 'disable')

        self.update_user(id=args.where_id, name=args.name,
                password=args.password, email=args.email,
                tenant_id=args.tenant_id, enabled=enabled)
