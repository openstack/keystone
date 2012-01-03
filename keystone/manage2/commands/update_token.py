from keystone.manage2 import base
from keystone.manage2 import common
from keystone.manage2 import mixins


@common.arg('--where-id',
    required=True,
    help='identifies the token to update by ID')
@common.arg('--user-id',
    required=False,
    help='change the user the token applies to, by ID')
@common.arg('--tenant-id',
    required=False,
    help='change the tenant this token applies to, by ID')
@common.arg('--expires',
    required=False,
    help="change the token's expiration date")
class Command(base.BaseBackendCommand, mixins.DateTimeMixin):
    """Updates the specified token."""

    # pylint: disable=E1101,R0913
    def update_token(self, id, user_id=None, tenant_id=None,
            expires=None):
        obj = self.get_token(id)
        self.get_user(user_id)
        self.get_tenant(tenant_id)

        if user_id is not None:
            obj.user_id = user_id

        if tenant_id is not None:
            obj.tenant_id = tenant_id

        if expires is not None:
            obj.expires = self.str_to_datetime(expires)

        self.token_manager.update(id, obj)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.update_token(id=args.where_id, user_id=args.user_id,
                tenant_id=args.tenant_id, expires=args.expires)
