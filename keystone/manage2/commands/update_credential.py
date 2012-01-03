from keystone.manage2 import base
from keystone.manage2 import common
from keystone.manage2 import mixins


@common.arg('--where-id',
    required=True,
    help='identifies the credential to update by ID')
@common.arg('--user-id',
    required=False,
    help='change the user the credential applies to, by ID')
@common.arg('--tenant-id',
    required=False,
    help='change the tenant this credential applies to, by ID')
@common.arg('--type',
    required=True,
    help="change the credential type (e.g. 'EC2')")
@common.arg('--key',
    required=True,
    help="change the credential key")
@common.arg('--secret',
    required=True,
    help="change the credential secret")
class Command(base.BaseBackendCommand, mixins.DateTimeMixin):
    """Updates the specified credential."""

    # pylint: disable=E1101,R0913
    def update_credential(self, id, user_id=None, tenant_id=None,
            cred_type=None, secret=None, key=None):
        obj = self.get_credential(id)
        self.get_user(user_id)
        self.get_tenant(tenant_id)

        if user_id is not None:
            obj.user_id = user_id

        if tenant_id is not None:
            obj.tenant_id = tenant_id

        if cred_type is not None:
            obj.type = cred_type

        if key is not None:
            obj.key = key

        if secret is not None:
            obj.secret = secret

        self.credential_manager.update(id, obj)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.update_credential(id=args.where_id, user_id=args.user_id,
                tenant_id=args.tenant_id, cred_type=args.type,
                key=args.key, secret=args.secret)
