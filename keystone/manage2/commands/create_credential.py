from keystone.manage2 import base
from keystone.manage2 import common
from keystone.manage2 import mixins
from keystone.backends import models


@common.arg('--user-id',
    required=True,
    help='identifies the user who can authenticate with this credential')
@common.arg('--tenant-id',
    required=False,
    help='identifies the tenant upon which the crednetial is valid')
@common.arg('--type',
    required=True,
    help="credential type (e.g. 'EC2')")
@common.arg('--key',
    required=True)
@common.arg('--secret',
    required=True)
class Command(base.BaseBackendCommand, mixins.DateTimeMixin):
    """Creates a new credential."""

    # pylint: disable=E1101,R0913
    def create_credential(self, user_id, credential_type, key, secret,
            tenant_id=None):
        self.get_user(user_id)
        self.get_tenant(tenant_id)

        obj = models.Credentials()
        obj.user_id = user_id
        obj.tenant_id = tenant_id
        obj.type = credential_type
        obj.key = key
        obj.secret = secret

        return self.credential_manager.create(obj)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        credential = self.create_credential(user_id=args.user_id,
                tenant_id=args.tenant_id, credential_type=args.type,
                key=args.key, secret=args.secret)
        print credential.id
