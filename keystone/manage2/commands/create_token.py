import uuid

from keystone.backends import models
from keystone.manage2 import base
from keystone.manage2 import common
from keystone.manage2 import mixins


@common.arg('--id',
    required=False,
    help='a unique token ID')
@common.arg('--user-id',
    required=True,
    help='identifies the user who can authenticate with this token')
@common.arg('--tenant-id',
    required=False,
    help='identifies the tenant upon which the token is valid')
@common.arg('--expires',
    required=False,
    help='identifies the POSIX date/time until which the token is valid '
        '(e.g. 1999-01-31T23:59)')
class Command(base.BaseBackendCommand, mixins.DateTimeMixin):
    """Creates a new token.

    If a token ID is not provided, one will be generated automatically.

    If a tenant ID is not provided, the token will be unscoped.

    If an expiration datetime is not provided, the token will expires 24
    hours after creation.
    """

    # pylint: disable=E1101,R0913
    def create_token(self, user_id, token_id=None, tenant_id=None,
            expires=None):
        self.get_user(user_id)
        self.get_tenant(tenant_id)

        obj = models.Token()
        obj.user_id = user_id
        obj.tenant_id = tenant_id

        if token_id is not None:
            obj.id = token_id
        else:
            obj.id = uuid.uuid4().hex

        if expires is not None:
            obj.expires = self.str_to_datetime(expires)
        else:
            obj.expires = Command.get_datetime_tomorrow()

        return self.token_manager.create(obj)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        token = self.create_token(token_id=args.id, user_id=args.user_id,
                tenant_id=args.tenant_id, expires=args.expires)
        print token.id
