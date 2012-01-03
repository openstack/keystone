from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--where-id',
    required=True,
    help='identify the token to be deleted by ID')
class Command(base.BaseBackendCommand):
    """Deletes the specified token."""

    # pylint: disable=E1101
    def delete_token(self, id):
        token = self.get_token(id)
        self.token_manager.delete(token.id)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.delete_token(id=args.where_id)
