from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--where-id',
    required=True,
    help='identify the credential to be deleted by ID')
class Command(base.BaseBackendCommand):
    """Deletes the specified credential."""

    # pylint: disable=E1101
    def delete_credential(self, id):
        credential = self.get_credential(id)
        self.credential_manager.delete(credential.id)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.delete_credential(id=args.where_id)
