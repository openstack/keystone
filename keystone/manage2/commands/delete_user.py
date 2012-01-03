from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--where-id',
    required=True,
    help='identify the user to be deleted by ID')
class Command(base.BaseBackendCommand):
    """Deletes the specified user.

    This command is irreversible! To simply disable a user,
    use `update_user --disable`."""

    # pylint: disable=E1101
    def delete_user(self, id):
        user = self.get_user(id)
        self.user_manager.delete(user.id)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.delete_user(id=args.where_id)
