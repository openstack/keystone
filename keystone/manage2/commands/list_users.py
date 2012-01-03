from keystone.manage2 import base
from keystone.manage2 import mixins


class Command(base.BaseBackendCommand, mixins.ListMixin):
    """Lists all users in the system."""

    # pylint: disable=E1101
    def get_users(self):
        return self.user_manager.get_all()

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        table = self.build_table(["ID", "Name", "Email", "Default Tenant ID",
            "Enabled"])

        for user in self.get_users():
            row = [user.id, user.name, user.email, user.tenant_id,
                    user.enabled]
            table.add_row(row)

        # TODO(dolph): sort order and subsets could become CLI options
        self.print_table(table)
