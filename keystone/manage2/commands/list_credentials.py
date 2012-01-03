from keystone.manage2 import base
from keystone.manage2 import mixins


class Command(base.BaseBackendCommand, mixins.ListMixin,
        mixins.DateTimeMixin):
    """Lists all credentials in the system."""

    # pylint: disable=E1101
    def get_credentials(self):
        return self.credential_manager.get_all()

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        table = self.build_table(["ID", "User ID", "Tenant ID",
            "Type", "Key", "Secret"])

        for obj in self.get_credentials():
            row = [obj.id, obj.user_id, obj.tenant_id,
                    obj.type, obj.key, obj.secret]
            table.add_row(row)

        self.print_table(table)
