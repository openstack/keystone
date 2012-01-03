from keystone.manage2 import base
from keystone.manage2 import mixins


class Command(base.BaseBackendCommand, mixins.ListMixin,
        mixins.DateTimeMixin):
    """Lists all tokens in the system."""

    # pylint: disable=E1101
    def get_tokens(self):
        return self.token_manager.get_all()

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        table = self.build_table(["ID", "User ID", "Tenant ID",
            "Expiration"])

        for obj in self.get_tokens():
            row = [obj.id, obj.user_id, obj.tenant_id,
                    self.datetime_to_str(obj.expires)]
            table.add_row(row)

        self.print_table(table)
