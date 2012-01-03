from keystone.manage2 import base
from keystone.manage2 import mixins


class Command(base.BaseBackendCommand, mixins.ListMixin):
    """Lists all roles in the system."""

    # pylint: disable=E1101
    def get_roles(self):
        return self.endpoint_manager.get_all()

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        table = self.build_table(["Endpoint Template ID", "Tenant ID"])

        for obj in self.get_roles():
            row = [obj.endpoint_template_id, obj.tenant_id]
            table.add_row(row)

        self.print_table(table)
