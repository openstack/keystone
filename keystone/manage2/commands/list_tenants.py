from keystone.manage2 import base
from keystone.manage2 import mixins


class Command(base.BaseBackendCommand, mixins.ListMixin):
    """Lists all tenants in the system."""

    # pylint: disable=E1101
    def get_tenants(self):
        return self.tenant_manager.get_all()

    def run(self, args):
        """Process argparse args, and print results to stdout"""

        table = self.build_table(["ID", "Name", "Enabled"])

        # populate the table
        for tenant in self.get_tenants():
            row = [tenant.id, tenant.name, tenant.enabled]
            table.add_row(row)

        self.print_table(table)
