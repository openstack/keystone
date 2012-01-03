from keystone.manage2 import base
from keystone.manage2 import mixins


class Command(base.BaseBackendCommand, mixins.ListMixin):
    """Lists all endpoint templates in the system."""

    # pylint: disable=E1101
    def get_endpoint_templates(self):
        return self.endpoint_template_manager.get_all()

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        table = self.build_table(['ID', 'Service ID', 'Region', 'Enabled',
            'Global', 'Public URL', 'Admin URL', 'Internal URL'])

        for obj in self.get_endpoint_templates():
            row = [obj.id, obj.service_id, obj.region, obj.enabled,
                    obj.is_global, obj.public_url, obj.admin_url,
                    obj.internal_url]
            table.add_row(row)

        self.print_table(table)
