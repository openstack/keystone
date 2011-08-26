import keystone.manage

DEFAULT_FIXTURE = [
# Tenants
    ('tenant', 'add', '1234'),
    ('tenant', 'add', 'ANOTHER:TENANT'),
    ('tenant', 'add', '0000'),
    ('tenant', 'disable', '0000'),
# Users
    ('user', 'add', 'joeuser', 'secrete', '1234'),
    ('user', 'add', 'joeadmin', 'secrete', '1234'),
    ('user', 'add', 'admin', 'secrete', '1234'),
    ('user', 'add', 'serviceadmin', 'secrete', '1234'),
    ('user', 'add', 'disabled', 'secrete', '1234'),
    ('user', 'disable', 'disabled'),
# Roles
    ('role', 'add', 'Admin'),
    ('role', 'add', 'KeystoneServiceAdmin'),
    ('role', 'grant', 'Admin', 'admin'),
    ('role', 'grant', 'KeystoneServiceAdmin', 'serviceadmin'),
    ('role', 'grant', 'Admin', 'joeadmin', '1234'),
    ('role', 'grant', 'Admin', 'joeadmin', 'ANOTHER:TENANT'),
    ('role', 'add', 'Member'),
    ('role', 'grant', 'Member', 'joeuser', '1234'),
# Keeping for compatibility for a while till dashboard catches up
    ('endpointTemplates', 'add', 'RegionOne', 'swift',
        'http://swift.publicinternets.com/v1/AUTH_%tenant_id%',
        'http://swift.admin-nets.local:8080/',
        'http://127.0.0.1:8080/v1/AUTH_%tenant_id%', '1', '0'),
    ('endpointTemplates', 'add', 'RegionOne', 'nova_compat',
        'http://nova.publicinternets.com/v1.0/',
        'http://127.0.0.1:8774/v1.0', 'http://localhost:8774/v1.0', '1', '0'),
    ('endpointTemplates', 'add', 'RegionOne', 'nova',
        'http://nova.publicinternets.com/v1.1/', 'http://127.0.0.1:8774/v1.1',
        'http://localhost:8774/v1.1', '1', '0'),
    ('endpointTemplates', 'add', 'RegionOne', 'glance',
        'http://glance.publicinternets.com/v1.1/%tenant_id%',
        'http://nova.admin-nets.local/v1.1/%tenant_id%',
        'http://127.0.0.1:9292/v1.1/%tenant_id%', '1', '0'),
    ('endpointTemplates', 'add', 'RegionOne', 'cdn',
        'http://cdn.publicinternets.com/v1.1/%tenant_id%',
        'http://cdn.admin-nets.local/v1.1/%tenant_id%',
        'http://127.0.0.1:7777/v1.1/%tenant_id%', '1', '0'),
# endpointTemplates
    ('endpointTemplates', 'add', 'RegionOne', 'object_store',
        'http://swift.publicinternets.com/v1/AUTH_%tenant_id%',
        'http://swift.admin-nets.local:8080/',
        'http://127.0.0.1:8080/v1/AUTH_%tenant_id%', '1', '0'),
    ('endpointTemplates', 'add', 'RegionOne', 'compute',
        'http://nova.publicinternets.com/v1.0/', 'http://127.0.0.1:8774/v1.0',
        'http://localhost:8774/v1.0', '1', '0'),
    ('endpointTemplates', 'add', 'RegionOne', 'compute_v1',
        'http://nova.publicinternets.com/v1.1/', 'http://127.0.0.1:8774/v1.1',
        'http://localhost:8774/v1.1', '1', '0'),
    ('endpointTemplates', 'add', 'RegionOne', 'image',
        'http://glance.publicinternets.com/v1.1/%tenant_id%',
        'http://nova.admin-nets.local/v1.1/%tenant_id%',
        'http://127.0.0.1:9292/v1.1/%tenant_id%', '1', '0'),
    ('endpointTemplates', 'add', 'RegionOne', 'cdn',
        'http://cdn.publicinternets.com/v1.1/%tenant_id%',
        'http://cdn.admin-nets.local/v1.1/%tenant_id%',
        'http://127.0.0.1:7777/v1.1/%tenant_id%', '1', '0'),
# Global endpointTemplate
    ('endpointTemplates', 'add', 'RegionOne', 'identity',
        'http://keystone.publicinternets.com/v2.0',
        'http://127.0.0.1:5001/v2.0', 'http://127.0.0.1:5000/v2.0', '1', '1'),
# Tokens
    ('token', 'add', '887665443383838', 'joeuser', '1234', '2012-02-05T00:00'),
    ('token', 'add', '999888777666', 'admin', '1234', '2015-02-05T00:00'),
    ('token', 'add', '111222333444', 'serviceadmin', '1234',
        '2015-02-05T00:00'),
    ('token', 'add', '000999', 'admin', '1234', '2010-02-05T00:00'),
    ('token', 'add', '999888777', 'disabled', '1234', '2015-02-05T00:00'),
# Tenant endpointsGlobal endpoint not added
    ('endpoint', 'add', '1234', '1'),
    ('endpoint', 'add', '1234', '2'),
    ('endpoint', 'add', '1234', '3'),
    ('endpoint', 'add', '1234', '4'),
    ('endpoint', 'add', '1234', '5'),
# Add Services
    ('service', 'add', 'exampleservice'),
# Add Credentials
    ('credentials', 'add', 'admin', 'EC2', 'admin:admin', 'admin', 'admin'),
]


def load_fixture(fixture=DEFAULT_FIXTURE, args=None):
    keystone.manage.parse_args(args)
    for cmd in fixture:
        keystone.manage.process(*cmd)


def main():
    load_fixture()


if __name__ == '__main__':
    main()
