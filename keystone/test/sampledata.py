import keystone.manage

DEFAULT_FIXTURE = [
# Tenants
    ('tenant', 'add', 'customer-x'),
    ('tenant', 'add', 'ANOTHER:TENANT'),
    ('tenant', 'add', 'project-y'),
    ('tenant', 'disable', 'project-y'),
# Users
    ('user', 'add', 'joeuser', 'secrete', 'customer-x'),
    ('user', 'add', 'joeadmin', 'secrete', 'customer-x'),
    ('user', 'add', 'admin', 'secrete'),
    ('user', 'add', 'serviceadmin', 'secrete', 'customer-x'),
    ('user', 'add', 'disabled', 'secrete', 'customer-x'),
    ('user', 'disable', 'disabled'),
# Roles
    ('role', 'add', 'Admin'),
    ('role', 'add', 'KeystoneServiceAdmin'),
    ('role', 'grant', 'Admin', 'admin'),
    ('role', 'grant', 'KeystoneServiceAdmin', 'serviceadmin'),
    ('role', 'grant', 'Admin', 'joeadmin', 'customer-x'),
    ('role', 'grant', 'Admin', 'joeadmin', 'ANOTHER:TENANT'),
    ('role', 'add', 'Member'),
    ('role', 'grant', 'Member', 'joeuser', 'customer-x'),
# Add Services
    #1 Service Name:exampleservice Type:example type
    ('service', 'add', 'exampleservice',
        'example type', 'example description'),
    #2 Service Name:swift Type:object-store
    ('service', 'add', 'swift',
        'object-store', 'Swift-compatible service'),
    #3 Service Name:cdn Type:object-store
    ('service', 'add', 'cdn',
        'object-store', 'Swift-compatible service'),
    #4 Service Name:nova Type:compute
    ('service', 'add', 'nova',
        'compute', 'OpenStack Compute Service'),
    #5 Service Name:nova_compat Type:Compute
    ('service', 'add', 'nova_compat',
        'compute', 'OpenStack Compute Service'),
    #6 Service Name:glance Type:image
    ('service', 'add', 'glance',
        'image', 'OpenStack Image Service'),
    #7 Service Name:keystone Type:identity
    ('service', 'add', 'identity',
        'identity', 'OpenStack Identity Service'),
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
        'http://127.0.0.1:7777/v1.1/%tenant_id%', '1',
        '0', '1.1', 'http://127.0.0.1:7777/', 'http://127.0.0.1:7777/v1.1'),
# endpointTemplates
    ('endpointTemplates', 'add', 'RegionOne', 'swift',
        'http://swift.publicinternets.com/v1/AUTH_%tenant_id%',
        'http://swift.admin-nets.local:8080/',
        'http://127.0.0.1:8080/v1/AUTH_%tenant_id%', '1', '0'),
    ('endpointTemplates', 'add', 'RegionOne', 'nova',
        'http://nova.publicinternets.com/v1.0/', 'http://127.0.0.1:8774/v1.0',
        'http://localhost:8774/v1.0', '1', '0'),
    ('endpointTemplates', 'add', 'RegionOne', 'nova_compat',
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
# Global endpointTemplate
    ('endpointTemplates', 'add', 'RegionOne', 'identity',
        'http://keystone.publicinternets.com/v2.0',
        'http://127.0.0.1:35357/v2.0', 'http://127.0.0.1:5000/v2.0', '1', '1'),
# Tokens
    ('token', 'add', '887665443383838', 'joeuser', 'customer-x',
        '2012-02-05T00:00'),
    ('token', 'add', '999888777666', 'admin', 'customer-x',
        '2015-02-05T00:00'),
    ('token', 'add', '111222333444', 'serviceadmin', 'customer-x',
        '2015-02-05T00:00'),
    ('token', 'add', '000999', 'admin', 'customer-x', '2010-02-05T00:00'),
    ('token', 'add', '999888777', 'disabled', 'customer-x',
        '2015-02-05T00:00'),
# Tenant endpointsGlobal endpoint not added
    ('endpoint', 'add', 'customer-x', '1'),
    ('endpoint', 'add', 'customer-x', '2'),
    ('endpoint', 'add', 'customer-x', '3'),
    ('endpoint', 'add', 'customer-x', '4'),
    ('endpoint', 'add', 'customer-x', '5'),
# Add Credentials
    ('credentials', 'add', 'admin', 'EC2', 'admin:admin', 'admin',
        'customer-x'),
]


def load_fixture(fixture=DEFAULT_FIXTURE, args=None):
    keystone.manage.parse_args(args)
    for cmd in fixture:
        keystone.manage.process(*cmd)


def main():
    load_fixture()


if __name__ == '__main__':
    main()
