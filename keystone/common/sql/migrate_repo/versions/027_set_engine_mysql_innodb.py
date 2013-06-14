
import sqlalchemy as sql
from sqlalchemy import MetaData

from keystone.common.sql import migration_helpers


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine;
    # bind migrate_engine to your metadata

    if migrate_engine.name != 'mysql':
        # InnoDB / MyISAM only applies to MySQL.
        return

    # This is a list of all the tables that might have been created with MyISAM
    # rather than InnoDB.
    tables = [
        'credential',
        'domain',
        'ec2_credential',
        'endpoint',
        'group',
        'group_domain_metadata',
        'group_project_metadata',
        'policy',
        'project',
        'role',
        'service',
        'token',
        'trust',
        'trust_role',
        'user',
        'user_domain_metadata',
        'user_group_membership',
        'user_project_metadata',
    ]

    meta = MetaData()
    meta.bind = migrate_engine

    domain_table = sql.Table('domain', meta, autoload=True)
    endpoint_table = sql.Table('endpoint', meta, autoload=True)
    group_table = sql.Table('group', meta, autoload=True)
    group_domain_metadata_table = sql.Table('group_domain_metadata', meta,
                                            autoload=True)
    group_project_metadata_table = sql.Table('group_project_metadata', meta,
                                             autoload=True)
    project_table = sql.Table('project', meta, autoload=True)
    service_table = sql.Table('service', meta, autoload=True)
    user_table = sql.Table('user', meta, autoload=True)
    user_domain_metadata_table = sql.Table('user_domain_metadata', meta,
                                           autoload=True)
    user_group_membership_table = sql.Table('user_group_membership', meta,
                                            autoload=True)

    # Mapping of table name to the constraints on that table,
    # so we can create them.
    table_constraints = {
        'endpoint': [{'table': endpoint_table,
                      'fk_column': 'service_id',
                      'ref_column': service_table.c.id},
                     ],
        'group': [{'table': group_table,
                   'fk_column': 'domain_id',
                   'ref_column': domain_table.c.id},
                  ],
        'group_domain_metadata': [{'table': group_domain_metadata_table,
                                   'fk_column': 'domain_id',
                                   'ref_column': domain_table.c.id},
                                  ],
        'group_project_metadata': [{'table': group_project_metadata_table,
                                    'fk_column': 'project_id',
                                    'ref_column': project_table.c.id},
                                   ],
        'project': [{'table': project_table,
                     'fk_column': 'domain_id',
                     'ref_column': domain_table.c.id},
                    ],
        'user': [{'table': user_table,
                  'fk_column': 'domain_id',
                  'ref_column': domain_table.c.id},
                 ],
        'user_domain_metadata': [{'table': user_domain_metadata_table,
                                  'fk_column': 'domain_id',
                                  'ref_column': domain_table.c.id},
                                 ],
        'user_group_membership': [{'table': user_group_membership_table,
                                   'fk_column': 'user_id',
                                   'ref_column': user_table.c.id},
                                  {'table': user_group_membership_table,
                                   'fk_column': 'group_id',
                                   'ref_column': group_table.c.id},
                                  ],
        'user_project_metadata': [{'table': group_project_metadata_table,
                                   'fk_column': 'project_id',
                                   'ref_column': project_table.c.id},
                                  ],
    }

    # Maps a table name to the tables that reference it as a FK constraint
    # (See the map above).
    ref_tables_map = {
        'service': ['endpoint', ],
        'domain': ['group', 'group_domain_metadata', 'project', 'user',
                   'user_domain_metadata', ],
        'project': ['group_project_metadata', 'user_project_metadata', ],
        'user': ['user_group_membership', ],
        'group': ['user_group_membership', ],
    }

    # The names of tables that need to have their FKs added.
    fk_table_names = set()

    d = migrate_engine.execute("SHOW TABLE STATUS WHERE Engine!='InnoDB';")
    for row in d.fetchall():
        table_name = row[0]

        if table_name not in tables:
            # Skip this table since it's not a Keystone table.
            continue

        migrate_engine.execute("ALTER TABLE `%s` Engine=InnoDB" % table_name)

        # Will add the FKs to the table if any of
        # a) the table itself was converted
        # b) the tables that the table referenced were converted

        if table_name in table_constraints:
            fk_table_names.add(table_name)

        ref_tables = ref_tables_map.get(table_name, [])
        for other_table_name in ref_tables:
            fk_table_names.add(other_table_name)

    # Now add all the FK constraints to those tables
    for table_name in fk_table_names:
        constraints = table_constraints.get(table_name)
        migration_helpers.add_constraints(constraints)


def downgrade(migrate_engine):
    pass
