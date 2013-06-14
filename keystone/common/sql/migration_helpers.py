# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC
# Copyright 2013 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import migrate
import sqlalchemy


#  Different RDBMSs use different schemes for naming the Foreign Key
#  Constraints.  SQLAlchemy does not yet attempt to determine the name
#  for the constraint, and instead attempts to deduce it from the column.
#  This fails on MySQL.
def get_constraints_names(table, column_name):
    fkeys = [fk.name for fk in table.constraints
             if (column_name in fk.columns and
                 isinstance(fk, sqlalchemy.ForeignKeyConstraint))]
    return fkeys


#  remove_constraints and add_constraints both accept a list of dictionaries
#  that contain:
#  {'table': a sqlalchemy table. The constraint is added to to dropped from
#           this table.
#  'fk_column': the name of a column on the above table,  The constraint
#               is added to or dropped from this column
#  'ref_column':a sqlalchemy column object.  This is the reference column
#               for the constraint.
def remove_constraints(constraints):
    for constraint_def in constraints:
        constraint_names = get_constraints_names(constraint_def['table'],
                                                 constraint_def['fk_column'])
        for constraint_name in constraint_names:
            migrate.ForeignKeyConstraint(
                columns=[getattr(constraint_def['table'].c,
                                 constraint_def['fk_column'])],
                refcolumns=[constraint_def['ref_column']],
                name=constraint_name).drop()


def add_constraints(constraints):
    for constraint_def in constraints:

        if constraint_def['table'].kwargs.get('mysql_engine') == 'MyISAM':
            # Don't try to create constraint when using MyISAM because it's
            # not supported.
            continue

        ref_col = constraint_def['ref_column']
        ref_engine = ref_col.table.kwargs.get('mysql_engine')
        if ref_engine == 'MyISAM':
            # Don't try to create constraint when using MyISAM because it's
            # not supported.
            continue

        migrate.ForeignKeyConstraint(
            columns=[getattr(constraint_def['table'].c,
                             constraint_def['fk_column'])],
            refcolumns=[constraint_def['ref_column']]).create()


def rename_tables_with_constraints(renames, constraints, engine):
    """Renames tables with foreign key constraints.

    Tables are renamed after first removing constraints. The constraints are
    replaced after the rename is complete.

    This works on databases that don't support renaming tables that have
    constraints on them (DB2).

    `renames` is a dict, mapping {'to_table_name': from_table, ...}
    """

    if engine.name != 'sqlite':
        # Sqlite doesn't support constraints, so nothing to remove.
        remove_constraints(constraints)

    for to_table_name in renames:
        from_table = renames[to_table_name]
        from_table.rename(to_table_name)

    if engine != 'sqlite':
        add_constraints(constraints)
