# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import sqlalchemy as sql

from keystone.common import utils
from keystone import exception


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    credential_table = sql.Table('credential',
                                 meta,
                                 autoload=True)

    ec2_cred_table = sql.Table('ec2_credential',
                               meta,
                               autoload=True)

    session = sql.orm.sessionmaker(bind=migrate_engine)()
    insert = credential_table.insert()
    for ec2credential in session.query(ec2_cred_table):
        cred_exist = check_credential_exists(ec2credential,
                                             credential_table, session)

        if not cred_exist:
            credential = utils.convert_ec2_to_v3_credential(ec2credential)
            insert.execute(credential)

    session.commit()
    session.close()

    ec2_cred_table.drop()


def check_credential_exists(ec2credential, credential_table, session):
    credential = session.query(credential_table).filter_by(
        id=utils.hash_access_key(ec2credential.access)).first()
    if credential is None:
        return False
    blob = utils.get_blob_from_credential(credential)
    # check if credential with same access key but different
    # secret key already exists in credential table.
    # If exists raise an exception
    if blob['secret'] != ec2credential.secret:
        msg = _('Credential %(access)s already exists with different secret'
                ' in %(table)s table')
        message = msg % {'access': ec2credential.access,
                         'table': credential_table.name}
        raise exception.Conflict(type='credential', details=message)
    # check if credential with same access and secret key but
    # associated with a different project exists. If exists raise
    # an exception
    elif credential.project_id is not None and (
            credential.project_id != ec2credential.tenant_id):
        msg = _('Credential %(access)s already exists with different project'
                ' in %(table)s table')
        message = msg % {'access': ec2credential.access,
                         'table': credential_table.name}
        raise exception.Conflict(type='credential', details=message)
    # if credential with same access and secret key and not associated
    # with any projects already exists in the credential table, then
    # return true.
    else:
        return True


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    session = sql.orm.sessionmaker(bind=migrate_engine)()

    ec2_credential_table = sql.Table(
        'ec2_credential',
        meta,
        sql.Column('access', sql.String(64), primary_key=True),
        sql.Column('secret', sql.String(64)),
        sql.Column('user_id', sql.String(64)),
        sql.Column('tenant_id', sql.String(64)),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    ec2_credential_table.create(migrate_engine, checkfirst=True)
    credential_table = sql.Table('credential',
                                 meta,
                                 autoload=True)
    insert = ec2_credential_table.insert()
    for credential in session.query(credential_table).filter(
            sql.and_(credential_table.c.type == 'ec2',
                     credential_table.c.project_id is not None)).all():
        ec2_credential = utils.convert_v3_to_ec2_credential(credential)
        insert.execute(ec2_credential)

    session.commit()
    session.close()
