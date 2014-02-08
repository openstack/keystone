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
from sqlalchemy.ext.declarative import declarative_base

from keystone.openstack.common.db.sqlalchemy import models


class KdsBase(models.ModelBase):
    pass


Base = declarative_base(cls=KdsBase)


class Host(Base):
    __tablename__ = 'kds_hosts'

    id = sql.Column(sql.Integer(), primary_key=True, autoincrement=True)
    name = sql.Column(sql.Text(), index=True, unique=True, nullable=False)
    group = sql.Column(sql.Boolean(), nullable=False, index=True)
    latest_generation = sql.Column(sql.Integer(), nullable=False)


class Key(Base):
    __tablename__ = 'kds_keys'

    host_id = sql.Column(sql.Integer(),
                         sql.ForeignKey('kds_hosts.id'),
                         primary_key=True,
                         autoincrement=False)

    generation = sql.Column(sql.Integer(),
                            primary_key=True,
                            autoincrement=False)

    signature = sql.Column(sql.LargeBinary(),
                           nullable=False)

    enc_key = sql.Column(sql.LargeBinary(),
                         nullable=False)

    expiration = sql.Column(sql.DateTime(),
                            nullable=True,
                            index=True)

    owner = sql.orm.relationship('Host',
                                 backref=sql.orm.backref('keys',
                                                         order_by=sql.desc(
                                                             generation)))
