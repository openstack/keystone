# Copyright 2014 IBM Corp.
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

import uuid

import sqlalchemy

from keystone.common import sql
from keystone import exception


class PolicyAssociation(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'policy_association'
    attributes = ['policy_id', 'endpoint_id', 'region_id', 'service_id']
    # The id column is never exposed outside this module. It only exists to
    # provide a primary key, given that the real columns we would like to use
    # (endpoint_id, service_id, region_id) can be null
    id = sql.Column(sql.String(64), primary_key=True)
    policy_id = sql.Column(sql.String(64), nullable=False)
    endpoint_id = sql.Column(sql.String(64), nullable=True)
    service_id = sql.Column(sql.String(64), nullable=True)
    region_id = sql.Column(sql.String(64), nullable=True)
    __table_args__ = (sql.UniqueConstraint('endpoint_id', 'service_id',
                                           'region_id'), {})

    def to_dict(self):
        """Returns the model's attributes as a dictionary.

        We override the standard method in order to hide the id column,
        since this only exists to provide the table with a primary key.

        """
        d = {}
        for attr in self.__class__.attributes:
            d[attr] = getattr(self, attr)
        return d


class EndpointPolicy(object):

    def create_policy_association(self, policy_id, endpoint_id=None,
                                  service_id=None, region_id=None):
        with sql.transaction() as session:
            try:
                # See if there is already a row for this association, and if
                # so, update it with the new policy_id
                query = session.query(PolicyAssociation)
                query = query.filter_by(endpoint_id=endpoint_id)
                query = query.filter_by(service_id=service_id)
                query = query.filter_by(region_id=region_id)
                association = query.one()
                association.policy_id = policy_id
            except sql.NotFound:
                association = PolicyAssociation(id=uuid.uuid4().hex,
                                                policy_id=policy_id,
                                                endpoint_id=endpoint_id,
                                                service_id=service_id,
                                                region_id=region_id)
                session.add(association)

    def check_policy_association(self, policy_id, endpoint_id=None,
                                 service_id=None, region_id=None):
        sql_constraints = sqlalchemy.and_(
            PolicyAssociation.policy_id == policy_id,
            PolicyAssociation.endpoint_id == endpoint_id,
            PolicyAssociation.service_id == service_id,
            PolicyAssociation.region_id == region_id)

        # NOTE(henry-nash): Getting a single value to save object
        # management overhead.
        with sql.transaction() as session:
            if session.query(PolicyAssociation.id).filter(
                    sql_constraints).distinct().count() == 0:
                raise exception.PolicyAssociationNotFound()

    def delete_policy_association(self, policy_id, endpoint_id=None,
                                  service_id=None, region_id=None):
        with sql.transaction() as session:
            query = session.query(PolicyAssociation)
            query = query.filter_by(policy_id=policy_id)
            query = query.filter_by(endpoint_id=endpoint_id)
            query = query.filter_by(service_id=service_id)
            query = query.filter_by(region_id=region_id)
            query.delete()

    def get_policy_association(self, endpoint_id=None,
                               service_id=None, region_id=None):
        sql_constraints = sqlalchemy.and_(
            PolicyAssociation.endpoint_id == endpoint_id,
            PolicyAssociation.service_id == service_id,
            PolicyAssociation.region_id == region_id)

        try:
            with sql.transaction() as session:
                policy_id = session.query(PolicyAssociation.policy_id).filter(
                    sql_constraints).distinct().one()
            return {'policy_id': policy_id}
        except sql.NotFound:
            raise exception.PolicyAssociationNotFound()

    def list_associations_for_policy(self, policy_id):
        with sql.transaction() as session:
            query = session.query(PolicyAssociation)
            query = query.filter_by(policy_id=policy_id)
            return [ref.to_dict() for ref in query.all()]

    def delete_association_by_endpoint(self, endpoint_id):
        with sql.transaction() as session:
            query = session.query(PolicyAssociation)
            query = query.filter_by(endpoint_id=endpoint_id)
            query.delete()

    def delete_association_by_service(self, service_id):
        with sql.transaction() as session:
            query = session.query(PolicyAssociation)
            query = query.filter_by(service_id=service_id)
            query.delete()

    def delete_association_by_region(self, region_id):
        with sql.transaction() as session:
            query = session.query(PolicyAssociation)
            query = query.filter_by(region_id=region_id)
            query.delete()

    def delete_association_by_policy(self, policy_id):
        with sql.transaction() as session:
            query = session.query(PolicyAssociation)
            query = query.filter_by(policy_id=policy_id)
            query.delete()
