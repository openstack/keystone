# Copyright 2017 SUSE Linux Gmbh
# Copyright 2017 Huawei
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

import copy
import sqlalchemy
from sqlalchemy.ext.hybrid import hybrid_property

from oslo_db import exception as db_exception

from keystone.common import driver_hints
from keystone.common import sql
from keystone import exception
from keystone.i18n import _
from keystone.limit.backends import base


class RegisteredLimitModel(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'registered_limit'
    attributes = [
        'internal_id',
        'id',
        'service_id',
        'region_id',
        'resource_name',
        'default_limit',
        'description'
    ]

    internal_id = sql.Column(sql.Integer, primary_key=True, nullable=False)
    id = sql.Column(sql.String(length=64), nullable=False, unique=True)
    service_id = sql.Column(sql.String(255),
                            sql.ForeignKey('service.id'))
    region_id = sql.Column(sql.String(64),
                           sql.ForeignKey('region.id'), nullable=True)
    resource_name = sql.Column(sql.String(255))
    default_limit = sql.Column(sql.Integer, nullable=False)
    description = sql.Column(sql.Text())

    def to_dict(self):
        ref = super(RegisteredLimitModel, self).to_dict()
        ref.pop('internal_id')
        return ref


class LimitModel(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'limit'
    attributes = [
        'internal_id',
        'id',
        'project_id',
        'service_id',
        'region_id',
        'resource_name',
        'resource_limit',
        'description',
        'registered_limit_id'
    ]

    # TODO(wxy): Drop "service_id", "region_id" and "resource_name" columns
    # in T release.
    internal_id = sql.Column(sql.Integer, primary_key=True, nullable=False)
    id = sql.Column(sql.String(length=64), nullable=False, unique=True)
    project_id = sql.Column(sql.String(64))
    _service_id = sql.Column('service_id', sql.String(255))
    _region_id = sql.Column('region_id', sql.String(64), nullable=True)
    _resource_name = sql.Column('resource_name', sql.String(255))
    resource_limit = sql.Column(sql.Integer, nullable=False)
    description = sql.Column(sql.Text())
    registered_limit_id = sql.Column(sql.String(64),
                                     sql.ForeignKey('registered_limit.id'))

    registered_limit = sqlalchemy.orm.relationship('RegisteredLimitModel')

    @hybrid_property
    def service_id(self):
        if self.registered_limit:
            return self.registered_limit.service_id
        return self._service_id

    @service_id.setter
    def service_id(self, value):
        self._service_id = value

    @service_id.expression
    def service_id(self):
        return LimitModel._service_id

    @hybrid_property
    def region_id(self):
        if self.registered_limit:
            return self.registered_limit.region_id
        return self._region_id

    @region_id.setter
    def region_id(self, value):
        self._region_id = value

    @region_id.expression
    def region_id(self):
        return LimitModel._region_id

    @hybrid_property
    def resource_name(self):
        if self.registered_limit:
            return self.registered_limit.resource_name
        return self._resource_name

    @resource_name.setter
    def resource_name(self, value):
        self._resource_name = value

    @resource_name.expression
    def resource_name(self):
        return LimitModel._resource_name

    @classmethod
    def from_dict(cls, limit):
        obj = super(LimitModel, cls).from_dict(limit)
        with sql.session_for_read() as session:
            query = session.query(RegisteredLimitModel).filter_by(
                id=obj.registered_limit_id)
            obj.registered_limit = query.first()
        return obj

    def to_dict(self):
        ref = super(LimitModel, self).to_dict()
        ref.pop('internal_id')
        ref.pop('registered_limit_id')
        return ref


class UnifiedLimit(base.UnifiedLimitDriverBase):

    def _check_unified_limit_unique(self, unified_limit,
                                    is_registered_limit=True):
        # Ensure the new created or updated unified limit won't break the
        # current reference between registered limit and limit. i.e. We should
        # ensure that there is no duplicate entry.
        hints = driver_hints.Hints()
        hints.add_filter('service_id', unified_limit['service_id'])
        hints.add_filter('resource_name', unified_limit['resource_name'])
        hints.add_filter('region_id', unified_limit.get('region_id'))
        if is_registered_limit:
            with sql.session_for_read() as session:
                query = session.query(RegisteredLimitModel)
                unified_limits = sql.filter_limit_query(RegisteredLimitModel,
                                                        query,
                                                        hints).all()
        else:
            hints.add_filter('project_id', unified_limit['project_id'])
            with sql.session_for_read() as session:
                query = session.query(LimitModel)
                old_unified_limits = sql.filter_limit_query(LimitModel,
                                                            query,
                                                            hints).all()
                query = session.query(
                    LimitModel).outerjoin(RegisteredLimitModel)
                new_unified_limits = query.filter(
                    LimitModel.project_id ==
                    unified_limit['project_id'],
                    RegisteredLimitModel.service_id ==
                    unified_limit['service_id'],
                    RegisteredLimitModel.region_id ==
                    unified_limit.get('region_id'),
                    RegisteredLimitModel.resource_name ==
                    unified_limit['resource_name']).all()
                unified_limits = old_unified_limits + new_unified_limits

        if unified_limits:
            msg = _('Duplicate entry')
            limit_type = 'registered_limit' if is_registered_limit else 'limit'
            raise exception.Conflict(type=limit_type, details=msg)

    def _check_referenced_limit_reference(self, registered_limit):
        # When updating or deleting a registered limit, we should ensure there
        # is no reference limit.
        with sql.session_for_read() as session:
            limits = session.query(LimitModel).filter_by(
                registered_limit_id=registered_limit['id'])
        if limits.all():
            raise exception.RegisteredLimitError(id=registered_limit.id)

    @sql.handle_conflicts(conflict_type='registered_limit')
    def create_registered_limits(self, registered_limits):
        with sql.session_for_write() as session:
            new_registered_limits = []
            for registered_limit in registered_limits:
                self._check_unified_limit_unique(registered_limit)
                ref = RegisteredLimitModel.from_dict(registered_limit)
                session.add(ref)
                new_registered_limits.append(ref.to_dict())
            return new_registered_limits

    @sql.handle_conflicts(conflict_type='registered_limit')
    def update_registered_limit(self, registered_limit_id, registered_limit):
        try:
            with sql.session_for_write() as session:
                ref = self._get_registered_limit(session, registered_limit_id)
                self._check_referenced_limit_reference(ref)
                old_dict = ref.to_dict()
                old_dict.update(registered_limit)
                if (registered_limit.get('service_id') or
                        registered_limit.get('region_id') or
                        registered_limit.get('resource_name')):
                    self._check_unified_limit_unique(old_dict)
                new_registered_limit = RegisteredLimitModel.from_dict(
                    old_dict)
                for attr in registered_limit:
                    if attr != 'id':
                        setattr(ref, attr, getattr(new_registered_limit,
                                                   attr))
                return ref.to_dict()
        except db_exception.DBReferenceError:
            raise exception.RegisteredLimitError(id=registered_limit_id)

    @driver_hints.truncated
    def list_registered_limits(self, hints):
        with sql.session_for_read() as session:
            registered_limits = session.query(RegisteredLimitModel)
            registered_limits = sql.filter_limit_query(RegisteredLimitModel,
                                                       registered_limits,
                                                       hints)
            return [s.to_dict() for s in registered_limits]

    def _get_registered_limit(self, session, registered_limit_id):
        query = session.query(RegisteredLimitModel).filter_by(
            id=registered_limit_id)
        ref = query.first()
        if ref is None:
            raise exception.RegisteredLimitNotFound(id=registered_limit_id)
        return ref

    def get_registered_limit(self, registered_limit_id):
        with sql.session_for_read() as session:
            return self._get_registered_limit(
                session, registered_limit_id).to_dict()

    def delete_registered_limit(self, registered_limit_id):
        try:
            with sql.session_for_write() as session:
                ref = self._get_registered_limit(session,
                                                 registered_limit_id)
                self._check_referenced_limit_reference(ref)
                session.delete(ref)
        except db_exception.DBReferenceError:
            raise exception.RegisteredLimitError(id=registered_limit_id)

    def _check_and_fill_registered_limit_id(self, limit):
        # Make sure there is a referenced registered limit first. Then add
        # the registered limit id to the new created limit.
        hints = driver_hints.Hints()
        limit_copy = copy.deepcopy(limit)
        hints.add_filter('service_id', limit_copy.pop('service_id'))
        hints.add_filter('resource_name', limit_copy.pop('resource_name'))
        hints.add_filter('region_id', limit_copy.pop('region_id', None))

        with sql.session_for_read() as session:
            registered_limits = session.query(RegisteredLimitModel)
            registered_limits = sql.filter_limit_query(
                RegisteredLimitModel, registered_limits, hints)
        reg_limits = registered_limits.all()
        if not reg_limits:
            raise exception.NoLimitReference

        limit_copy['registered_limit_id'] = reg_limits[0]['id']
        return limit_copy

    @sql.handle_conflicts(conflict_type='limit')
    def create_limits(self, limits):
        try:
            with sql.session_for_write() as session:
                new_limits = []
                for limit in limits:
                    self._check_unified_limit_unique(limit,
                                                     is_registered_limit=False)
                    target = self._check_and_fill_registered_limit_id(limit)
                    ref = LimitModel.from_dict(target)
                    session.add(ref)
                    new_limits.append(ref.to_dict())
                return new_limits
        except db_exception.DBReferenceError:
            raise exception.NoLimitReference()

    @sql.handle_conflicts(conflict_type='limit')
    def update_limit(self, limit_id, limit):
        with sql.session_for_write() as session:
            ref = self._get_limit(session, limit_id)
            old_dict = ref.to_dict()
            old_dict.update(limit)
            new_limit = LimitModel.from_dict(old_dict)
            ref.resource_limit = new_limit.resource_limit
            ref.description = new_limit.description
            return ref.to_dict()

    @driver_hints.truncated
    def list_limits(self, hints):
        hint_copy = copy.deepcopy(hints)
        new_format_data = []
        with sql.session_for_read() as session:
            query = session.query(LimitModel)
            limits = sql.filter_limit_query(LimitModel,
                                            query,
                                            hints)
            old_format_data = [s.to_dict() for s in limits]
            project_filter = hint_copy.get_exact_filter_by_name('project_id')
            if hint_copy.filters and (not project_filter
                                      or len(hint_copy.filters) > 1):
                # If the hints contain "service_id", "region_id" or
                # "resource_name", we should combine the registered_limit table
                # first to fetch these information.
                query_new = session.query(
                    LimitModel).outerjoin(RegisteredLimitModel)
                limits = sql.filter_limit_query(RegisteredLimitModel,
                                                query_new,
                                                hint_copy)
                if project_filter:
                    limits = limits.filter(
                        LimitModel.project_id == project_filter['value'])
                new_format_data = [s.to_dict() for s in limits]
            return old_format_data + new_format_data

    def _get_limit(self, session, limit_id):
        query = session.query(LimitModel).filter_by(id=limit_id)
        ref = query.first()
        if ref is None:
            raise exception.LimitNotFound(id=limit_id)
        return ref

    def get_limit(self, limit_id):
        with sql.session_for_read() as session:
            return self._get_limit(session,
                                   limit_id).to_dict()

    def delete_limit(self, limit_id):
        with sql.session_for_write() as session:
            ref = self._get_limit(session,
                                  limit_id)
            session.delete(ref)

    def delete_limits_for_project(self, project_id):
        limit_ids = []
        with sql.session_for_write() as session:
            query = session.query(LimitModel)
            query = query.filter_by(project_id=project_id)
            for limit in query.all():
                limit_ids.append(limit.id)
            query.delete()
        return limit_ids
