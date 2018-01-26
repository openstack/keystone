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

from oslo_db import exception as db_exception
import sqlalchemy

from keystone.common import driver_hints
from keystone.common import sql
from keystone import exception
from keystone.i18n import _
from keystone.limit.backends import base


class RegisteredLimitModel(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'registered_limit'
    attributes = [
        'id',
        'service_id',
        'region_id',
        'resource_name',
        'default_limit'
    ]

    id = sql.Column(sql.String(length=64), primary_key=True)
    service_id = sql.Column(sql.String(255),
                            sql.ForeignKey('service.id'))
    region_id = sql.Column(sql.String(64),
                           sql.ForeignKey('region.id'), nullable=True)
    resource_name = sql.Column(sql.String(255))
    default_limit = sql.Column(sql.Integer, nullable=False)

    __table_args__ = (
        sqlalchemy.UniqueConstraint('service_id',
                                    'region_id',
                                    'resource_name'),)


class LimitModel(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'limit'
    attributes = [
        'id',
        'project_id',
        'service_id',
        'region_id',
        'resource_name',
        'resource_limit'
    ]

    id = sql.Column(sql.String(length=64), primary_key=True)
    project_id = sql.Column(sql.String(64),
                            sql.ForeignKey('project.id'))
    service_id = sql.Column(sql.String(255))
    region_id = sql.Column(sql.String(64), nullable=True)
    resource_name = sql.Column(sql.String(255))
    resource_limit = sql.Column(sql.Integer, nullable=False)

    __table_args__ = (
        sqlalchemy.ForeignKeyConstraint(['service_id',
                                         'region_id',
                                         'resource_name'],
                                        ['registered_limit.service_id',
                                         'registered_limit.region_id',
                                         'registered_limit.resource_name']),
        sqlalchemy.UniqueConstraint('project_id',
                                    'service_id',
                                    'region_id',
                                    'resource_name'),)


class UnifiedLimit(base.UnifiedLimitDriverBase):

    def _check_unified_limit_without_region(self, unified_limit,
                                            is_registered_limit=True):
        hints = driver_hints.Hints()
        hints.add_filter('service_id', unified_limit['service_id'])
        hints.add_filter('resource_name', unified_limit['resource_name'])
        hints.add_filter('region_id', None)
        if not is_registered_limit:
            # For limit, we should ensure:
            # 1. there is no duplicate entry.
            # 2. there is a registered limit reference.
            reference_hints = copy.deepcopy(hints)
            hints.add_filter('project_id', unified_limit['project_id'])
            with sql.session_for_read() as session:
                unified_limits = session.query(LimitModel)
                unified_limits = sql.filter_limit_query(LimitModel,
                                                        unified_limits,
                                                        hints)
            with sql.session_for_read() as session:
                registered_limits = session.query(RegisteredLimitModel)
                registered_limits = sql.filter_limit_query(
                    RegisteredLimitModel, registered_limits, reference_hints)
            if not registered_limits.all():
                raise exception.NoLimitReference
        else:
            # For registered limit, we should just ensure that there is no
            # duplicate entry.
            with sql.session_for_read() as session:
                unified_limits = session.query(RegisteredLimitModel)
                unified_limits = sql.filter_limit_query(RegisteredLimitModel,
                                                        unified_limits,
                                                        hints)
        if unified_limits.all():
            msg = _('Duplicate entry')
            limit_type = 'registered_limit' if is_registered_limit else 'limit'
            raise exception.Conflict(type=limit_type, details=msg)

    def _check_referenced_limit_without_region(self, registered_limit):
        hints = driver_hints.Hints()
        hints.add_filter('service_id', registered_limit.service_id)
        hints.add_filter('resource_name', registered_limit.resource_name)
        hints.add_filter('region_id', None)
        with sql.session_for_read() as session:
            limits = session.query(LimitModel)
            limits = sql.filter_limit_query(LimitModel,
                                            limits,
                                            hints)
        if limits.all():
            raise exception.RegisteredLimitError(id=registered_limit.id)

    @sql.handle_conflicts(conflict_type='registered_limit')
    def create_registered_limits(self, registered_limits):
        with sql.session_for_write() as session:
            for registered_limit in registered_limits:
                if registered_limit.get('region_id') is None:
                    self._check_unified_limit_without_region(registered_limit)
                ref = RegisteredLimitModel.from_dict(registered_limit)
                session.add(ref)

    @sql.handle_conflicts(conflict_type='registered_limit')
    def update_registered_limits(self, registered_limits):
        try:
            with sql.session_for_write() as session:
                for registered_limit in registered_limits:
                    ref = self._get_registered_limit(session,
                                                     registered_limit['id'])
                    if not ref.region_id:
                        self._check_referenced_limit_without_region(ref)
                    old_dict = ref.to_dict()
                    old_dict.update(registered_limit)
                    new_registered_limit = RegisteredLimitModel.from_dict(
                        old_dict)
                    for attr in RegisteredLimitModel.attributes:
                        if attr != 'id':
                            setattr(ref, attr, getattr(new_registered_limit,
                                                       attr))
        except db_exception.DBReferenceError as e:
            try:
                reg_id = e.inner_exception.params['registered_limit_id']
            except (TypeError, KeyError):
                # TODO(wxy): For SQLite, the registered_limit_id is not
                # contained in the error message. We should find a way to
                # handle it, maybe to improve the message in oslo.db.
                error_message = _("Unable to update the registered limits "
                                  "because there are project limits "
                                  "associated with it.")
                raise exception.RegisteredLimitError(message=error_message)
            raise exception.RegisteredLimitError(id=reg_id)

    @driver_hints.truncated
    def list_registered_limits(self, hints):
        with sql.session_for_read() as session:
            registered_limits = session.query(RegisteredLimitModel)
            registered_limits = sql.filter_limit_query(RegisteredLimitModel,
                                                       registered_limits,
                                                       hints)
            return [s.to_dict() for s in registered_limits]

    def _get_registered_limit(self, session, registered_limit_id):
        ref = session.query(RegisteredLimitModel).get(registered_limit_id)
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
                if not ref.region_id:
                    self._check_referenced_limit_without_region(ref)
                session.delete(ref)
        except db_exception.DBReferenceError:
            raise exception.RegisteredLimitError(id=registered_limit_id)

    @sql.handle_conflicts(conflict_type='limit')
    def create_limits(self, limits):
        try:
            with sql.session_for_write() as session:
                for limit in limits:
                    if limit.get('region_id') is None:
                        self._check_unified_limit_without_region(
                            limit, is_registered_limit=False)
                    ref = LimitModel.from_dict(limit)
                    session.add(ref)
        except db_exception.DBReferenceError:
            raise exception.NoLimitReference()

    @sql.handle_conflicts(conflict_type='limit')
    def update_limits(self, limits):
        with sql.session_for_write() as session:
            for limit in limits:
                ref = self._get_limit(session, limit['id'])
                old_dict = ref.to_dict()
                old_dict['resource_limit'] = limit['resource_limit']
                new_limit = LimitModel.from_dict(old_dict)
                ref.resource_limit = new_limit.resource_limit

    @driver_hints.truncated
    def list_limits(self, hints):
        with sql.session_for_read() as session:
            limits = session.query(LimitModel)
            limits = sql.filter_limit_query(LimitModel,
                                            limits,
                                            hints)
            return [s.to_dict() for s in limits]

    def _get_limit(self, session, limit_id):
        ref = session.query(LimitModel).get(limit_id)
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
