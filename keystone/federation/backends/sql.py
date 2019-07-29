# Copyright 2014 OpenStack Foundation
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

from oslo_log import log
from oslo_serialization import jsonutils
from sqlalchemy import orm

from keystone.common import sql
from keystone import exception
from keystone.federation.backends import base
from keystone.i18n import _


LOG = log.getLogger(__name__)


class FederationProtocolModel(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'federation_protocol'
    attributes = ['id', 'idp_id', 'mapping_id', 'remote_id_attribute']
    mutable_attributes = frozenset(['mapping_id', 'remote_id_attribute'])

    id = sql.Column(sql.String(64), primary_key=True)
    idp_id = sql.Column(sql.String(64), sql.ForeignKey('identity_provider.id',
                        ondelete='CASCADE'), primary_key=True)
    mapping_id = sql.Column(sql.String(64), nullable=False)
    remote_id_attribute = sql.Column(sql.String(64))

    @classmethod
    def from_dict(cls, dictionary):
        new_dictionary = dictionary.copy()
        return cls(**new_dictionary)

    def to_dict(self):
        """Return a dictionary with model's attributes."""
        d = dict()
        for attr in self.__class__.attributes:
            d[attr] = getattr(self, attr)
        return d


class IdentityProviderModel(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'identity_provider'
    attributes = ['id', 'domain_id', 'enabled', 'description', 'remote_ids',
                  'authorization_ttl']
    mutable_attributes = frozenset(['description', 'enabled', 'remote_ids',
                                    'authorization_ttl'])

    id = sql.Column(sql.String(64), primary_key=True)
    domain_id = sql.Column(sql.String(64), nullable=False)
    enabled = sql.Column(sql.Boolean, nullable=False)
    description = sql.Column(sql.Text(), nullable=True)
    authorization_ttl = sql.Column(sql.Integer, nullable=True)

    remote_ids = orm.relationship('IdPRemoteIdsModel',
                                  order_by='IdPRemoteIdsModel.remote_id',
                                  cascade='all, delete-orphan')
    expiring_user_group_memberships = orm.relationship(
        'ExpiringUserGroupMembership',
        cascade='all, delete-orphan',
        backref="idp"
    )

    @classmethod
    def from_dict(cls, dictionary):
        new_dictionary = dictionary.copy()
        remote_ids_list = new_dictionary.pop('remote_ids', None)
        if not remote_ids_list:
            remote_ids_list = []
        identity_provider = cls(**new_dictionary)
        remote_ids = []
        # NOTE(fmarco76): the remote_ids_list contains only remote ids
        # associated with the IdP because of the "relationship" established in
        # sqlalchemy and corresponding to the FK in the idp_remote_ids table
        for remote in remote_ids_list:
            remote_ids.append(IdPRemoteIdsModel(remote_id=remote))
        identity_provider.remote_ids = remote_ids
        return identity_provider

    def to_dict(self):
        """Return a dictionary with model's attributes."""
        d = dict()
        for attr in self.__class__.attributes:
            d[attr] = getattr(self, attr)
        d['remote_ids'] = []
        for remote in self.remote_ids:
            d['remote_ids'].append(remote.remote_id)
        return d


class IdPRemoteIdsModel(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'idp_remote_ids'
    attributes = ['idp_id', 'remote_id']
    mutable_attributes = frozenset(['idp_id', 'remote_id'])

    idp_id = sql.Column(sql.String(64),
                        sql.ForeignKey('identity_provider.id',
                                       ondelete='CASCADE'))
    remote_id = sql.Column(sql.String(255),
                           primary_key=True)

    @classmethod
    def from_dict(cls, dictionary):
        new_dictionary = dictionary.copy()
        return cls(**new_dictionary)

    def to_dict(self):
        """Return a dictionary with model's attributes."""
        d = dict()
        for attr in self.__class__.attributes:
            d[attr] = getattr(self, attr)
        return d


class MappingModel(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'mapping'
    attributes = ['id', 'rules']

    id = sql.Column(sql.String(64), primary_key=True)
    rules = sql.Column(sql.JsonBlob(), nullable=False)

    @classmethod
    def from_dict(cls, dictionary):
        new_dictionary = dictionary.copy()
        new_dictionary['rules'] = jsonutils.dumps(new_dictionary['rules'])
        return cls(**new_dictionary)

    def to_dict(self):
        """Return a dictionary with model's attributes."""
        d = dict()
        for attr in self.__class__.attributes:
            d[attr] = getattr(self, attr)
        d['rules'] = jsonutils.loads(d['rules'])
        return d


class ServiceProviderModel(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'service_provider'
    attributes = ['auth_url', 'id', 'enabled', 'description',
                  'relay_state_prefix', 'sp_url']
    mutable_attributes = frozenset(['auth_url', 'description', 'enabled',
                                    'relay_state_prefix', 'sp_url'])

    id = sql.Column(sql.String(64), primary_key=True)
    enabled = sql.Column(sql.Boolean, nullable=False)
    description = sql.Column(sql.Text(), nullable=True)
    auth_url = sql.Column(sql.String(256), nullable=False)
    sp_url = sql.Column(sql.String(256), nullable=False)
    relay_state_prefix = sql.Column(sql.String(256), nullable=False)

    @classmethod
    def from_dict(cls, dictionary):
        new_dictionary = dictionary.copy()
        return cls(**new_dictionary)

    def to_dict(self):
        """Return a dictionary with model's attributes."""
        d = dict()
        for attr in self.__class__.attributes:
            d[attr] = getattr(self, attr)
        return d


class Federation(base.FederationDriverBase):

    _CONFLICT_LOG_MSG = 'Conflict %(conflict_type)s: %(details)s'

    def _handle_idp_conflict(self, e):
        conflict_type = 'identity_provider'
        details = str(e)
        LOG.debug(self._CONFLICT_LOG_MSG, {'conflict_type': conflict_type,
                                           'details': details})
        if 'remote_id' in details:
            msg = _('Duplicate remote ID: %s')
        else:
            msg = _('Duplicate entry: %s')
        msg = msg % e.value
        raise exception.Conflict(type=conflict_type, details=msg)

    # Identity Provider CRUD
    def create_idp(self, idp_id, idp):
        idp['id'] = idp_id
        try:
            with sql.session_for_write() as session:
                idp_ref = IdentityProviderModel.from_dict(idp)
                session.add(idp_ref)
                return idp_ref.to_dict()
        except sql.DBDuplicateEntry as e:
            self._handle_idp_conflict(e)

    def delete_idp(self, idp_id):
        with sql.session_for_write() as session:
            self._delete_assigned_protocols(session, idp_id)
            idp_ref = self._get_idp(session, idp_id)
            session.delete(idp_ref)

    def _get_idp(self, session, idp_id):
        idp_ref = session.query(IdentityProviderModel).get(idp_id)
        if not idp_ref:
            raise exception.IdentityProviderNotFound(idp_id=idp_id)
        return idp_ref

    def _get_idp_from_remote_id(self, session, remote_id):
        q = session.query(IdPRemoteIdsModel)
        q = q.filter_by(remote_id=remote_id)
        try:
            return q.one()
        except sql.NotFound:
            raise exception.IdentityProviderNotFound(idp_id=remote_id)

    def list_idps(self, hints=None):
        with sql.session_for_read() as session:
            query = session.query(IdentityProviderModel)
            idps = sql.filter_limit_query(IdentityProviderModel, query, hints)
            idps_list = [idp.to_dict() for idp in idps]
            return idps_list

    def get_idp(self, idp_id):
        with sql.session_for_read() as session:
            idp_ref = self._get_idp(session, idp_id)
            return idp_ref.to_dict()

    def get_idp_from_remote_id(self, remote_id):
        with sql.session_for_read() as session:
            ref = self._get_idp_from_remote_id(session, remote_id)
            return ref.to_dict()

    def update_idp(self, idp_id, idp):
        try:
            with sql.session_for_write() as session:
                idp_ref = self._get_idp(session, idp_id)
                old_idp = idp_ref.to_dict()
                old_idp.update(idp)
                new_idp = IdentityProviderModel.from_dict(old_idp)
                for attr in IdentityProviderModel.mutable_attributes:
                    setattr(idp_ref, attr, getattr(new_idp, attr))
                return idp_ref.to_dict()
        except sql.DBDuplicateEntry as e:
            self._handle_idp_conflict(e)

    # Protocol CRUD
    def _get_protocol(self, session, idp_id, protocol_id):
        q = session.query(FederationProtocolModel)
        q = q.filter_by(id=protocol_id, idp_id=idp_id)
        try:
            return q.one()
        except sql.NotFound:
            kwargs = {'protocol_id': protocol_id,
                      'idp_id': idp_id}
            raise exception.FederatedProtocolNotFound(**kwargs)

    @sql.handle_conflicts(conflict_type='federation_protocol')
    def create_protocol(self, idp_id, protocol_id, protocol):
        protocol['id'] = protocol_id
        protocol['idp_id'] = idp_id
        with sql.session_for_write() as session:
            self._get_idp(session, idp_id)
            protocol_ref = FederationProtocolModel.from_dict(protocol)
            session.add(protocol_ref)
            return protocol_ref.to_dict()

    def update_protocol(self, idp_id, protocol_id, protocol):
        with sql.session_for_write() as session:
            proto_ref = self._get_protocol(session, idp_id, protocol_id)
            old_proto = proto_ref.to_dict()
            old_proto.update(protocol)
            new_proto = FederationProtocolModel.from_dict(old_proto)
            for attr in FederationProtocolModel.mutable_attributes:
                setattr(proto_ref, attr, getattr(new_proto, attr))
            return proto_ref.to_dict()

    def get_protocol(self, idp_id, protocol_id):
        with sql.session_for_read() as session:
            protocol_ref = self._get_protocol(session, idp_id, protocol_id)
            return protocol_ref.to_dict()

    def list_protocols(self, idp_id):
        with sql.session_for_read() as session:
            q = session.query(FederationProtocolModel)
            q = q.filter_by(idp_id=idp_id)
            protocols = [protocol.to_dict() for protocol in q]
            return protocols

    def delete_protocol(self, idp_id, protocol_id):
        with sql.session_for_write() as session:
            key_ref = self._get_protocol(session, idp_id, protocol_id)
            session.delete(key_ref)

    def _delete_assigned_protocols(self, session, idp_id):
        query = session.query(FederationProtocolModel)
        query = query.filter_by(idp_id=idp_id)
        query.delete()

    # Mapping CRUD
    def _get_mapping(self, session, mapping_id):
        mapping_ref = session.query(MappingModel).get(mapping_id)
        if not mapping_ref:
            raise exception.MappingNotFound(mapping_id=mapping_id)
        return mapping_ref

    @sql.handle_conflicts(conflict_type='mapping')
    def create_mapping(self, mapping_id, mapping):
        ref = {}
        ref['id'] = mapping_id
        ref['rules'] = mapping.get('rules')
        with sql.session_for_write() as session:
            mapping_ref = MappingModel.from_dict(ref)
            session.add(mapping_ref)
            return mapping_ref.to_dict()

    def delete_mapping(self, mapping_id):
        with sql.session_for_write() as session:
            mapping_ref = self._get_mapping(session, mapping_id)
            session.delete(mapping_ref)

    def list_mappings(self):
        with sql.session_for_read() as session:
            mappings = session.query(MappingModel)
            return [x.to_dict() for x in mappings]

    def get_mapping(self, mapping_id):
        with sql.session_for_read() as session:
            mapping_ref = self._get_mapping(session, mapping_id)
            return mapping_ref.to_dict()

    @sql.handle_conflicts(conflict_type='mapping')
    def update_mapping(self, mapping_id, mapping):
        ref = {}
        ref['id'] = mapping_id
        ref['rules'] = mapping.get('rules')
        with sql.session_for_write() as session:
            mapping_ref = self._get_mapping(session, mapping_id)
            old_mapping = mapping_ref.to_dict()
            old_mapping.update(ref)
            new_mapping = MappingModel.from_dict(old_mapping)
            for attr in MappingModel.attributes:
                setattr(mapping_ref, attr, getattr(new_mapping, attr))
            return mapping_ref.to_dict()

    def get_mapping_from_idp_and_protocol(self, idp_id, protocol_id):
        with sql.session_for_read() as session:
            protocol_ref = self._get_protocol(session, idp_id, protocol_id)
            mapping_id = protocol_ref.mapping_id
            mapping_ref = self._get_mapping(session, mapping_id)
            return mapping_ref.to_dict()

    # Service Provider CRUD
    @sql.handle_conflicts(conflict_type='service_provider')
    def create_sp(self, sp_id, sp):
        sp['id'] = sp_id
        with sql.session_for_write() as session:
            sp_ref = ServiceProviderModel.from_dict(sp)
            session.add(sp_ref)
            return sp_ref.to_dict()

    def delete_sp(self, sp_id):
        with sql.session_for_write() as session:
            sp_ref = self._get_sp(session, sp_id)
            session.delete(sp_ref)

    def _get_sp(self, session, sp_id):
        sp_ref = session.query(ServiceProviderModel).get(sp_id)
        if not sp_ref:
            raise exception.ServiceProviderNotFound(sp_id=sp_id)
        return sp_ref

    def list_sps(self, hints=None):
        with sql.session_for_read() as session:
            query = session.query(ServiceProviderModel)
            sps = sql.filter_limit_query(ServiceProviderModel, query, hints)
            sps_list = [sp.to_dict() for sp in sps]
            return sps_list

    def get_sp(self, sp_id):
        with sql.session_for_read() as session:
            sp_ref = self._get_sp(session, sp_id)
            return sp_ref.to_dict()

    def update_sp(self, sp_id, sp):
        with sql.session_for_write() as session:
            sp_ref = self._get_sp(session, sp_id)
            old_sp = sp_ref.to_dict()
            old_sp.update(sp)
            new_sp = ServiceProviderModel.from_dict(old_sp)
            for attr in ServiceProviderModel.mutable_attributes:
                setattr(sp_ref, attr, getattr(new_sp, attr))
            return sp_ref.to_dict()

    def get_enabled_service_providers(self):
        with sql.session_for_read() as session:
            service_providers = session.query(ServiceProviderModel)
            service_providers = service_providers.filter_by(enabled=True)
            return service_providers
