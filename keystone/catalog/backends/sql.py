# Copyright 2012 OpenStack Foundation
# Copyright 2012 Canonical Ltd.
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

import itertools

from oslo_config import cfg
import sqlalchemy
from sqlalchemy.sql import true

from keystone import catalog
from keystone.catalog import core
from keystone.common import sql
from keystone import exception


CONF = cfg.CONF


class Region(sql.ModelBase, sql.DictBase):
    __tablename__ = 'region'
    attributes = ['id', 'description', 'parent_region_id']
    id = sql.Column(sql.String(255), primary_key=True)
    description = sql.Column(sql.String(255), nullable=False)
    # NOTE(jaypipes): Right now, using an adjacency list model for
    #                 storing the hierarchy of regions is fine, since
    #                 the API does not support any kind of querying for
    #                 more complex hierarchical queries such as "get me only
    #                 the regions that are subchildren of this region", etc.
    #                 If, in the future, such queries are needed, then it
    #                 would be possible to add in columns to this model for
    #                 "left" and "right" and provide support for a nested set
    #                 model.
    parent_region_id = sql.Column(sql.String(255), nullable=True)

    # TODO(jaypipes): I think it's absolutely stupid that every single model
    #                 is required to have an "extra" column because of the
    #                 DictBase in the keystone.common.sql.core module. Forcing
    #                 tables to have pointless columns in the database is just
    #                 bad. Remove all of this extra JSON blob stuff.
    #                 See: https://bugs.launchpad.net/keystone/+bug/1265071
    extra = sql.Column(sql.JsonBlob())
    endpoints = sqlalchemy.orm.relationship("Endpoint", backref="region")


class Service(sql.ModelBase, sql.DictBase):
    __tablename__ = 'service'
    attributes = ['id', 'type', 'enabled']
    id = sql.Column(sql.String(64), primary_key=True)
    type = sql.Column(sql.String(255))
    enabled = sql.Column(sql.Boolean, nullable=False, default=True,
                         server_default=sqlalchemy.sql.expression.true())
    extra = sql.Column(sql.JsonBlob())
    endpoints = sqlalchemy.orm.relationship("Endpoint", backref="service")


class Endpoint(sql.ModelBase, sql.DictBase):
    __tablename__ = 'endpoint'
    attributes = ['id', 'interface', 'region_id', 'service_id', 'url',
                  'legacy_endpoint_id', 'enabled']
    id = sql.Column(sql.String(64), primary_key=True)
    legacy_endpoint_id = sql.Column(sql.String(64))
    interface = sql.Column(sql.String(8), nullable=False)
    region_id = sql.Column(sql.String(255),
                           sql.ForeignKey('region.id',
                                          ondelete='RESTRICT'),
                           nullable=True,
                           default=None)
    service_id = sql.Column(sql.String(64),
                            sql.ForeignKey('service.id'),
                            nullable=False)
    url = sql.Column(sql.Text(), nullable=False)
    enabled = sql.Column(sql.Boolean, nullable=False, default=True,
                         server_default=sqlalchemy.sql.expression.true())
    extra = sql.Column(sql.JsonBlob())


class Catalog(catalog.CatalogDriverV8):
    # Regions
    def list_regions(self, hints):
        session = sql.get_session()
        regions = session.query(Region)
        regions = sql.filter_limit_query(Region, regions, hints)
        return [s.to_dict() for s in list(regions)]

    def _get_region(self, session, region_id):
        ref = session.query(Region).get(region_id)
        if not ref:
            raise exception.RegionNotFound(region_id=region_id)
        return ref

    def _delete_child_regions(self, session, region_id, root_region_id):
        """Delete all child regions.

        Recursively delete any region that has the supplied region
        as its parent.
        """
        children = session.query(Region).filter_by(parent_region_id=region_id)
        for child in children:
            if child.id == root_region_id:
                # Hit a circular region hierarchy
                return
            self._delete_child_regions(session, child.id, root_region_id)
            session.delete(child)

    def _check_parent_region(self, session, region_ref):
        """Raise a NotFound if the parent region does not exist.

        If the region_ref has a specified parent_region_id, check that
        the parent exists, otherwise, raise a NotFound.
        """
        parent_region_id = region_ref.get('parent_region_id')
        if parent_region_id is not None:
            # This will raise NotFound if the parent doesn't exist,
            # which is the behavior we want.
            self._get_region(session, parent_region_id)

    def _has_endpoints(self, session, region, root_region):
        if region.endpoints is not None and len(region.endpoints) > 0:
            return True

        q = session.query(Region)
        q = q.filter_by(parent_region_id=region.id)
        for child in q.all():
            if child.id == root_region.id:
                # Hit a circular region hierarchy
                return False
            if self._has_endpoints(session, child, root_region):
                return True
        return False

    def get_region(self, region_id):
        session = sql.get_session()
        return self._get_region(session, region_id).to_dict()

    def delete_region(self, region_id):
        session = sql.get_session()
        with session.begin():
            ref = self._get_region(session, region_id)
            if self._has_endpoints(session, ref, ref):
                raise exception.RegionDeletionError(region_id=region_id)
            self._delete_child_regions(session, region_id, region_id)
            session.delete(ref)

    @sql.handle_conflicts(conflict_type='region')
    def create_region(self, region_ref):
        session = sql.get_session()
        with session.begin():
            self._check_parent_region(session, region_ref)
            region = Region.from_dict(region_ref)
            session.add(region)
        return region.to_dict()

    def update_region(self, region_id, region_ref):
        session = sql.get_session()
        with session.begin():
            self._check_parent_region(session, region_ref)
            ref = self._get_region(session, region_id)
            old_dict = ref.to_dict()
            old_dict.update(region_ref)
            self._ensure_no_circle_in_hierarchical_regions(old_dict)
            new_region = Region.from_dict(old_dict)
            for attr in Region.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_region, attr))
        return ref.to_dict()

    # Services
    @sql.truncated
    def list_services(self, hints):
        session = sql.get_session()
        services = session.query(Service)
        services = sql.filter_limit_query(Service, services, hints)
        return [s.to_dict() for s in list(services)]

    def _get_service(self, session, service_id):
        ref = session.query(Service).get(service_id)
        if not ref:
            raise exception.ServiceNotFound(service_id=service_id)
        return ref

    def get_service(self, service_id):
        session = sql.get_session()
        return self._get_service(session, service_id).to_dict()

    def delete_service(self, service_id):
        session = sql.get_session()
        with session.begin():
            ref = self._get_service(session, service_id)
            session.query(Endpoint).filter_by(service_id=service_id).delete()
            session.delete(ref)

    def create_service(self, service_id, service_ref):
        session = sql.get_session()
        with session.begin():
            service = Service.from_dict(service_ref)
            session.add(service)
        return service.to_dict()

    def update_service(self, service_id, service_ref):
        session = sql.get_session()
        with session.begin():
            ref = self._get_service(session, service_id)
            old_dict = ref.to_dict()
            old_dict.update(service_ref)
            new_service = Service.from_dict(old_dict)
            for attr in Service.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_service, attr))
            ref.extra = new_service.extra
        return ref.to_dict()

    # Endpoints
    def create_endpoint(self, endpoint_id, endpoint_ref):
        session = sql.get_session()
        new_endpoint = Endpoint.from_dict(endpoint_ref)

        with session.begin():
            session.add(new_endpoint)
        return new_endpoint.to_dict()

    def delete_endpoint(self, endpoint_id):
        session = sql.get_session()
        with session.begin():
            ref = self._get_endpoint(session, endpoint_id)
            session.delete(ref)

    def _get_endpoint(self, session, endpoint_id):
        try:
            return session.query(Endpoint).filter_by(id=endpoint_id).one()
        except sql.NotFound:
            raise exception.EndpointNotFound(endpoint_id=endpoint_id)

    def get_endpoint(self, endpoint_id):
        session = sql.get_session()
        return self._get_endpoint(session, endpoint_id).to_dict()

    @sql.truncated
    def list_endpoints(self, hints):
        session = sql.get_session()
        endpoints = session.query(Endpoint)
        endpoints = sql.filter_limit_query(Endpoint, endpoints, hints)
        return [e.to_dict() for e in list(endpoints)]

    def update_endpoint(self, endpoint_id, endpoint_ref):
        session = sql.get_session()

        with session.begin():
            ref = self._get_endpoint(session, endpoint_id)
            old_dict = ref.to_dict()
            old_dict.update(endpoint_ref)
            new_endpoint = Endpoint.from_dict(old_dict)
            for attr in Endpoint.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_endpoint, attr))
            ref.extra = new_endpoint.extra
        return ref.to_dict()

    def get_catalog(self, user_id, tenant_id):
        """Retrieve and format the V2 service catalog.

        :param user_id: The id of the user who has been authenticated for
            creating service catalog.
        :param tenant_id: The id of the project. 'tenant_id' will be None
            in the case this being called to create a catalog to go in a
            domain scoped token. In this case, any endpoint that requires
            a tenant_id as part of their URL will be skipped (as would a whole
            service if, as a consequence, it has no valid endpoints).

        :returns: A nested dict representing the service catalog or an
                  empty dict.

        """
        substitutions = dict(
            itertools.chain(CONF.items(), CONF.eventlet_server.items()))
        substitutions.update({'user_id': user_id})
        silent_keyerror_failures = []
        if tenant_id:
            substitutions.update({'tenant_id': tenant_id})
        else:
            silent_keyerror_failures = ['tenant_id']

        session = sql.get_session()
        endpoints = (session.query(Endpoint).
                     options(sql.joinedload(Endpoint.service)).
                     filter(Endpoint.enabled == true()).all())

        catalog = {}

        for endpoint in endpoints:
            if not endpoint.service['enabled']:
                continue
            try:
                formatted_url = core.format_url(
                    endpoint['url'], substitutions,
                    silent_keyerror_failures=silent_keyerror_failures)
                if formatted_url is not None:
                    url = formatted_url
                else:
                    continue
            except exception.MalformedEndpoint:
                continue  # this failure is already logged in format_url()

            region = endpoint['region_id']
            service_type = endpoint.service['type']
            default_service = {
                'id': endpoint['id'],
                'name': endpoint.service.extra.get('name', ''),
                'publicURL': ''
            }
            catalog.setdefault(region, {})
            catalog[region].setdefault(service_type, default_service)
            interface_url = '%sURL' % endpoint['interface']
            catalog[region][service_type][interface_url] = url

        return catalog

    def get_v3_catalog(self, user_id, tenant_id):
        """Retrieve and format the current V3 service catalog.

        :param user_id: The id of the user who has been authenticated for
            creating service catalog.
        :param tenant_id: The id of the project. 'tenant_id' will be None in
            the case this being called to create a catalog to go in a domain
            scoped token. In this case, any endpoint that requires a
            tenant_id as part of their URL will be skipped.

        :returns: A list representing the service catalog or an empty list

        """
        d = dict(
            itertools.chain(CONF.items(), CONF.eventlet_server.items()))
        d.update({'user_id': user_id})
        silent_keyerror_failures = []
        if tenant_id:
            d.update({'tenant_id': tenant_id})
        else:
            silent_keyerror_failures = ['tenant_id']

        session = sql.get_session()
        services = (session.query(Service).filter(Service.enabled == true()).
                    options(sql.joinedload(Service.endpoints)).
                    all())

        def make_v3_endpoints(endpoints):
            for endpoint in (ep.to_dict() for ep in endpoints if ep.enabled):
                del endpoint['service_id']
                del endpoint['legacy_endpoint_id']
                del endpoint['enabled']
                endpoint['region'] = endpoint['region_id']
                try:
                    formatted_url = core.format_url(
                        endpoint['url'], d,
                        silent_keyerror_failures=silent_keyerror_failures)
                    if formatted_url:
                        endpoint['url'] = formatted_url
                    else:
                        continue
                except exception.MalformedEndpoint:
                    continue  # this failure is already logged in format_url()

                yield endpoint

        # TODO(davechen): If there is service with no endpoints, we should skip
        # the service instead of keeping it in the catalog, see bug #1436704.
        def make_v3_service(svc):
            eps = list(make_v3_endpoints(svc.endpoints))
            service = {'endpoints': eps, 'id': svc.id, 'type': svc.type}
            service['name'] = svc.extra.get('name', '')
            return service

        return [make_v3_service(svc) for svc in services]
