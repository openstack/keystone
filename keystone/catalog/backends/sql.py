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

import sqlalchemy
from sqlalchemy.sql import true

from keystone.catalog.backends import base
from keystone.common import driver_hints
from keystone.common import sql
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF


class Region(sql.ModelBase, sql.ModelDictMixinWithExtras):
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
    extra = sql.Column(sql.JsonBlob())
    endpoints = sqlalchemy.orm.relationship("Endpoint", backref="region")


class Service(sql.ModelBase, sql.ModelDictMixinWithExtras):
    __tablename__ = 'service'
    attributes = ['id', 'type', 'enabled']
    id = sql.Column(sql.String(64), primary_key=True)
    type = sql.Column(sql.String(255))
    enabled = sql.Column(sql.Boolean, nullable=False, default=True,
                         server_default=sqlalchemy.sql.expression.true())
    extra = sql.Column(sql.JsonBlob())
    endpoints = sqlalchemy.orm.relationship("Endpoint", backref="service")


class Endpoint(sql.ModelBase, sql.ModelDictMixinWithExtras):
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

    @classmethod
    def from_dict(cls, endpoint_dict):
        """Override from_dict to set enabled if missing."""
        new_dict = endpoint_dict.copy()
        if new_dict.get('enabled') is None:
            new_dict['enabled'] = True
        return super(Endpoint, cls).from_dict(new_dict)


class Catalog(base.CatalogDriverBase):
    # Regions
    def list_regions(self, hints):
        with sql.session_for_read() as session:
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
        with sql.session_for_read() as session:
            return self._get_region(session, region_id).to_dict()

    def delete_region(self, region_id):
        with sql.session_for_write() as session:
            ref = self._get_region(session, region_id)
            if self._has_endpoints(session, ref, ref):
                raise exception.RegionDeletionError(region_id=region_id)
            self._delete_child_regions(session, region_id, region_id)
            session.delete(ref)

    @sql.handle_conflicts(conflict_type='region')
    def create_region(self, region_ref):
        with sql.session_for_write() as session:
            self._check_parent_region(session, region_ref)
            region = Region.from_dict(region_ref)
            session.add(region)
            return region.to_dict()

    def update_region(self, region_id, region_ref):
        with sql.session_for_write() as session:
            self._check_parent_region(session, region_ref)
            ref = self._get_region(session, region_id)
            old_dict = ref.to_dict()
            old_dict.update(region_ref)
            self._ensure_no_circle_in_hierarchical_regions(old_dict)
            new_region = Region.from_dict(old_dict)
            for attr in Region.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_region, attr))
            ref.extra = new_region.extra
            return ref.to_dict()

    # Services
    @driver_hints.truncated
    def list_services(self, hints):
        with sql.session_for_read() as session:
            services = session.query(Service)
            services = sql.filter_limit_query(Service, services, hints)
            return [s.to_dict() for s in list(services)]

    def _get_service(self, session, service_id):
        ref = session.query(Service).get(service_id)
        if not ref:
            raise exception.ServiceNotFound(service_id=service_id)
        return ref

    def get_service(self, service_id):
        with sql.session_for_read() as session:
            return self._get_service(session, service_id).to_dict()

    def delete_service(self, service_id):
        with sql.session_for_write() as session:
            ref = self._get_service(session, service_id)
            session.query(Endpoint).filter_by(service_id=service_id).delete()
            session.delete(ref)

    def create_service(self, service_id, service_ref):
        with sql.session_for_write() as session:
            service = Service.from_dict(service_ref)
            session.add(service)
            return service.to_dict()

    def update_service(self, service_id, service_ref):
        with sql.session_for_write() as session:
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
    def create_endpoint(self, endpoint_id, endpoint):
        with sql.session_for_write() as session:
            endpoint_ref = Endpoint.from_dict(endpoint)
            session.add(endpoint_ref)
            return endpoint_ref.to_dict()

    def delete_endpoint(self, endpoint_id):
        with sql.session_for_write() as session:
            ref = self._get_endpoint(session, endpoint_id)
            session.delete(ref)

    def _get_endpoint(self, session, endpoint_id):
        try:
            return session.query(Endpoint).filter_by(id=endpoint_id).one()
        except sql.NotFound:
            raise exception.EndpointNotFound(endpoint_id=endpoint_id)

    def get_endpoint(self, endpoint_id):
        with sql.session_for_read() as session:
            return self._get_endpoint(session, endpoint_id).to_dict()

    @driver_hints.truncated
    def list_endpoints(self, hints):
        with sql.session_for_read() as session:
            endpoints = session.query(Endpoint)
            endpoints = sql.filter_limit_query(Endpoint, endpoints, hints)
            return [e.to_dict() for e in list(endpoints)]

    def update_endpoint(self, endpoint_id, endpoint_ref):
        with sql.session_for_write() as session:
            ref = self._get_endpoint(session, endpoint_id)
            old_dict = ref.to_dict()
            old_dict.update(endpoint_ref)
            new_endpoint = Endpoint.from_dict(old_dict)
            for attr in Endpoint.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_endpoint, attr))
            ref.extra = new_endpoint.extra
            return ref.to_dict()

    def get_catalog(self, user_id, project_id):
        """Retrieve and format the V2 service catalog.

        :param user_id: The id of the user who has been authenticated for
            creating service catalog.
        :param project_id: The id of the project. 'project_id' will be None
            in the case this being called to create a catalog to go in a
            domain scoped token. In this case, any endpoint that requires
            a project_id as part of their URL will be skipped (as would a whole
            service if, as a consequence, it has no valid endpoints).

        :returns: A nested dict representing the service catalog or an
                  empty dict.

        """
        substitutions = dict(
            itertools.chain(CONF.items(), CONF.eventlet_server.items()))
        substitutions.update({'user_id': user_id})
        silent_keyerror_failures = []
        if project_id:
            substitutions.update({
                'tenant_id': project_id,
                'project_id': project_id
            })
        else:
            silent_keyerror_failures = ['tenant_id', 'project_id']

        with sql.session_for_read() as session:
            endpoints = (session.query(Endpoint).
                         options(sql.joinedload(Endpoint.service)).
                         filter(Endpoint.enabled == true()).all())

            catalog = {}

            for endpoint in endpoints:
                if not endpoint.service['enabled']:
                    continue
                try:
                    formatted_url = utils.format_url(
                        endpoint['url'], substitutions,
                        silent_keyerror_failures=silent_keyerror_failures)
                    if formatted_url is not None:
                        url = formatted_url
                    else:
                        continue
                except exception.MalformedEndpoint:  # nosec(tkelsey)
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

    def get_v3_catalog(self, user_id, project_id):
        """Retrieve and format the current V3 service catalog.

        :param user_id: The id of the user who has been authenticated for
            creating service catalog.
        :param project_id: The id of the project. 'project_id' will be None in
            the case this being called to create a catalog to go in a domain
            scoped token. In this case, any endpoint that requires a
            project_id as part of their URL will be skipped.

        :returns: A list representing the service catalog or an empty list

        """
        d = dict(
            itertools.chain(CONF.items(), CONF.eventlet_server.items()))
        d.update({'user_id': user_id})
        silent_keyerror_failures = []
        if project_id:
            d.update({
                'tenant_id': project_id,
                'project_id': project_id,
            })
        else:
            silent_keyerror_failures = ['tenant_id', 'project_id']

        with sql.session_for_read() as session:
            services = (session.query(Service).filter(
                Service.enabled == true()).options(
                    sql.joinedload(Service.endpoints)).all())

            def make_v3_endpoints(endpoints):
                for endpoint in (ep.to_dict()
                                 for ep in endpoints if ep.enabled):
                    del endpoint['service_id']
                    del endpoint['legacy_endpoint_id']
                    del endpoint['enabled']
                    endpoint['region'] = endpoint['region_id']
                    try:
                        formatted_url = utils.format_url(
                            endpoint['url'], d,
                            silent_keyerror_failures=silent_keyerror_failures)
                        if formatted_url:
                            endpoint['url'] = formatted_url
                        else:
                            continue
                    except exception.MalformedEndpoint:  # nosec(tkelsey)
                        # this failure is already logged in format_url()
                        continue

                    yield endpoint

            # TODO(davechen): If there is service with no endpoints, we should
            # skip the service instead of keeping it in the catalog,
            # see bug #1436704.
            def make_v3_service(svc):
                eps = list(make_v3_endpoints(svc.endpoints))
                service = {'endpoints': eps, 'id': svc.id, 'type': svc.type}
                service['name'] = svc.extra.get('name', '')
                return service

            # Build the unfiltered catalog, this is the catalog that is
            # returned if endpoint filtering is not performed and the
            # option of `return_all_endpoints_if_no_filter` is set to true.
            catalog_ref = [make_v3_service(svc) for svc in services]

            # Filter the `catalog_ref` above by any project-endpoint
            # association configured by endpoint filter.
            filtered_endpoints = {}
            if project_id:
                filtered_endpoints = (
                    self.catalog_api.list_endpoints_for_project(project_id))
            # endpoint filter is enabled, only return the filtered endpoints.
            if filtered_endpoints:
                filtered_ids = list(filtered_endpoints.keys())
                # This is actually working on the copy of `catalog_ref` since
                # the index will be shifted if remove/add any entry for the
                # original one.
                for service in catalog_ref[:]:
                    endpoints = service['endpoints']
                    for endpoint in endpoints[:]:
                        endpoint_id = endpoint['id']
                        # remove the endpoint that is not associated with
                        # the project.
                        if endpoint_id not in filtered_ids:
                            service['endpoints'].remove(endpoint)
                            continue
                        # remove the disabled endpoint from the list.
                        if not filtered_endpoints[endpoint_id]['enabled']:
                            service['endpoints'].remove(endpoint)
                    # NOTE(davechen): The service will not be included in the
                    # catalog if the service doesn't have any endpoint when
                    # endpoint filter is enabled, this is inconsistent with
                    # full catalog that is returned when endpoint filter is
                    # disabled.
                    if not service.get('endpoints'):
                        catalog_ref.remove(service)
            # When it arrives here it means it's domain scoped token (
            # `project_id` is not set) or it's a project scoped token
            # but the endpoint filtering is not performed.
            # Both of them tell us the endpoint filtering is not enabled, so
            # check the option of `return_all_endpoints_if_no_filter`, it will
            # judge whether a full unfiltered catalog or a empty service
            # catalog will be returned.
            elif not CONF.endpoint_filter.return_all_endpoints_if_no_filter:
                return []
            return catalog_ref

    @sql.handle_conflicts(conflict_type='project_endpoint')
    def add_endpoint_to_project(self, endpoint_id, project_id):
        with sql.session_for_write() as session:
            endpoint_filter_ref = ProjectEndpoint(endpoint_id=endpoint_id,
                                                  project_id=project_id)
            session.add(endpoint_filter_ref)

    def _get_project_endpoint_ref(self, session, endpoint_id, project_id):
        endpoint_filter_ref = session.query(ProjectEndpoint).get(
            (endpoint_id, project_id))
        if endpoint_filter_ref is None:
            msg = _('Endpoint %(endpoint_id)s not found in project '
                    '%(project_id)s') % {'endpoint_id': endpoint_id,
                                         'project_id': project_id}
            raise exception.NotFound(msg)
        return endpoint_filter_ref

    def check_endpoint_in_project(self, endpoint_id, project_id):
        with sql.session_for_read() as session:
            self._get_project_endpoint_ref(session, endpoint_id, project_id)

    def remove_endpoint_from_project(self, endpoint_id, project_id):
        with sql.session_for_write() as session:
            endpoint_filter_ref = self._get_project_endpoint_ref(
                session, endpoint_id, project_id)
            session.delete(endpoint_filter_ref)

    def list_endpoints_for_project(self, project_id):
        with sql.session_for_read() as session:
            query = session.query(ProjectEndpoint)
            query = query.filter_by(project_id=project_id)
            endpoint_filter_refs = query.all()
            return [ref.to_dict() for ref in endpoint_filter_refs]

    def list_projects_for_endpoint(self, endpoint_id):
        with sql.session_for_read() as session:
            query = session.query(ProjectEndpoint)
            query = query.filter_by(endpoint_id=endpoint_id)
            endpoint_filter_refs = query.all()
            return [ref.to_dict() for ref in endpoint_filter_refs]

    def delete_association_by_endpoint(self, endpoint_id):
        with sql.session_for_write() as session:
            query = session.query(ProjectEndpoint)
            query = query.filter_by(endpoint_id=endpoint_id)
            query.delete(synchronize_session=False)

    def delete_association_by_project(self, project_id):
        with sql.session_for_write() as session:
            query = session.query(ProjectEndpoint)
            query = query.filter_by(project_id=project_id)
            query.delete(synchronize_session=False)

    def create_endpoint_group(self, endpoint_group_id, endpoint_group):
        with sql.session_for_write() as session:
            endpoint_group_ref = EndpointGroup.from_dict(endpoint_group)
            session.add(endpoint_group_ref)
            return endpoint_group_ref.to_dict()

    def _get_endpoint_group(self, session, endpoint_group_id):
        endpoint_group_ref = session.query(EndpointGroup).get(
            endpoint_group_id)
        if endpoint_group_ref is None:
            raise exception.EndpointGroupNotFound(
                endpoint_group_id=endpoint_group_id)
        return endpoint_group_ref

    def get_endpoint_group(self, endpoint_group_id):
        with sql.session_for_read() as session:
            endpoint_group_ref = self._get_endpoint_group(session,
                                                          endpoint_group_id)
            return endpoint_group_ref.to_dict()

    def update_endpoint_group(self, endpoint_group_id, endpoint_group):
        with sql.session_for_write() as session:
            endpoint_group_ref = self._get_endpoint_group(session,
                                                          endpoint_group_id)
            old_endpoint_group = endpoint_group_ref.to_dict()
            old_endpoint_group.update(endpoint_group)
            new_endpoint_group = EndpointGroup.from_dict(old_endpoint_group)
            for attr in EndpointGroup.mutable_attributes:
                setattr(endpoint_group_ref, attr,
                        getattr(new_endpoint_group, attr))
            return endpoint_group_ref.to_dict()

    def delete_endpoint_group(self, endpoint_group_id):
        with sql.session_for_write() as session:
            endpoint_group_ref = self._get_endpoint_group(session,
                                                          endpoint_group_id)
            self._delete_endpoint_group_association_by_endpoint_group(
                session, endpoint_group_id)
            session.delete(endpoint_group_ref)

    def get_endpoint_group_in_project(self, endpoint_group_id, project_id):
        with sql.session_for_read() as session:
            ref = self._get_endpoint_group_in_project(session,
                                                      endpoint_group_id,
                                                      project_id)
            return ref.to_dict()

    @sql.handle_conflicts(conflict_type='project_endpoint_group')
    def add_endpoint_group_to_project(self, endpoint_group_id, project_id):
        with sql.session_for_write() as session:
            # Create a new Project Endpoint group entity
            endpoint_group_project_ref = ProjectEndpointGroupMembership(
                endpoint_group_id=endpoint_group_id, project_id=project_id)
            session.add(endpoint_group_project_ref)

    def _get_endpoint_group_in_project(self, session,
                                       endpoint_group_id, project_id):
        endpoint_group_project_ref = session.query(
            ProjectEndpointGroupMembership).get((endpoint_group_id,
                                                 project_id))
        if endpoint_group_project_ref is None:
            msg = _('Endpoint Group Project Association not found')
            raise exception.NotFound(msg)
        else:
            return endpoint_group_project_ref

    def list_endpoint_groups(self, hints):
        with sql.session_for_read() as session:
            query = session.query(EndpointGroup)
            endpoint_group_refs = sql.filter_limit_query(
                EndpointGroup, query, hints)
            return [e.to_dict() for e in endpoint_group_refs]

    def list_endpoint_groups_for_project(self, project_id):
        with sql.session_for_read() as session:
            query = session.query(ProjectEndpointGroupMembership)
            query = query.filter_by(project_id=project_id)
            endpoint_group_refs = query.all()
            return [ref.to_dict() for ref in endpoint_group_refs]

    def remove_endpoint_group_from_project(self, endpoint_group_id,
                                           project_id):
        with sql.session_for_write() as session:
            endpoint_group_project_ref = self._get_endpoint_group_in_project(
                session, endpoint_group_id, project_id)
            session.delete(endpoint_group_project_ref)

    def list_projects_associated_with_endpoint_group(self, endpoint_group_id):
        with sql.session_for_read() as session:
            query = session.query(ProjectEndpointGroupMembership)
            query = query.filter_by(endpoint_group_id=endpoint_group_id)
            endpoint_group_refs = query.all()
            return [ref.to_dict() for ref in endpoint_group_refs]

    def _delete_endpoint_group_association_by_endpoint_group(
            self, session, endpoint_group_id):
        query = session.query(ProjectEndpointGroupMembership)
        query = query.filter_by(endpoint_group_id=endpoint_group_id)
        query.delete()

    def delete_endpoint_group_association_by_project(self, project_id):
        with sql.session_for_write() as session:
            query = session.query(ProjectEndpointGroupMembership)
            query = query.filter_by(project_id=project_id)
            query.delete()


class ProjectEndpoint(sql.ModelBase, sql.ModelDictMixin):
    """project-endpoint relationship table."""

    __tablename__ = 'project_endpoint'
    attributes = ['endpoint_id', 'project_id']
    endpoint_id = sql.Column(sql.String(64),
                             primary_key=True,
                             nullable=False)
    project_id = sql.Column(sql.String(64),
                            primary_key=True,
                            nullable=False)


class EndpointGroup(sql.ModelBase, sql.ModelDictMixin):
    """Endpoint Groups table."""

    __tablename__ = 'endpoint_group'
    attributes = ['id', 'name', 'description', 'filters']
    mutable_attributes = frozenset(['name', 'description', 'filters'])
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(255), nullable=False)
    description = sql.Column(sql.Text, nullable=True)
    filters = sql.Column(sql.JsonBlob(), nullable=False)


class ProjectEndpointGroupMembership(sql.ModelBase, sql.ModelDictMixin):
    """Project to Endpoint group relationship table."""

    __tablename__ = 'project_endpoint_group'
    attributes = ['endpoint_group_id', 'project_id']
    endpoint_group_id = sql.Column(sql.String(64),
                                   sql.ForeignKey('endpoint_group.id'),
                                   nullable=False)
    project_id = sql.Column(sql.String(64), nullable=False)
    __table_args__ = (sql.PrimaryKeyConstraint('endpoint_group_id',
                                               'project_id'),)
