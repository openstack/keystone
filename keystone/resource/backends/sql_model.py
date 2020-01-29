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

from sqlalchemy import orm
from sqlalchemy.orm import collections

from keystone.common import resource_options
from keystone.common import sql
from keystone.resource.backends import base
from keystone.resource.backends import resource_options as ro


class Project(sql.ModelBase, sql.ModelDictMixinWithExtras):
    # NOTE(henry-nash): From the manager and above perspective, the domain_id
    # is nullable.  However, to ensure uniqueness in multi-process
    # configurations, it is better to still use the sql uniqueness constraint.
    # Since the support for a nullable component of a uniqueness constraint
    # across different sql databases is mixed, we instead store a special value
    # to represent null, as defined in NULL_DOMAIN_ID above.

    def to_dict(self, include_extra_dict=False):
        d = super(Project, self).to_dict(
            include_extra_dict=include_extra_dict)
        if d['domain_id'] == base.NULL_DOMAIN_ID:
            d['domain_id'] = None
        # NOTE(notmorgan): Eventually it may make sense to drop the empty
        # option dict creation to the superclass (if enough models use it)
        d['options'] = resource_options.ref_mapper_to_dict_options(self)
        return d

    @classmethod
    def from_dict(cls, project_dict):
        new_dict = project_dict.copy()
        # TODO(morgan): move this functionality to a common location
        resource_options = {}
        options = new_dict.pop('options', {})
        for opt in cls.resource_options_registry.options:
            if opt.option_name in options:
                opt_value = options[opt.option_name]
                # NOTE(notmorgan): None is always a valid type
                if opt_value is not None:
                    opt.validator(opt_value)
                resource_options[opt.option_id] = opt_value
        project_obj = super(Project, cls).from_dict(new_dict)
        setattr(project_obj, '_resource_options', resource_options)
        return project_obj

    __tablename__ = 'project'
    attributes = ['id', 'name', 'domain_id', 'description', 'enabled',
                  'parent_id', 'is_domain', 'tags']
    resource_options_registry = ro.PROJECT_OPTIONS_REGISTRY
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    domain_id = sql.Column(sql.String(64), sql.ForeignKey('project.id'),
                           nullable=False)
    description = sql.Column(sql.Text())
    enabled = sql.Column(sql.Boolean)
    extra = sql.Column(sql.JsonBlob())
    parent_id = sql.Column(sql.String(64), sql.ForeignKey('project.id'))
    is_domain = sql.Column(sql.Boolean, default=False, nullable=False,
                           server_default='0')
    _tags = orm.relationship(
        'ProjectTag',
        single_parent=True,
        lazy='subquery',
        cascade='all,delete-orphan',
        backref='project',
        primaryjoin='and_(ProjectTag.project_id==Project.id)'
    )
    _resource_option_mapper = orm.relationship(
        'ProjectOption',
        single_parent=True,
        cascade='all,delete,delete-orphan',
        lazy='subquery',
        backref='project',
        collection_class=collections.attribute_mapped_collection('option_id')
    )

    # Unique constraint across two columns to create the separation
    # rather than just only 'name' being unique
    __table_args__ = (sql.UniqueConstraint('domain_id', 'name'),)

    @property
    def tags(self):
        if self._tags:
            return [tag.name for tag in self._tags]
        return []

    @tags.setter
    def tags(self, values):
        new_tags = []
        for tag in values:
            tag_ref = ProjectTag()
            tag_ref.project_id = self.id
            tag_ref.name = str(tag)
            new_tags.append(tag_ref)
        self._tags = new_tags


class ProjectTag(sql.ModelBase, sql.ModelDictMixin):

    def to_dict(self):
        d = super(ProjectTag, self).to_dict()
        return d

    __tablename__ = 'project_tag'
    attributes = ['project_id', 'name']
    project_id = sql.Column(
        sql.String(64), sql.ForeignKey('project.id', ondelete='CASCADE'),
        nullable=False, primary_key=True)
    name = sql.Column(sql.Unicode(255), nullable=False, primary_key=True)
    __table_args__ = (sql.UniqueConstraint('project_id', 'name'),)


class ProjectOption(sql.ModelBase):
    __tablename__ = 'project_option'
    project_id = sql.Column(sql.String(64),
                            sql.ForeignKey('project.id', ondelete='CASCADE'),
                            nullable=False, primary_key=True)
    option_id = sql.Column(sql.String(4), nullable=False,
                           primary_key=True)
    option_value = sql.Column(sql.JsonBlob, nullable=True)

    def __init__(self, option_id, option_value):
        self.option_id = option_id
        self.option_value = option_value
