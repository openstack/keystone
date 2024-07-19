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

"""Fake driver to test out-of-tree drivers handling."""

from oslo_config import cfg

from keystone import exception
from keystone.identity.backends import base


class FooDriver(base.IdentityDriverBase):
    """Fake out-of-tree driver.

    It does not make much sense to inherit from BaseClass, but in certain
    places across the code methods are invoked

    """

    @classmethod
    def register_opts(cls, conf):
        grp = cfg.OptGroup("foo")
        opts = [cfg.StrOpt("opt1")]
        conf.register_group(grp)
        conf.register_opts(opts, group=grp)

    def authenticate(self, user_id, password):
        raise exception.NotImplemented()  # pragma: no cover

    def create_user(self, user_id, user):
        raise exception.NotImplemented()  # pragma: no cover

    def list_users(self, hints):
        raise exception.NotImplemented()  # pragma: no cover

    def unset_default_project_id(self, project_id):
        raise exception.NotImplemented()  # pragma: no cover

    def list_users_in_group(self, group_id, hints):
        raise exception.NotImplemented()  # pragma: no cover

    def get_user(self, user_id):
        raise exception.NotImplemented()  # pragma: no cover

    def update_user(self, user_id, user):
        raise exception.NotImplemented()  # pragma: no cover

    def change_password(self, user_id, new_password):
        raise exception.NotImplemented()  # pragma: no cover

    def add_user_to_group(self, user_id, group_id):
        raise exception.NotImplemented()  # pragma: no cover

    def check_user_in_group(self, user_id, group_id):
        raise exception.NotImplemented()  # pragma: no cover

    def remove_user_from_group(self, user_id, group_id):
        raise exception.NotImplemented()  # pragma: no cover

    def delete_user(self, user_id):
        raise exception.NotImplemented()  # pragma: no cover

    def get_user_by_name(self, user_name, domain_id):
        raise exception.NotImplemented()  # pragma: no cover

    def reset_last_active(self):
        raise exception.NotImplemented()  # pragma: no cover

    def create_group(self, group_id, group):
        raise exception.NotImplemented()  # pragma: no cover

    def list_groups(self, hints):
        raise exception.NotImplemented()  # pragma: no cover

    def list_groups_for_user(self, user_id, hints):
        raise exception.NotImplemented()  # pragma: no cover

    def get_group(self, group_id):
        raise exception.NotImplemented()  # pragma: no cover

    def get_group_by_name(self, group_name, domain_id):
        raise exception.NotImplemented()  # pragma: no cover

    def update_group(self, group_id, group):
        raise exception.NotImplemented()  # pragma: no cover

    def delete_group(self, group_id):
        raise exception.NotImplemented()  # pragma: no cover
