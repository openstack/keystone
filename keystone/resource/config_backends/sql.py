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

from keystone.common import sql
from keystone import exception
from keystone.i18n import _
from keystone.resource.config_backends import base


class WhiteListedConfig(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'whitelisted_config'
    domain_id = sql.Column(sql.String(64), primary_key=True)
    group = sql.Column(sql.String(255), primary_key=True)
    option = sql.Column(sql.String(255), primary_key=True)
    value = sql.Column(sql.JsonBlob(), nullable=False)

    def to_dict(self):
        d = super(WhiteListedConfig, self).to_dict()
        d.pop('domain_id')
        return d


class SensitiveConfig(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'sensitive_config'
    domain_id = sql.Column(sql.String(64), primary_key=True)
    group = sql.Column(sql.String(255), primary_key=True)
    option = sql.Column(sql.String(255), primary_key=True)
    value = sql.Column(sql.JsonBlob(), nullable=False)

    def to_dict(self):
        d = super(SensitiveConfig, self).to_dict()
        d.pop('domain_id')
        return d


class ConfigRegister(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'config_register'
    type = sql.Column(sql.String(64), primary_key=True)
    domain_id = sql.Column(sql.String(64), nullable=False)


class DomainConfig(base.DomainConfigDriverBase):

    def choose_table(self, sensitive):
        if sensitive:
            return SensitiveConfig
        else:
            return WhiteListedConfig

    def _create_config_option(
            self, session, domain_id, group, option, sensitive, value):
        config_table = self.choose_table(sensitive)
        ref = config_table(domain_id=domain_id, group=group, option=option,
                           value=value)
        session.add(ref)

    def create_config_options(self, domain_id, option_list):
        with sql.session_for_write() as session:
            for config_table in [WhiteListedConfig, SensitiveConfig]:
                query = session.query(config_table)
                query = query.filter_by(domain_id=domain_id)
                query.delete(False)
            for option in option_list:
                self._create_config_option(
                    session, domain_id, option['group'],
                    option['option'], option['sensitive'], option['value'])

    def _get_config_option(self, session, domain_id, group, option, sensitive):
        try:
            config_table = self.choose_table(sensitive)
            ref = (session.query(config_table).
                   filter_by(domain_id=domain_id, group=group,
                             option=option).one())
        except sql.NotFound:
            msg = _('option %(option)s in group %(group)s') % {
                'group': group, 'option': option}
            raise exception.DomainConfigNotFound(
                domain_id=domain_id, group_or_option=msg)
        return ref

    def get_config_option(self, domain_id, group, option, sensitive=False):
        with sql.session_for_read() as session:
            ref = self._get_config_option(session, domain_id, group, option,
                                          sensitive)
            return ref.to_dict()

    def list_config_options(self, domain_id, group=None, option=None,
                            sensitive=False):
        with sql.session_for_read() as session:
            config_table = self.choose_table(sensitive)
            query = session.query(config_table)
            query = query.filter_by(domain_id=domain_id)
            if group:
                query = query.filter_by(group=group)
                if option:
                    query = query.filter_by(option=option)
            return [ref.to_dict() for ref in query.all()]

    def update_config_options(self, domain_id, option_list):
        with sql.session_for_write() as session:
            for option in option_list:
                self._delete_config_options(
                    session, domain_id, option['group'], option['option'])
                self._create_config_option(
                    session, domain_id, option['group'], option['option'],
                    option['sensitive'], option['value'])

    def _delete_config_options(self, session, domain_id, group, option):
        for config_table in [WhiteListedConfig, SensitiveConfig]:
            query = session.query(config_table)
            query = query.filter_by(domain_id=domain_id)
            if group:
                query = query.filter_by(group=group)
                if option:
                    query = query.filter_by(option=option)
            query.delete(False)

    def delete_config_options(self, domain_id, group=None, option=None):
        with sql.session_for_write() as session:
            self._delete_config_options(session, domain_id, group, option)

    def obtain_registration(self, domain_id, type):
        try:
            with sql.session_for_write() as session:
                ref = ConfigRegister(type=type, domain_id=domain_id)
                session.add(ref)
            return True
        except sql.DBDuplicateEntry:  # nosec
            # Continue on and return False to indicate failure.
            pass
        return False

    def read_registration(self, type):
        with sql.session_for_read() as session:
            ref = session.query(ConfigRegister).get(type)
            if not ref:
                raise exception.ConfigRegistrationNotFound()
            return ref.domain_id

    def release_registration(self, domain_id, type=None):
        """Silently delete anything registered for the domain specified."""
        with sql.session_for_write() as session:
            query = session.query(ConfigRegister)
            if type:
                query = query.filter_by(type=type)
            query = query.filter_by(domain_id=domain_id)
            query.delete(False)
