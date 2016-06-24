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

from oslo_config import cfg

from keystone.conf import constants
from keystone.conf import utils


assertion_expiration_time = cfg.IntOpt(
    'assertion_expiration_time',
    default=3600,
    help=utils.fmt("""
Default TTL, in seconds, for any generated SAML assertion created by Keystone.
"""))

xmlsec1_binary = cfg.StrOpt(
    'xmlsec1_binary',
    default='xmlsec1',
    help=utils.fmt("""
Binary to be called for XML signing. Install the appropriate package, specify
absolute path or adjust your PATH environment variable if the binary cannot be
found.
"""))

certfile = cfg.StrOpt(
    'certfile',
    default=constants._CERTFILE,
    help=utils.fmt("""
Path of the certfile for SAML signing. For non-production environments, you may
be interested in using `keystone-manage pki_setup` to generate self-signed
certificates. Note, the path cannot contain a comma.
"""))

keyfile = cfg.StrOpt(
    'keyfile',
    default=constants._KEYFILE,
    help=utils.fmt("""
Path of the keyfile for SAML signing. Note, the path cannot contain a comma.
"""))

idp_entity_id = cfg.StrOpt(
    'idp_entity_id',
    help=utils.fmt("""
Entity ID value for unique Identity Provider identification. Usually FQDN is
set with a suffix. A value is required to generate IDP Metadata. For example:
https://keystone.example.com/v3/OS-FEDERATION/saml2/idp
"""))

idp_sso_endpoint = cfg.StrOpt(
    'idp_sso_endpoint',
    help=utils.fmt("""
Identity Provider Single-Sign-On service value, required in the Identity
Provider's metadata. A value is required to generate IDP Metadata. For example:
https://keystone.example.com/v3/OS-FEDERATION/saml2/sso
"""))

idp_lang = cfg.StrOpt(
    'idp_lang', default='en',
    help=utils.fmt("""
Language used by the organization.
"""))

idp_organization_name = cfg.StrOpt(
    'idp_organization_name',
    help=utils.fmt("""
Organization name the installation belongs to.
"""))

idp_organization_display_name = cfg.StrOpt(
    'idp_organization_display_name',
    help=utils.fmt("""
Organization name to be displayed.
"""))

idp_organization_url = cfg.StrOpt(
    'idp_organization_url',
    help=utils.fmt("""
URL of the organization.
"""))

idp_contact_company = cfg.StrOpt(
    'idp_contact_company',
    help=utils.fmt("""
Company of contact person.
"""))

idp_contact_name = cfg.StrOpt(
    'idp_contact_name',
    help=utils.fmt("""
Given name of contact person
"""))

idp_contact_surname = cfg.StrOpt(
    'idp_contact_surname',
    help=utils.fmt("""
Surname of contact person.
"""))

idp_contact_email = cfg.StrOpt(
    'idp_contact_email',
    help=utils.fmt("""
Email address of contact person.
"""))

idp_contact_telephone = cfg.StrOpt(
    'idp_contact_telephone',
    help=utils.fmt("""
Telephone number of contact person.
"""))

idp_contact_type = cfg.StrOpt(
    'idp_contact_type',
    default='other',
    choices=['technical', 'support', 'administrative', 'billing', 'other'],
    help=utils.fmt("""
The contact type describing the main point of contact for the identity
provider.
"""))

idp_metadata_path = cfg.StrOpt(
    'idp_metadata_path',
    default='/etc/keystone/saml2_idp_metadata.xml',
    help=utils.fmt("""
Path to the Identity Provider Metadata file. This file should be generated with
the keystone-manage saml_idp_metadata command.
"""))

relay_state_prefix = cfg.StrOpt(
    'relay_state_prefix',
    default='ss:mem:',
    help=utils.fmt("""
The prefix to use for the RelayState SAML attribute, used when generating ECP
wrapped assertions.
"""))


GROUP_NAME = __name__.split('.')[-1]
ALL_OPTS = [
    assertion_expiration_time,
    xmlsec1_binary,
    certfile,
    keyfile,
    idp_entity_id,
    idp_sso_endpoint,
    idp_lang,
    idp_organization_name,
    idp_organization_display_name,
    idp_organization_url,
    idp_contact_company,
    idp_contact_name,
    idp_contact_surname,
    idp_contact_email,
    idp_contact_telephone,
    idp_contact_type,
    idp_metadata_path,
    relay_state_prefix,
]


def register_opts(conf):
    conf.register_opts(ALL_OPTS, group=GROUP_NAME)


def list_opts():
    return {GROUP_NAME: ALL_OPTS}
