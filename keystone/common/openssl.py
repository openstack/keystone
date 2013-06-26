# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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
#

import os
import stat

from keystone.common import environment
from keystone.common import logging
from keystone import config


LOG = logging.getLogger(__name__)
CONF = config.CONF
DIR_PERMS = (stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
             stat.S_IRGRP | stat.S_IXGRP |
             stat.S_IROTH | stat.S_IXOTH)
CERT_PERMS = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
PRIV_PERMS = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR


def file_exists(file_path):
    return os.path.exists(file_path)


class BaseCertificateConfigure(object):
    """Create a certificate signing environment.

    This is based on a config section and reasonable OpenSSL defaults.

    """

    def __init__(self, conf_obj, keystone_user, keystone_group, **kwargs):
        self.conf_dir = os.path.dirname(conf_obj.ca_certs)
        self.use_keystone_user = keystone_user
        self.use_keystone_group = keystone_group
        self.ssl_config_file_name = os.path.join(self.conf_dir, "openssl.conf")
        self.request_file_name = os.path.join(self.conf_dir, "req.pem")
        self.ssl_dictionary = {'conf_dir': self.conf_dir,
                               'ca_cert': conf_obj.ca_certs,
                               'ssl_config': self.ssl_config_file_name,
                               'ca_private_key': conf_obj.ca_key,
                               'request_file': self.request_file_name,
                               'signing_key': conf_obj.keyfile,
                               'signing_cert': conf_obj.certfile,
                               'key_size': int(conf_obj.key_size),
                               'valid_days': int(conf_obj.valid_days),
                               'cert_subject': conf_obj.cert_subject,
                               'ca_password': conf_obj.ca_password}
        self.ssl_dictionary.update(kwargs)

    def _make_dirs(self, file_name):
        dir = os.path.dirname(file_name)
        if not file_exists(dir):
            os.makedirs(dir, DIR_PERMS)
        if os.geteuid() == 0 and self.use_keystone_group:
            os.chown(dir, -1, self.use_keystone_group)

    def _set_permissions(self, file_name, perms):
        os.chmod(file_name, perms)
        if os.geteuid() == 0:
            os.chown(file_name, self.use_keystone_user or -1,
                     self.use_keystone_group or -1)

    def exec_command(self, command):
        to_exec = command % self.ssl_dictionary
        LOG.info(to_exec)
        environment.subprocess.check_call(to_exec.rsplit(' '))

    def build_ssl_config_file(self):
        if not file_exists(self.ssl_config_file_name):
            self._make_dirs(self.ssl_config_file_name)
            ssl_config_file = open(self.ssl_config_file_name, 'w')
            ssl_config_file.write(self.sslconfig % self.ssl_dictionary)
            ssl_config_file.close()
        self._set_permissions(self.ssl_config_file_name, CERT_PERMS)

        index_file_name = os.path.join(self.conf_dir, 'index.txt')
        if not file_exists(index_file_name):
            index_file = open(index_file_name, 'w')
            index_file.write('')
            index_file.close()
        self._set_permissions(self.ssl_config_file_name, PRIV_PERMS)

        serial_file_name = os.path.join(self.conf_dir, 'serial')
        if not file_exists(serial_file_name):
            index_file = open(serial_file_name, 'w')
            index_file.write('01')
            index_file.close()
        self._set_permissions(self.ssl_config_file_name, PRIV_PERMS)

    def build_ca_cert(self):
        ca_key_file = self.ssl_dictionary['ca_private_key']
        ca_cert = self.ssl_dictionary['ca_cert']

        if not file_exists(ca_key_file):
            self._make_dirs(ca_key_file)
            self.exec_command('openssl genrsa -out %(ca_private_key)s '
                              '%(key_size)d')
            self._set_permissions(self.ssl_dictionary['ca_private_key'],
                                  stat.S_IRUSR)

        if not file_exists(ca_cert):
            self._make_dirs(ca_cert)
            self.exec_command('openssl req -new -x509 -extensions v3_ca '
                              '-passin pass:%(ca_password)s '
                              '-key %(ca_private_key)s -out %(ca_cert)s '
                              '-days %(valid_days)d '
                              '-config %(ssl_config)s '
                              '-subj %(cert_subject)s')
            self._set_permissions(ca_cert, CERT_PERMS)

    def build_private_key(self):
        signing_keyfile = self.ssl_dictionary['signing_key']

        if not file_exists(signing_keyfile):
            self._make_dirs(signing_keyfile)

            self.exec_command('openssl genrsa -out %(signing_key)s '
                              '%(key_size)d ')
        self._set_permissions(os.path.dirname(signing_keyfile), PRIV_PERMS)
        self._set_permissions(signing_keyfile, stat.S_IRUSR)

    def build_signing_cert(self):
        signing_cert = self.ssl_dictionary['signing_cert']

        if not file_exists(signing_cert):
            self._make_dirs(signing_cert)

            self.exec_command('openssl req -key %(signing_key)s -new -nodes '
                              '-out %(request_file)s -config %(ssl_config)s '
                              '-subj %(cert_subject)s')

            self.exec_command('openssl ca -batch -out %(signing_cert)s '
                              '-config %(ssl_config)s -days %(valid_days)dd '
                              '-cert %(ca_cert)s -keyfile %(ca_private_key)s '
                              '-infiles %(request_file)s')

    def run(self):
        self.build_ssl_config_file()
        self.build_ca_cert()
        self.build_private_key()
        self.build_signing_cert()


class ConfigurePKI(BaseCertificateConfigure):
    """Generate files for PKI signing using OpenSSL.

    Signed tokens require a private key and signing certificate which itself
    must be signed by a CA.  This class generates them with workable defaults
    if each of the files are not present

    """

    def __init__(self, keystone_user, keystone_group):
        super(ConfigurePKI, self).__init__(CONF.signing,
                                           keystone_user, keystone_group)


class ConfigureSSL(BaseCertificateConfigure):
    """Generate files for HTTPS using OpenSSL.

    Creates a public/private key and certificates. If a CA is not given
    one will be generated using provided arguments.
    """

    def __init__(self, keystone_user, keystone_group):
        super(ConfigureSSL, self).__init__(CONF.ssl,
                                           keystone_user, keystone_group)


BaseCertificateConfigure.sslconfig = """
# OpenSSL configuration file.
#

# Establish working directory.

dir            = %(conf_dir)s

[ ca ]
default_ca        = CA_default

[ CA_default ]
new_certs_dir     = $dir
serial            = $dir/serial
database          = $dir/index.txt
default_days      = 365
default_md        = default # use public key default MD
preserve          = no
email_in_dn       = no
nameopt           = default_ca
certopt           = default_ca
policy            = policy_anything
x509_extensions   = usr_cert
unique_subject    = no

[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits       = 2048 # Size of keys
default_keyfile    = key.pem # name of generated keys
default_md         = default # message digest algorithm
string_mask        = nombstr # permitted characters
distinguished_name = req_distinguished_name
req_extensions     = v3_req

[ req_distinguished_name ]
0.organizationName          = Organization Name (company)
organizationalUnitName      = Organizational Unit Name (department, division)
emailAddress                = Email Address
emailAddress_max            = 40
localityName                = Locality Name (city, district)
stateOrProvinceName         = State or Province Name (full name)
countryName                 = Country Name (2 letter code)
countryName_min             = 2
countryName_max             = 2
commonName                  = Common Name (hostname, IP, or your name)
commonName_max              = 64

[ v3_ca ]
basicConstraints       = CA:TRUE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always

[ v3_req ]
basicConstraints     = CA:FALSE
subjectKeyIdentifier = hash

[ usr_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
"""
