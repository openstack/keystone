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

import keystone.conf


CONF = keystone.conf.CONF


def symptom_comma_in_SAML_public_certificate_path():
    """`[saml] certfile` should not contain a comma (`,`).

    Because a comma is part of the API between keystone and the external
    xmlsec1 binary which utilizes the certificate, keystone cannot include a
    comma in the path to the public certificate file.
    """
    return ',' in CONF.saml.certfile


def symptom_comma_in_SAML_private_key_file_path():
    """`[saml] certfile` should not contain a comma (`,`).

    Because a comma is part of the API between keystone and the external
    xmlsec1 binary which utilizes the key, keystone cannot include a comma in
    the path to the private key file.
    """
    return ',' in CONF.saml.keyfile
