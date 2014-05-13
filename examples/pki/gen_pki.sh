#!/bin/bash

# Copyright 2012 OpenStack Foundation
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

# This script generates the crypto necessary for the SSL tests.

DIR=`dirname "$0"`
CURRENT_DIR=`cd "$DIR" && pwd`
CERTS_DIR=$CURRENT_DIR/certs
PRIVATE_DIR=$CURRENT_DIR/private
CMS_DIR=$CURRENT_DIR/cms


function rm_old {
    rm -rf $CERTS_DIR/*.pem
    rm -rf $PRIVATE_DIR/*.pem
}

function cleanup {
    rm -rf *.conf > /dev/null 2>&1
    rm -rf index* > /dev/null 2>&1
    rm -rf *.crt > /dev/null 2>&1
    rm -rf newcerts > /dev/null 2>&1
    rm -rf *.pem > /dev/null 2>&1
    rm -rf serial* > /dev/null 2>&1
}

function generate_ca_conf {
    echo '
[ req ]
default_bits            = 2048
default_keyfile         = cakey.pem
default_md              = default

prompt                  = no
distinguished_name      = ca_distinguished_name

x509_extensions         = ca_extensions

[ ca_distinguished_name ]
serialNumber            = 5
countryName             = US
stateOrProvinceName     = CA
localityName            = Sunnyvale
organizationName        = OpenStack
organizationalUnitName  = Keystone
emailAddress            = keystone@openstack.org
commonName              = Self Signed

[ ca_extensions ]
basicConstraints        = critical,CA:true
' > ca.conf
}

function generate_ssl_req_conf {
    echo '
[ req ]
default_bits            = 2048
default_keyfile         = keystonekey.pem
default_md              = default

prompt                  = no
distinguished_name      = distinguished_name

[ distinguished_name ]
countryName             = US
stateOrProvinceName     = CA
localityName            = Sunnyvale
organizationName        = OpenStack
organizationalUnitName  = Keystone
commonName              = localhost
emailAddress            = keystone@openstack.org
' > ssl_req.conf
}

function generate_cms_signing_req_conf {
    echo '
[ req ]
default_bits            = 2048
default_keyfile         = keystonekey.pem
default_md              = default

prompt                  = no
distinguished_name      = distinguished_name

[ distinguished_name ]
countryName             = US
stateOrProvinceName     = CA
localityName            = Sunnyvale
organizationName        = OpenStack
organizationalUnitName  = Keystone
commonName              = Keystone
emailAddress            = keystone@openstack.org
' > cms_signing_req.conf
}

function generate_signing_conf {
    echo '
[ ca ]
default_ca      = signing_ca

[ signing_ca ]
dir             = .
database        = $dir/index.txt
new_certs_dir   = $dir/newcerts

certificate     = $dir/certs/cacert.pem
serial          = $dir/serial
private_key     = $dir/private/cakey.pem

default_days            = 21360
default_crl_days        = 30
default_md              = default

policy                  = policy_any

[ policy_any ]
countryName             = supplied
stateOrProvinceName     = supplied
localityName            = optional
organizationName        = supplied
organizationalUnitName  = supplied
emailAddress            = supplied
commonName              = supplied
' > signing.conf
}

function setup {
    touch index.txt
    echo '10' > serial
    generate_ca_conf
    mkdir newcerts
}

function check_error {
    if [ $1 != 0 ] ; then
        echo "Failed! rc=${1}"
        echo 'Bailing ...'
        cleanup
        exit $1
    else
        echo 'Done'
    fi
}

function generate_ca {
    echo 'Generating New CA Certificate ...'
    openssl req -x509 -newkey rsa:2048 -days 21360 -out $CERTS_DIR/cacert.pem -keyout $PRIVATE_DIR/cakey.pem -outform PEM -config ca.conf -nodes
    check_error $?
}

function ssl_cert_req {
    echo 'Generating SSL Certificate Request ...'
    generate_ssl_req_conf
    openssl req -newkey rsa:2048 -keyout $PRIVATE_DIR/ssl_key.pem -keyform PEM -out ssl_req.pem -outform PEM -config ssl_req.conf -nodes
    check_error $?
    #openssl req -in req.pem -text -noout
}

function cms_signing_cert_req {
    echo 'Generating CMS Signing Certificate Request ...'
    generate_cms_signing_req_conf
    openssl req -newkey rsa:2048 -keyout $PRIVATE_DIR/signing_key.pem -keyform PEM -out cms_signing_req.pem -outform PEM -config cms_signing_req.conf -nodes
    check_error $?
    #openssl req -in req.pem -text -noout
}

function issue_certs {
    generate_signing_conf
    echo 'Issuing SSL Certificate ...'
    openssl ca -in ssl_req.pem -config signing.conf -batch
    check_error $?
    openssl x509 -in $CURRENT_DIR/newcerts/10.pem -out $CERTS_DIR/ssl_cert.pem
    check_error $?
    echo 'Issuing CMS Signing Certificate ...'
    openssl ca -in cms_signing_req.pem -config signing.conf -batch
    check_error $?
    openssl x509 -in $CURRENT_DIR/newcerts/11.pem -out $CERTS_DIR/signing_cert.pem
    check_error $?
}

function create_middleware_cert {
    cp $CERTS_DIR/ssl_cert.pem $CERTS_DIR/middleware.pem
    cat $PRIVATE_DIR/ssl_key.pem >> $CERTS_DIR/middleware.pem
}

function check_openssl {
    echo 'Checking openssl availability ...'
    which openssl
    check_error $?
}

function gen_sample_cms {
    for json_file in "${CMS_DIR}/auth_token_revoked.json" "${CMS_DIR}/auth_token_unscoped.json" "${CMS_DIR}/auth_token_scoped.json" "${CMS_DIR}/revocation_list.json"; do
        openssl cms -sign -in $json_file -nosmimecap -signer $CERTS_DIR/signing_cert.pem -inkey $PRIVATE_DIR/signing_key.pem -outform PEM -nodetach -nocerts -noattr -out ${json_file/.json/.pem}
    done
}

check_openssl
rm_old
cleanup
setup
generate_ca
ssl_cert_req
cms_signing_cert_req
issue_certs
create_middleware_cert
gen_sample_cms
cleanup
