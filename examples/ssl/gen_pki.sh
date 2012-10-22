#!/bin/bash

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

# This script generates the crypto necessary for the SSL tests.

DIR=`dirname "$0"`
CURRENT_DIR=`cd "$DIR" && pwd`
CERTS_DIR=$CURRENT_DIR/certs
PRIVATE_DIR=$CURRENT_DIR/private


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
default_bits            = 1024
default_keyfile         = cakey.pem
default_md              = sha1

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

function generate_req_conf {
  echo '
[ req ]
default_bits            = 1024
default_keyfile         = keystonekey.pem
default_md              = sha1

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
' > req.conf
}

function generate_signing_conf {
  echo '
[ ca ]
default_ca      = signing_ca

[ signing_ca ]
dir             = .
database        = $dir/index.txt
new_certs_dir   = $dir/newcerts

certificate     = $dir/certs/ca.pem
serial          = $dir/serial
private_key     = $dir/private/cakey.pem

default_days            = 21360
default_crl_days        = 30
default_md              = sha1

policy                  = policy_any

x509_extensions         = ca_extensions

[ policy_any ]
countryName             = supplied
stateOrProvinceName     = supplied
localityName            = optional
organizationName        = supplied
organizationalUnitName  = supplied
emailAddress            = supplied
commonName              = supplied

[ ca_extensions ]
basicConstraints        = critical,CA:true
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
  openssl req -x509 -newkey rsa:1024 -days 21360 -out $CERTS_DIR/ca.pem -keyout $PRIVATE_DIR/cakey.pem -outform PEM -config ca.conf -nodes
  check_error $?
}

function cert_req {
  echo 'Generating Certificate Request ...'
  generate_req_conf
  openssl req -newkey rsa:1024 -keyout $PRIVATE_DIR/keystonekey.pem -keyform PEM -out req.pem -outform PEM -config req.conf -nodes
  check_error $?
  #openssl req -in req.pem -text -noout
}


function issue_cert {
  echo 'Issuing SSL Certificate ...'
  generate_signing_conf
  openssl ca -in req.pem -config signing.conf -batch
  check_error $?
  openssl x509 -in $CURRENT_DIR/newcerts/10.pem -out $CERTS_DIR/keystone.pem
  check_error $?
}

function create_middleware_cert {
  cp $CERTS_DIR/keystone.pem $CERTS_DIR/middleware.pem
  cat $PRIVATE_DIR/keystonekey.pem >> $CERTS_DIR/middleware.pem
}


echo $CURRENT_DIR
rm_old
cleanup
setup
generate_ca
cert_req
issue_cert
create_middleware_cert
cleanup
