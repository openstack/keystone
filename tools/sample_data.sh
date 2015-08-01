#!/usr/bin/env bash

# Copyright 2013 OpenStack Foundation
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

# Sample initial data for Keystone using python-openstackclient
#
# This script is based on the original DevStack keystone_data.sh script.
#
# It demonstrates how to bootstrap Keystone with an administrative user
# using the OS_TOKEN and OS_URL environment variables and the administrative
# API.  It will get the admin_token (OS_TOKEN) and admin_port from
# keystone.conf if available.
#
# Disable creation of endpoints by setting DISABLE_ENDPOINTS environment variable.
# Use this with the Catalog Templated backend.
#
# A EC2-compatible credential is created for the admin user and
# placed in etc/ec2rc.
#
# Tenant               User      Roles
# -------------------------------------------------------
# demo                 admin     admin
# service              glance    admin
# service              nova      admin
# service              ec2       admin
# service              swift     admin

# By default, passwords used are those in the OpenStack Install and Deploy Manual.
# One can override these (publicly known, and hence, insecure) passwords by setting the appropriate
# environment variables. A common default password for all the services can be used by
# setting the "SERVICE_PASSWORD" environment variable.

# Test to verify that the openstackclient is installed, if not exit
type openstack >/dev/null 2>&1 || {
    echo >&2 "openstackclient is not installed. Please install it to use this script. Aborting."
    exit 1
    }

ADMIN_PASSWORD=${ADMIN_PASSWORD:-secrete}
NOVA_PASSWORD=${NOVA_PASSWORD:-${SERVICE_PASSWORD:-nova}}
GLANCE_PASSWORD=${GLANCE_PASSWORD:-${SERVICE_PASSWORD:-glance}}
EC2_PASSWORD=${EC2_PASSWORD:-${SERVICE_PASSWORD:-ec2}}
SWIFT_PASSWORD=${SWIFT_PASSWORD:-${SERVICE_PASSWORD:-swiftpass}}

CONTROLLER_PUBLIC_ADDRESS=${CONTROLLER_PUBLIC_ADDRESS:-localhost}
CONTROLLER_ADMIN_ADDRESS=${CONTROLLER_ADMIN_ADDRESS:-localhost}
CONTROLLER_INTERNAL_ADDRESS=${CONTROLLER_INTERNAL_ADDRESS:-localhost}

TOOLS_DIR=$(cd $(dirname "$0") && pwd)
KEYSTONE_CONF=${KEYSTONE_CONF:-/etc/keystone/keystone.conf}
if [[ -r "$KEYSTONE_CONF" ]]; then
    EC2RC="$(dirname "$KEYSTONE_CONF")/ec2rc"
elif [[ -r "$TOOLS_DIR/../etc/keystone.conf" ]]; then
    # assume git checkout
    KEYSTONE_CONF="$TOOLS_DIR/../etc/keystone.conf"
    EC2RC="$TOOLS_DIR/../etc/ec2rc"
else
    KEYSTONE_CONF=""
    EC2RC="ec2rc"
fi

# Extract some info from Keystone's configuration file
if [[ -r "$KEYSTONE_CONF" ]]; then
    CONFIG_SERVICE_TOKEN=$(sed 's/[[:space:]]//g' $KEYSTONE_CONF | grep ^admin_token= | cut -d'=' -f2)
    if [[ -z "${CONFIG_SERVICE_TOKEN}" ]]; then
        # default config options are commented out, so lets try those
        CONFIG_SERVICE_TOKEN=$(sed 's/[[:space:]]//g' $KEYSTONE_CONF | grep ^\#admin_token= | cut -d'=' -f2)
    fi
    CONFIG_ADMIN_PORT=$(sed 's/[[:space:]]//g' $KEYSTONE_CONF | grep ^admin_port= | cut -d'=' -f2)
    if [[ -z "${CONFIG_ADMIN_PORT}" ]]; then
        # default config options are commented out, so lets try those
        CONFIG_ADMIN_PORT=$(sed 's/[[:space:]]//g' $KEYSTONE_CONF | grep ^\#admin_port= | cut -d'=' -f2)
    fi
fi

export OS_TOKEN=${OS_TOKEN:-$CONFIG_SERVICE_TOKEN}
if [[ -z "$OS_TOKEN" ]]; then
    echo "No service token found."
    echo "Set OS_TOKEN manually from keystone.conf admin_token."
    exit 1
fi

export OS_URL=${OS_URL:-http://$CONTROLLER_PUBLIC_ADDRESS:${CONFIG_ADMIN_PORT:-35357}/v2.0}

function get_id () {
    echo `"$@" | grep ' id ' | awk '{print $4}'`
}

#
# Default tenant
#
openstack project create demo \
                         --description "Default Tenant"

openstack user create admin --project demo \
                      --password "${ADMIN_PASSWORD}"

openstack role create admin

openstack role add --user admin \
                   --project demo\
                   admin

#
# Service tenant
#
openstack project create service \
                  --description "Service Tenant"

openstack user create glance --project service\
                      --password "${GLANCE_PASSWORD}"

openstack role add --user glance \
                   --project service \
                   admin

openstack user create nova --project service\
                      --password "${NOVA_PASSWORD}"

openstack role add --user nova \
                   --project service \
                   admin

openstack user create ec2 --project service \
                      --password "${EC2_PASSWORD}"

openstack role add --user ec2 \
                   --project service \
                   admin

openstack user create swift --project service \
                      --password "${SWIFT_PASSWORD}" \

openstack role add --user swift \
                   --project service \
                   admin

#
# Keystone service
#
openstack service create --name keystone \
                         --description "Keystone Identity Service" \
                         identity
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    openstack endpoint create --region RegionOne \
        --publicurl "http://$CONTROLLER_PUBLIC_ADDRESS:\$(public_port)s/v2.0" \
        --adminurl "http://$CONTROLLER_ADMIN_ADDRESS:\$(admin_port)s/v2.0" \
        --internalurl "http://$CONTROLLER_INTERNAL_ADDRESS:\$(public_port)s/v2.0" \
        keystone
fi

#
# Nova service
#
openstack service create --name=nova \
                         --description="Nova Compute Service" \
                         compute
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    openstack endpoint create --region RegionOne \
        --publicurl "http://$CONTROLLER_PUBLIC_ADDRESS:8774/v2/\$(tenant_id)s" \
        --adminurl "http://$CONTROLLER_ADMIN_ADDRESS:8774/v2/\$(tenant_id)s" \
        --internalurl "http://$CONTROLLER_INTERNAL_ADDRESS:8774/v2/\$(tenant_id)s" \
        nova
fi

#
# Volume service
#
openstack service create --name=volume \
                         --description="Cinder Volume Service" \
                         volume
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    openstack endpoint create --region RegionOne \
        --publicurl "http://$CONTROLLER_PUBLIC_ADDRESS:8776/v1/\$(tenant_id)s" \
        --adminurl "http://$CONTROLLER_ADMIN_ADDRESS:8776/v1/\$(tenant_id)s" \
        --internalurl "http://$CONTROLLER_INTERNAL_ADDRESS:8776/v1/\$(tenant_id)s" \
        volume
fi

#
# Image service
#
openstack service create --name=glance \
                         --description="Glance Image Service" \
                         image
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    openstack endpoint create --region RegionOne  \
        --publicurl "http://$CONTROLLER_PUBLIC_ADDRESS:9292" \
        --adminurl "http://$CONTROLLER_ADMIN_ADDRESS:9292" \
        --internalurl "http://$CONTROLLER_INTERNAL_ADDRESS:9292" \
        glance
fi

#
# EC2 service
#
openstack service create --name=ec2 \
                         --description="EC2 Compatibility Layer" \
                         ec2
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    openstack endpoint create --region RegionOne \
        --publicurl "http://$CONTROLLER_PUBLIC_ADDRESS:8773/services/Cloud" \
        --adminurl "http://$CONTROLLER_ADMIN_ADDRESS:8773/services/Admin" \
        --internalurl "http://$CONTROLLER_INTERNAL_ADDRESS:8773/services/Cloud" \
        ec2
fi

#
# Swift service
#
openstack service create --name=swift \
                         --description="Swift Object Storage Service" \
                         object-store
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    openstack endpoint create --region RegionOne \
        --publicurl   "http://$CONTROLLER_PUBLIC_ADDRESS:8080/v1/AUTH_\$(tenant_id)s" \
        --adminurl    "http://$CONTROLLER_ADMIN_ADDRESS:8080/v1" \
        --internalurl "http://$CONTROLLER_INTERNAL_ADDRESS:8080/v1/AUTH_\$(tenant_id)s" \
        swift
fi

# create ec2 creds and parse the secret and access key returned
ADMIN_USER=$(get_id openstack user show admin)
RESULT=$(openstack ec2 credentials create --project service --user $ADMIN_USER)
ADMIN_ACCESS=`echo "$RESULT" | grep access | awk '{print $4}'`
ADMIN_SECRET=`echo "$RESULT" | grep secret | awk '{print $4}'`

# write the secret and access to ec2rc
cat > $EC2RC <<EOF
ADMIN_ACCESS=$ADMIN_ACCESS
ADMIN_SECRET=$ADMIN_SECRET
EOF
