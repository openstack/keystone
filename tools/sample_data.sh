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

# Sample initial data for Keystone using python-keystoneclient
#
# This script is based on the original DevStack keystone_data.sh script.
#
# It demonstrates how to bootstrap Keystone with an administrative user
# using the SERVICE_TOKEN and SERVICE_ENDPOINT environment variables
# and the administrative API.  It will get the admin_token (SERVICE_TOKEN)
# and admin_port from keystone.conf if available.
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
    CONFIG_ADMIN_PORT=$(sed 's/[[:space:]]//g' $KEYSTONE_CONF | grep ^admin_port= | cut -d'=' -f2)
fi

export SERVICE_TOKEN=${SERVICE_TOKEN:-$CONFIG_SERVICE_TOKEN}
if [[ -z "$SERVICE_TOKEN" ]]; then
    echo "No service token found."
    echo "Set SERVICE_TOKEN manually from keystone.conf admin_token."
    exit 1
fi

export SERVICE_ENDPOINT=${SERVICE_ENDPOINT:-http://$CONTROLLER_PUBLIC_ADDRESS:${CONFIG_ADMIN_PORT:-35357}/v2.0}

function get_id () {
    echo `"$@" | grep ' id ' | awk '{print $4}'`
}

#
# Default tenant
#
DEMO_TENANT=$(get_id keystone tenant-create --name=demo \
                                            --description "Default Tenant")

ADMIN_USER=$(get_id keystone user-create --name=admin \
                                         --pass="${ADMIN_PASSWORD}")

ADMIN_ROLE=$(get_id keystone role-create --name=admin)

keystone user-role-add --user-id $ADMIN_USER \
                       --role-id $ADMIN_ROLE \
                       --tenant-id $DEMO_TENANT

#
# Service tenant
#
SERVICE_TENANT=$(get_id keystone tenant-create --name=service \
                                               --description "Service Tenant")

GLANCE_USER=$(get_id keystone user-create --name=glance \
                                          --pass="${GLANCE_PASSWORD}")

keystone user-role-add --user-id $GLANCE_USER \
                       --role-id $ADMIN_ROLE \
                       --tenant-id $SERVICE_TENANT

NOVA_USER=$(get_id keystone user-create --name=nova \
                                        --pass="${NOVA_PASSWORD}" \
                                        --tenant-id $SERVICE_TENANT)

keystone user-role-add --user-id $NOVA_USER \
                       --role-id $ADMIN_ROLE \
                       --tenant-id $SERVICE_TENANT

EC2_USER=$(get_id keystone user-create --name=ec2 \
                                       --pass="${EC2_PASSWORD}" \
                                       --tenant-id $SERVICE_TENANT)

keystone user-role-add --user-id $EC2_USER \
                       --role-id $ADMIN_ROLE \
                       --tenant-id $SERVICE_TENANT

SWIFT_USER=$(get_id keystone user-create --name=swift \
                                         --pass="${SWIFT_PASSWORD}" \
                                         --tenant-id $SERVICE_TENANT)

keystone user-role-add --user-id $SWIFT_USER \
                       --role-id $ADMIN_ROLE \
                       --tenant-id $SERVICE_TENANT

#
# Keystone service
#
KEYSTONE_SERVICE=$(get_id \
keystone service-create --name=keystone \
                        --type=identity \
                        --description="Keystone Identity Service")
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    keystone endpoint-create --region RegionOne --service-id $KEYSTONE_SERVICE \
        --publicurl "http://$CONTROLLER_PUBLIC_ADDRESS:\$(public_port)s/v2.0" \
        --adminurl "http://$CONTROLLER_ADMIN_ADDRESS:\$(admin_port)s/v2.0" \
        --internalurl "http://$CONTROLLER_INTERNAL_ADDRESS:\$(public_port)s/v2.0"
fi

#
# Nova service
#
NOVA_SERVICE=$(get_id \
keystone service-create --name=nova \
                        --type=compute \
                        --description="Nova Compute Service")
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    keystone endpoint-create --region RegionOne --service-id $NOVA_SERVICE \
        --publicurl "http://$CONTROLLER_PUBLIC_ADDRESS:\$(compute_port)s/v1.1/\$(tenant_id)s" \
        --adminurl "http://$CONTROLLER_ADMIN_ADDRESS:\$(compute_port)s/v1.1/\$(tenant_id)s" \
        --internalurl "http://$CONTROLLER_INTERNAL_ADDRESS:\$(compute_port)s/v1.1/\$(tenant_id)s"
fi

#
# Volume service
#
VOLUME_SERVICE=$(get_id \
keystone service-create --name=volume \
                        --type=volume \
                        --description="Nova Volume Service")
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    keystone endpoint-create --region RegionOne --service-id $VOLUME_SERVICE \
        --publicurl "http://$CONTROLLER_PUBLIC_ADDRESS:8776/v1/\$(tenant_id)s" \
        --adminurl "http://$CONTROLLER_ADMIN_ADDRESS:8776/v1/\$(tenant_id)s" \
        --internalurl "http://$CONTROLLER_INTERNAL_ADDRESS:8776/v1/\$(tenant_id)s"
fi

#
# Image service
#
GLANCE_SERVICE=$(get_id \
keystone service-create --name=glance \
                        --type=image \
                        --description="Glance Image Service")
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    keystone endpoint-create --region RegionOne --service-id $GLANCE_SERVICE \
        --publicurl "http://$CONTROLLER_PUBLIC_ADDRESS:9292" \
        --adminurl "http://$CONTROLLER_ADMIN_ADDRESS:9292" \
        --internalurl "http://$CONTROLLER_INTERNAL_ADDRESS:9292"
fi

#
# EC2 service
#
EC2_SERVICE=$(get_id \
keystone service-create --name=ec2 \
                        --type=ec2 \
                        --description="EC2 Compatibility Layer")
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    keystone endpoint-create --region RegionOne --service-id $EC2_SERVICE \
        --publicurl "http://$CONTROLLER_PUBLIC_ADDRESS:8773/services/Cloud" \
        --adminurl "http://$CONTROLLER_ADMIN_ADDRESS:8773/services/Admin" \
        --internalurl "http://$CONTROLLER_INTERNAL_ADDRESS:8773/services/Cloud"
fi

#
# Swift service
#
SWIFT_SERVICE=$(get_id \
keystone service-create --name=swift \
                        --type="object-store" \
                        --description="Swift Service")
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    keystone endpoint-create --region RegionOne --service-id $SWIFT_SERVICE \
        --publicurl   "http://$CONTROLLER_PUBLIC_ADDRESS:8888/v1/AUTH_\$(tenant_id)s" \
        --adminurl    "http://$CONTROLLER_ADMIN_ADDRESS:8888/v1" \
        --internalurl "http://$CONTROLLER_INTERNAL_ADDRESS:8888/v1/AUTH_\$(tenant_id)s"
fi

# create ec2 creds and parse the secret and access key returned
RESULT=$(keystone ec2-credentials-create --tenant-id=$SERVICE_TENANT --user-id=$ADMIN_USER)
ADMIN_ACCESS=`echo "$RESULT" | grep access | awk '{print $4}'`
ADMIN_SECRET=`echo "$RESULT" | grep secret | awk '{print $4}'`

# write the secret and access to ec2rc
cat > $EC2RC <<EOF
ADMIN_ACCESS=$ADMIN_ACCESS
ADMIN_SECRET=$ADMIN_SECRET
EOF
