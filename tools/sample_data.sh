#!/usr/bin/env bash

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

# Sample initial data for Keystone using python-keystoneclient
#
# This script is based on the original DevStack keystone_data.sh script.
#
# It demonstrates how to bootstrap Keystone with an administrative user
# using the SERVICE_TOKEN and SERVICE_ENDPOINT environment variables
# and the administrative API.  It will get the admin_token (SERVICE_TOKEN)
# and admin_port from keystone.conf if available.
#
# There are two environment variables to set passwords that should be set
# prior to running this script.  Warnings will appear if they are unset.
# * ADMIN_PASSWORD is used to set the password for the admin and demo accounts.
# * SERVICE_PASSWORD is used to set the password for the service accounts.
#
# Enable the Swift and Quantum accounts by setting ENABLE_SWIFT and/or
# ENABLE_QUANTUM environment variables.
#
# Enable creation of endpoints by setting ENABLE_ENDPOINTS environment variable.
# Works with Catalog SQL backend. Do not use with Catalog Templated backend
# (default).
#
# A set of EC2-compatible credentials is created for both admin and demo
# users and placed in etc/ec2rc.
#
# Tenant               User      Roles
# -------------------------------------------------------
# admin                admin     admin
# service              glance    admin
# service              nova      admin
# service              quantum   admin        # if enabled
# service              swift     admin        # if enabled
# demo                 admin     admin
# demo                 demo      Member,sysadmin,netadmin
# invisible_to_admin   demo      Member

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

# Please set these, they are ONLY SAMPLE PASSWORDS!
ADMIN_PASSWORD=${ADMIN_PASSWORD:-secrete}
if [[ "$ADMIN_PASSWORD" == "secrete" ]]; then
    echo "The default admin password has been detected.  Please consider"
    echo "setting an actual password in environment variable ADMIN_PASSWORD"
fi
SERVICE_PASSWORD=${SERVICE_PASSWORD:-$ADMIN_PASSWORD}
if [[ "$SERVICE_PASSWORD" == "$ADMIN_PASSWORD" ]]; then
    echo "The default service password has been detected.  Please consider"
    echo "setting an actual password in environment variable SERVICE_PASSWORD"
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

export SERVICE_ENDPOINT=${SERVICE_ENDPOINT:-http://127.0.0.1:${CONFIG_ADMIN_PORT:-35357}/v2.0}

function get_id () {
    echo `"$@" | grep ' id ' | awk '{print $4}'`
}


# Tenants
ADMIN_TENANT=$(get_id keystone tenant-create --name=admin)
SERVICE_TENANT=$(get_id keystone tenant-create --name=service)
DEMO_TENANT=$(get_id keystone tenant-create --name=demo)
INVIS_TENANT=$(get_id keystone tenant-create --name=invisible_to_admin)


# Users
ADMIN_USER=$(get_id keystone user-create --name=admin \
                                         --pass="$ADMIN_PASSWORD" \
                                         --email=admin@example.com)
DEMO_USER=$(get_id keystone user-create --name=demo \
                                        --pass="$ADMIN_PASSWORD" \
                                        --email=admin@example.com)


# Roles
ADMIN_ROLE=$(get_id keystone role-create --name=admin)
MEMBER_ROLE=$(get_id keystone role-create --name=Member)
KEYSTONEADMIN_ROLE=$(get_id keystone role-create --name=KeystoneAdmin)
KEYSTONESERVICE_ROLE=$(get_id keystone role-create --name=KeystoneServiceAdmin)
SYSADMIN_ROLE=$(get_id keystone role-create --name=sysadmin)
NETADMIN_ROLE=$(get_id keystone role-create --name=netadmin)


# Add Roles to Users in Tenants
keystone user-role-add --user_id $ADMIN_USER --role_id $ADMIN_ROLE --tenant_id $ADMIN_TENANT
keystone user-role-add --user_id $DEMO_USER --role_id $MEMBER_ROLE --tenant_id $DEMO_TENANT
keystone user-role-add --user_id $DEMO_USER --role_id $SYSADMIN_ROLE --tenant_id $DEMO_TENANT
keystone user-role-add --user_id $DEMO_USER --role_id $NETADMIN_ROLE --tenant_id $DEMO_TENANT
keystone user-role-add --user_id $DEMO_USER --role_id $MEMBER_ROLE --tenant_id $INVIS_TENANT
keystone user-role-add --user_id $ADMIN_USER --role_id $ADMIN_ROLE --tenant_id $DEMO_TENANT

# TODO(termie): these two might be dubious
keystone user-role-add --user_id $ADMIN_USER --role_id $KEYSTONEADMIN_ROLE --tenant_id $ADMIN_TENANT
keystone user-role-add --user_id $ADMIN_USER --role_id $KEYSTONESERVICE_ROLE --tenant_id $ADMIN_TENANT


# Services
NOVA_SERVICE=$(get_id \
keystone service-create --name=nova \
                        --type=compute \
                        --description="Nova Compute Service")
NOVA_USER=$(get_id keystone user-create --name=nova \
                                        --pass="$SERVICE_PASSWORD" \
                                        --tenant_id $SERVICE_TENANT \
                                        --email=nova@example.com)
keystone user-role-add --tenant_id $SERVICE_TENANT \
                       --user_id $NOVA_USER \
                       --role_id $ADMIN_ROLE
if [[ -n "$ENABLE_ENDPOINTS" ]]; then
    keystone endpoint-create --region RegionOne --service_id $NOVA_SERVICE \
        --publicurl 'http://localhost:$(compute_port)s/v1.1/$(tenant_id)s' \
        --adminurl 'http://localhost:$(compute_port)s/v1.1/$(tenant_id)s' \
        --internalurl 'http://localhost:$(compute_port)s/v1.1/$(tenant_id)s'
fi

EC2_SERVICE=$(get_id \
keystone service-create --name=ec2 \
                        --type=ec2 \
                        --description="EC2 Compatibility Layer")
if [[ -n "$ENABLE_ENDPOINTS" ]]; then
    keystone endpoint-create --region RegionOne --service_id $EC2_SERVICE \
        --publicurl http://localhost:8773/services/Cloud \
        --adminurl http://localhost:8773/services/Admin \
        --internalurl http://localhost:8773/services/Cloud
fi

GLANCE_SERVICE=$(get_id \
keystone service-create --name=glance \
                        --type=image \
                        --description="Glance Image Service")
GLANCE_USER=$(get_id keystone user-create --name=glance \
                                          --pass="$SERVICE_PASSWORD" \
                                          --tenant_id $SERVICE_TENANT \
                                          --email=glance@example.com)
keystone user-role-add --tenant_id $SERVICE_TENANT \
                       --user_id $GLANCE_USER \
                       --role_id $ADMIN_ROLE
if [[ -n "$ENABLE_ENDPOINTS" ]]; then
    keystone endpoint-create --region RegionOne --service_id $GLANCE_SERVICE \
        --publicurl http://localhost:9292/v1 \
        --adminurl http://localhost:9292/v1 \
        --internalurl http://localhost:9292/v1
fi

KEYSTONE_SERVICE=$(get_id \
keystone service-create --name=keystone \
                        --type=identity \
                        --description="Keystone Identity Service")
if [[ -n "$ENABLE_ENDPOINTS" ]]; then
    keystone endpoint-create --region RegionOne --service_id $KEYSTONE_SERVICE \
        --publicurl 'http://localhost:$(public_port)s/v2.0' \
        --adminurl 'http://localhost:$(admin_port)s/v2.0' \
        --internalurl 'http://localhost:$(admin_port)s/v2.0'
fi

VOLUME_SERVICE=$(get_id \
keystone service-create --name="nova-volume" \
                        --type=volume \
                        --description="Nova Volume Service")
if [[ -n "$ENABLE_ENDPOINTS" ]]; then
    keystone endpoint-create --region RegionOne --service_id $VOLUME_SERVICE \
        --publicurl 'http://localhost:8776/v1/$(tenant_id)s' \
        --adminurl 'http://localhost:8776/v1/$(tenant_id)s' \
        --internalurl 'http://localhost:8776/v1/$(tenant_id)s'
fi

keystone service-create --name="horizon" \
						--type=dashboard \
						--description="OpenStack Dashboard"

if [[ -n "$ENABLE_SWIFT" ]]; then
    keystone service-create --name=swift \
                            --type="object-store" \
                            --description="Swift Service"
    SWIFT_USER=$(get_id keystone user-create --name=swift \
                                             --pass="$SERVICE_PASSWORD" \
                                             --tenant_id $SERVICE_TENANT \
                                             --email=swift@example.com)
    keystone user-role-add --tenant_id $SERVICE_TENANT \
                           --user_id $SWIFT_USER \
                           --role_id $ADMIN_ROLE
fi

if [[ -n "$ENABLE_QUANTUM" ]]; then
    keystone service-create --name=quantum \
                            --type=network \
                            --description="Quantum Service"
    QUANTUM_USER=$(get_id keystone user-create --name=quantum \
                                               --pass="$SERVICE_PASSWORD" \
                                               --tenant_id $SERVICE_TENANT \
                                               --email=quantum@example.com)
    keystone user-role-add --tenant_id $SERVICE_TENANT \
                           --user_id $QUANTUM_USER \
                           --role_id $ADMIN_ROLE
fi


# create ec2 creds and parse the secret and access key returned
RESULT=$(keystone ec2-credentials-create --tenant_id=$ADMIN_TENANT --user_id=$ADMIN_USER)
ADMIN_ACCESS=`echo "$RESULT" | grep access | awk '{print $4}'`
ADMIN_SECRET=`echo "$RESULT" | grep secret | awk '{print $4}'`

RESULT=$(keystone ec2-credentials-create --tenant_id=$DEMO_TENANT --user_id=$DEMO_USER)
DEMO_ACCESS=`echo "$RESULT" | grep access | awk '{print $4}'`
DEMO_SECRET=`echo "$RESULT" | grep secret | awk '{print $4}'`

# write the secret and access to ec2rc
cat > $EC2RC <<EOF
ADMIN_ACCESS=$ADMIN_ACCESS
ADMIN_SECRET=$ADMIN_SECRET
DEMO_ACCESS=$DEMO_ACCESS
DEMO_SECRET=$DEMO_SECRET
EOF
