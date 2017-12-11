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
# using the `keystone-manage bootstrap` command.  It will get the admin_port
# from keystone.conf if available.
#
# Disable creation of endpoints by setting DISABLE_ENDPOINTS environment variable.
# Use this with the Catalog Templated backend.
#
# Project              User      Roles
# -------------------------------------------------------
# demo                 admin     admin
# service              glance    service
# service              nova      service
# service              cinder    service
# service              swift     service
# service              neutron   service

# By default, passwords used are those in the OpenStack Install and Deploy Manual.
# One can override these (publicly known, and hence, insecure) passwords by setting the appropriate
# environment variables. A common default password for all the services can be used by
# setting the "SERVICE_PASSWORD" environment variable.

# Test to verify that the openstackclient is installed, if not exit
type openstack >/dev/null 2>&1 || {
    echo >&2 "openstackclient is not installed. Please install it to use this script. Aborting."
    exit 1
    }

ADMIN_PASSWORD=${ADMIN_PASSWORD:-secret}
NOVA_PASSWORD=${NOVA_PASSWORD:-${SERVICE_PASSWORD:-nova}}
GLANCE_PASSWORD=${GLANCE_PASSWORD:-${SERVICE_PASSWORD:-glance}}
CINDER_PASSWORD=${CINDER_PASSWORD:-${SERVICE_PASSWORD:-cinder}}
SWIFT_PASSWORD=${SWIFT_PASSWORD:-${SERVICE_PASSWORD:-swiftpass}}
NEUTRON_PASSWORD=${NEUTRON_PASSWORD:-${SERVICE_PASSWORD:-neutron}}

CONTROLLER_PUBLIC_ADDRESS=${CONTROLLER_PUBLIC_ADDRESS:-localhost}
CONTROLLER_ADMIN_ADDRESS=${CONTROLLER_ADMIN_ADDRESS:-localhost}
CONTROLLER_INTERNAL_ADDRESS=${CONTROLLER_INTERNAL_ADDRESS:-localhost}

TOOLS_DIR=$(cd $(dirname "$0") && pwd)
KEYSTONE_CONF=${KEYSTONE_CONF:-/etc/keystone/keystone.conf}
if [[ ! -r "$KEYSTONE_CONF" ]]; then
    if [[ -r "$TOOLS_DIR/../etc/keystone.conf" ]]; then
        # assume git checkout
        KEYSTONE_CONF="$TOOLS_DIR/../etc/keystone.conf"
    else
        KEYSTONE_CONF=""
    fi
fi

# Extract some info from Keystone's configuration file
if [[ -r "$KEYSTONE_CONF" ]]; then
    CONFIG_ADMIN_PORT=$(sed 's/[[:space:]]//g' $KEYSTONE_CONF | grep ^admin_port= | cut -d'=' -f2)
    if [[ -z "${CONFIG_ADMIN_PORT}" ]]; then
        # default config options are commented out, so lets try those
        CONFIG_ADMIN_PORT=$(sed 's/[[:space:]]//g' $KEYSTONE_CONF | grep ^\#admin_port= | cut -d'=' -f2)
    fi
fi

export OS_USERNAME=admin
export OS_PASSWORD=$ADMIN_PASSWORD
export OS_PROJECT_NAME=admin
export OS_USER_DOMAIN_ID=default
export OS_PROJECT_DOMAIN_ID=default
export OS_IDENTITY_API_VERSION=3
export OS_AUTH_URL=http://$CONTROLLER_PUBLIC_ADDRESS:${CONFIG_ADMIN_PORT:-35357}/v3

export OS_BOOTSTRAP_PASSWORD=$ADMIN_PASSWORD
export OS_BOOTSTRAP_REGION_ID=RegionOne
export OS_BOOTSTRAP_ADMIN_URL="http://$CONTROLLER_PUBLIC_ADDRESS:\$(public_port)s/v3"
export OS_BOOTSTRAP_PUBLIC_URL="http://$CONTROLLER_ADMIN_ADDRESS:\$(admin_port)s/v3"
export OS_BOOTSTRAP_INTERNAL_URL="http://$CONTROLLER_INTERNAL_ADDRESS:\$(public_port)s/v3"
keystone-manage bootstrap

#
# Default tenant
#
openstack project create demo \
                         --description "Default Tenant"

#
# Service tenant
#
openstack role create service

openstack project create service \
                  --description "Service Tenant"

openstack user create glance --project service\
                      --password "${GLANCE_PASSWORD}"

openstack role add --user glance \
                   --project service \
                   service

openstack user create nova --project service\
                      --password "${NOVA_PASSWORD}"

openstack role add --user nova \
                   --project service \
                   service

openstack user create cinder --project service \
                      --password "${CINDER_PASSWORD}"

openstack role add --user cinder \
                   --project service \
                   service

openstack user create swift --project service \
                      --password "${SWIFT_PASSWORD}" \

openstack role add --user swift \
                   --project service \
                   service

openstack user create neutron --project service \
                      --password "${NEUTRON_PASSWORD}" \

openstack role add --user neutron \
                   --project service \
                   service

#
# Nova service
#
openstack service create --name=nova_legacy \
                         --description="Nova Compute Service (Legacy 2.0)" \
                         compute_legacy
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    openstack endpoint create --region RegionOne \
        compute public "http://$CONTROLLER_PUBLIC_ADDRESS:8774/v2/\$(project_id)s"
    openstack endpoint create --region RegionOne \
        compute admin "http://$CONTROLLER_ADMIN_ADDRESS:8774/v2/\$(project_id)s"
    openstack endpoint create --region RegionOne \
        compute internal "http://$CONTROLLER_INTERNAL_ADDRESS:8774/v2/\$(project_id)s"
fi

openstack service create --name=nova \
                         --description="Nova Compute Service" \
                         compute
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    openstack endpoint create --region RegionOne \
        compute public "http://$CONTROLLER_PUBLIC_ADDRESS:8774/v2.1"
    openstack endpoint create --region RegionOne \
        compute admin "http://$CONTROLLER_ADMIN_ADDRESS:8774/v2.1"
    openstack endpoint create --region RegionOne \
        compute internal "http://$CONTROLLER_INTERNAL_ADDRESS:8774/v2.1"
fi

#
# Volume service
#
openstack service create --name=cinderv2 \
                         --description="Cinder Volume Service V2" \
                         volumev2
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    openstack endpoint create --region RegionOne \
        volume public "http://$CONTROLLER_PUBLIC_ADDRESS:8776/v2/\$(project_id)s"
    openstack endpoint create --region RegionOne \
        volume admin "http://$CONTROLLER_ADMIN_ADDRESS:8776/v2/\$(project_id)s"
    openstack endpoint create --region RegionOne \
        volume internal "http://$CONTROLLER_INTERNAL_ADDRESS:8776/v2/\$(project_id)s"
fi

openstack service create --name=cinderv3 \
                         --description="Cinder Volume Service V3" \
                         volumev3
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    openstack endpoint create --region RegionOne \
        volume public "http://$CONTROLLER_PUBLIC_ADDRESS:8776/v3/\$(project_id)s"
    openstack endpoint create --region RegionOne \
        volume admin "http://$CONTROLLER_ADMIN_ADDRESS:8776/v3/\$(project_id)s"
    openstack endpoint create --region RegionOne \
        volume internal "http://$CONTROLLER_INTERNAL_ADDRESS:8776/v3/\$(project_id)s"
fi

#
# Image service
#
openstack service create --name=glance \
                         --description="Glance Image Service" \
                         image
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    openstack endpoint create --region RegionOne  \
        image public "http://$CONTROLLER_PUBLIC_ADDRESS:9292"
    openstack endpoint create --region RegionOne  \
        image admin "http://$CONTROLLER_ADMIN_ADDRESS:9292"
    openstack endpoint create --region RegionOne  \
        image internal "http://$CONTROLLER_INTERNAL_ADDRESS:9292"
fi

#
# Swift service
#
openstack service create --name=swift \
                         --description="Swift Object Storage Service" \
                         object-store
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    openstack endpoint create --region RegionOne \
        object-store public "http://$CONTROLLER_PUBLIC_ADDRESS:8080/v1/AUTH_\$(project_id)s"
    openstack endpoint create --region RegionOne \
        object-store admin "http://$CONTROLLER_ADMIN_ADDRESS:8080/v1"
    openstack endpoint create --region RegionOne \
        object-store internal "http://$CONTROLLER_INTERNAL_ADDRESS:8080/v1/AUTH_\$(project_id)s"
fi

#
# Neutron service
#
openstack service create --name=neutron \
                         --description="Neutron Network Service" \
                         network
if [[ -z "$DISABLE_ENDPOINTS" ]]; then
    openstack endpoint create --region RegionOne \
        network public "http://$CONTROLLER_PUBLIC_ADDRESS:9696"
    openstack endpoint create --region RegionOne \
        network admin "http://$CONTROLLER_ADMIN_ADDRESS:9696"
    openstack endpoint create --region RegionOne \
        network internal "http://$CONTROLLER_INTERNAL_ADDRESS:9696"
fi
