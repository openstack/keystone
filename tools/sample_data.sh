#!/usr/bin/env bash
#
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
if [[ -r $TOOLS_DIR/../etc/keystone.conf ]]; then
    CONFIG_SERVICE_TOKEN=$(sed 's/[[:space:]]//g' $TOOLS_DIR/../etc/keystone.conf | grep ^admin_token= | cut -d'=' -f2)
    CONFIG_ADMIN_PORT=$(sed 's/[[:space:]]//g' $TOOLS_DIR/../etc/keystone.conf | grep ^admin_port= | cut -d'=' -f2)
fi

export SERVICE_TOKEN=${SERVICE_TOKEN:-$CONFIG_SERVICE_TOKEN}
if [[ -z "$SERVICE_TOKEN" ]]; then
    echo "No service token found."
    echo "Set SERVICE_TOKEN manually from keystone.conf admin_token."
    exit 1
fi

export SERVICE_ENDPOINT=${SERVICE_ENDPOINT:-http://127.0.0.1:${CONFIG_ADMIN_PORT:-35357}/v2.0}

function get_id () {
    echo `$@ | grep ' id ' | awk '{print $4}'`
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
keystone user-role-add --user $ADMIN_USER --role $ADMIN_ROLE --tenant_id $ADMIN_TENANT
keystone user-role-add --user $DEMO_USER --role $MEMBER_ROLE --tenant_id $DEMO_TENANT
keystone user-role-add --user $DEMO_USER --role $SYSADMIN_ROLE --tenant_id $DEMO_TENANT
keystone user-role-add --user $DEMO_USER --role $NETADMIN_ROLE --tenant_id $DEMO_TENANT
keystone user-role-add --user $DEMO_USER --role $MEMBER_ROLE --tenant_id $INVIS_TENANT
keystone user-role-add --user $ADMIN_USER --role $ADMIN_ROLE --tenant_id $DEMO_TENANT

# TODO(termie): these two might be dubious
keystone user-role-add --user $ADMIN_USER --role $KEYSTONEADMIN_ROLE --tenant_id $ADMIN_TENANT
keystone user-role-add --user $ADMIN_USER --role $KEYSTONESERVICE_ROLE --tenant_id $ADMIN_TENANT


# Services
keystone service-create --name=nova \
                        --type=compute \
                        --description="Nova Compute Service"
NOVA_USER=$(get_id keystone user-create --name=nova \
                                        --pass="$SERVICE_PASSWORD" \
                                        --tenant_id $SERVICE_TENANT \
                                        --email=nova@example.com)
keystone user-role-add --tenant_id $SERVICE_TENANT \
                       --user $NOVA_USER \
                       --role $ADMIN_ROLE

keystone service-create --name=ec2 \
                        --type=ec2 \
                        --description="EC2 Compatibility Layer"

keystone service-create --name=glance \
                        --type=image \
                        --description="Glance Image Service"
GLANCE_USER=$(get_id keystone user-create --name=glance \
                                          --pass="$SERVICE_PASSWORD" \
                                          --tenant_id $SERVICE_TENANT \
                                          --email=glance@example.com)
keystone user-role-add --tenant_id $SERVICE_TENANT \
                       --user $GLANCE_USER \
                       --role $ADMIN_ROLE

keystone service-create --name=keystone \
                        --type=identity \
                        --description="Keystone Identity Service"

keystone service-create --name=volume \
                        --type="nova-volume" \
                        --description="Nova Volume Service"

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
                           --user $SWIFT_USER \
                           --role $ADMIN_ROLE
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
                           --user $QUANTUM_USER \
                           --role $ADMIN_ROLE
fi


# create ec2 creds and parse the secret and access key returned
RESULT=$(keystone ec2-credentials-create --tenant_id=$ADMIN_TENANT --user=$ADMIN_USER)
ADMIN_ACCESS=`echo "$RESULT" | grep access | awk '{print $4}'`
ADMIN_SECRET=`echo "$RESULT" | grep secret | awk '{print $4}'`

RESULT=$(keystone ec2-credentials-create --tenant_id=$DEMO_TENANT --user=$DEMO_USER)
DEMO_ACCESS=`echo "$RESULT" | grep access | awk '{print $4}'`
DEMO_SECRET=`echo "$RESULT" | grep secret | awk '{print $4}'`

# write the secret and access to ec2rc
cat > $TOOLS_DIR/../etc/ec2rc <<EOF
ADMIN_ACCESS=$ADMIN_ACCESS
ADMIN_SECRET=$ADMIN_SECRET
DEMO_ACCESS=$DEMO_ACCESS
DEMO_SECRET=$DEMO_SECRET
EOF
