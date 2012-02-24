#!/usr/bin/env bash
#
# Sample data for Keystone using python-keystoneclient
#
# This is based on the origina sample configuration created by DevStack.
# It demonstrates how to bootstrap Keystone with an administrative user
# using the SERVICE_TOKEN and SERVICE_ENDPOINT environment variables
# and the administrative API.  It need not be run on the node running
# Keystone, but will get the admin_token (SERVICE_TOKEN) and admin_port
# from keystone.conf if available.
#
# A set of EC2-compatible credentials is created for both admin and demo
# users and placed in etc/ec2rc.
#
# Tenant               User      Roles
# -------------------------------------------------------
# admin                admin     admin
# demo                 admin     admin
# demo                 demo      Member,sysadmin,netadmin
# invisible_to_admin   demo      Member

TOOLS_DIR=$(cd $(dirname "$0") && pwd)

# Please set this, it is ONLY A SAMPLE PASSWORD!
ADMIN_PASSWORD=${ADMIN_PASSWORD:-secrete}
if [[ "$ADMIN_PASSWORD" == "secrete" ]]; then
    echo "The default admin password has been detected.  Please consider"
    echo "setting an actual password in environment variable ADMIN_PASSWORD"
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

keystone service-create --name=ec2 \
                        --type=ec2 \
                        --description="EC2 Compatibility Layer"

keystone service-create --name=glance \
                        --type=image \
                        --description="Glance Image Service"

keystone service-create --name=keystone \
                        --type=identity \
                        --description="Keystone Identity Service"

keystone service-create --name=swift \
                        --type="nova-volume" \
                        --description="Nova Volume Service"

if [[ -d "$TOOLS_DIR/../../swift" ]]; then
    keystone service-create --name=swift \
                            --type="object-store" \
                            --description="Swift Service"
fi

if [[ -d "$TOOLD_DIR/../../quantum" ]]; then
    keystone service-create --name=quantum \
                            --type=network \
                            --description="Quantum Service"
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
