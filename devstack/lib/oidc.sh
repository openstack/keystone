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

DOMAIN_NAME=${DOMAIN_NAME:-federated_domain}
PROJECT_NAME=${PROJECT_NAME:-federated_project}
GROUP_NAME=${GROUP_NAME:-federated_users}

OIDC_CLIENT_ID=${CLIENT_ID:-devstack}
OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET:-nomoresecret}

OIDC_ISSUER=${OIDC_ISSUER:-"https://$HOST_IP:8443"}
OIDC_ISSUER_BASE="${OIDC_ISSUER}/realms/master"

OIDC_METADATA_URL=${OIDC_METADATA_URL:-"https://$HOST_IP:8443/realms/master/.well-known/openid-configuration"}
OIDC_INTROSPECTION_URL=${OIDC_INTROSPECTION_URL:-"https://$HOST_IP:8443/realms/master/protocol/openid-connect/token/introspect"}

IDP_ID=${IDP_ID:-sso}
IDP_USERNAME=${IDP_USERNAME:-admin}
IDP_PASSWORD=${IDP_PASSWORD:-nomoresecret}

MAPPING_REMOTE_TYPE=${MAPPING_REMOTE_TYPE:-OIDC-preferred_username}
MAPPING_USER_NAME=${MAPPING_USER_NAME:-"{0}"}
PROTOCOL_ID=${PROTOCOL_ID:-openid}

REDIRECT_URI="https://$HOST_IP/identity/v3/auth/OS-FEDERATION/identity_providers/$IDP_ID/protocols/openid/websso"

OIDC_PLUGIN="$DEST/keystone/devstack"

function install_federation {
    if is_ubuntu; then
        install_package libapache2-mod-auth-openidc
        sudo a2enmod headers
        install_package docker.io
        install_package docker-compose
    elif is_fedora; then
        install_package mod_auth_openidc
        install_package podman
        install_package podman-docker
        install_package docker-compose
        sudo systemctl start podman.socket
    else
        echo "Skipping installation. Only supported on Ubuntu and RHEL based."
    fi
}

function configure_federation {
    # Specify the header that contains information about the identity provider
    iniset $KEYSTONE_CONF openid remote_id_attribute "HTTP_OIDC_ISS"
    iniset $KEYSTONE_CONF auth methods "password,token,openid,application_credential"
    iniset $KEYSTONE_CONF federation trusted_dashboard "https://$HOST_IP/auth/websso/"

    cp $DEST/keystone/etc/sso_callback_template.html /etc/keystone/

    if [[ "$WSGI_MODE" == "uwsgi" ]]; then
        restart_service "devstack@keystone"
    fi

    if [[ "$OIDC_ISSUER_BASE" == "https://$HOST_IP:8443/realms/master" ]]; then
        # Assuming we want to setup a local keycloak here.
        sed -i "s#DEVSTACK_DEST#${DATA_DIR}#" ${OIDC_PLUGIN}/tools/oidc/docker-compose.yaml
        sudo docker-compose --file ${OIDC_PLUGIN}/tools/oidc/docker-compose.yaml up -d

        # wait for the server to be up
        attempt_counter=0
        max_attempts=100
        until $(curl --output /dev/null --silent --fail $OIDC_METADATA_URL); do
            if [ ${attempt_counter} -eq ${max_attempts} ];then
                echo "Keycloak server failed to come up in time"
                exit 1
            fi

            attempt_counter=$(($attempt_counter+1))
            sleep 5
        done

        KEYCLOAK_URL="https://$HOST_IP:8443" \
            KEYCLOAK_USERNAME="admin" \
            KEYCLOAK_PASSWORD="nomoresecret" \
            HOST_IP="$HOST_IP" \
            python3 $OIDC_PLUGIN/tools/oidc/setup_keycloak_client.py
    fi

    local keystone_apache_conf=$(apache_site_config_for keystone-api)
    cat $OIDC_PLUGIN/files/oidc/apache_oidc.conf | sudo tee -a $keystone_apache_conf
    sudo sed -i -e "
        s|%OIDC_CLIENT_ID%|$OIDC_CLIENT_ID|g;
        s|%OIDC_CLIENT_SECRET%|$OIDC_CLIENT_SECRET|g;
        s|%OIDC_METADATA_URL%|$OIDC_METADATA_URL|g;
        s|%OIDC_INTROSPECTION_URL%|$OIDC_INTROSPECTION_URL|g;
        s|%HOST_IP%|$HOST_IP|g;
        s|%IDP_ID%|$IDP_ID|g;
    " $keystone_apache_conf

    restart_apache_server
}

function register_federation {
    local federated_domain=$(get_or_create_domain $DOMAIN_NAME)
    local federated_project=$(get_or_create_project $PROJECT_NAME $DOMAIN_NAME)
    local federated_users=$(get_or_create_group $GROUP_NAME $DOMAIN_NAME)

    openstack role add --group $federated_users --domain $federated_domain member
    openstack role add --group $federated_users --project $federated_project member

    openstack identity provider create \
        --remote-id $OIDC_ISSUER_BASE \
        --domain $DOMAIN_NAME $IDP_ID
}

function configure_tests_settings {
    # Here we set any settings that might be need by the fed_scenario set of tests
    iniset $TEMPEST_CONFIG identity-feature-enabled federation True

    # we probably need an oidc version of this flag based on local oidc
    iniset $TEMPEST_CONFIG identity-feature-enabled external_idp True

    # Identity provider settings
    iniset $TEMPEST_CONFIG fed_scenario idp_id $IDP_ID
    iniset $TEMPEST_CONFIG fed_scenario idp_remote_ids $OIDC_ISSUER_BASE
    iniset $TEMPEST_CONFIG fed_scenario idp_username $IDP_USERNAME
    iniset $TEMPEST_CONFIG fed_scenario idp_password $IDP_PASSWORD
    iniset $TEMPEST_CONFIG fed_scenario idp_oidc_url $OIDC_ISSUER
    iniset $TEMPEST_CONFIG fed_scenario idp_client_id $OIDC_CLIENT_ID
    iniset $TEMPEST_CONFIG fed_scenario idp_client_secret $OIDC_CLIENT_SECRET

    # Mapping rules settings
    iniset $TEMPEST_CONFIG fed_scenario mapping_remote_type $MAPPING_REMOTE_TYPE
    iniset $TEMPEST_CONFIG fed_scenario mapping_user_name $MAPPING_USER_NAME
    iniset $TEMPEST_CONFIG fed_scenario mapping_group_name $GROUP_NAME
    iniset $TEMPEST_CONFIG fed_scenario mapping_group_domain_name $DOMAIN_NAME
    iniset $TEMPEST_CONFIG fed_scenario enable_k2k_groups_mapping False

    # Protocol settings
    iniset $TEMPEST_CONFIG fed_scenario protocol_id $PROTOCOL_ID
}

function uninstall_federation {
    # Ensure Keycloak is stopped and the containers are cleaned up
     sudo docker-compose --file ${OIDC_PLUGIN}/tools/oidc/docker-compose.yaml down
    if is_ubuntu; then
        sudo docker rmi $(sudo docker images -a -q)
        uninstall_package docker-compose
    elif is_fedora; then
        sudo podman rmi $(sudo podman images -a -q)
        uninstall_package podman
    else
        echo "Skipping uninstallation of OIDC federation for non ubuntu nor fedora nor suse host"
    fi
}

