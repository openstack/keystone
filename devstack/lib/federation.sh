# Copyright 2016 Massachusetts Open Cloud
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

DOMAIN_NAME=${DOMAIN_NAME:-federated_domain}
PROJECT_NAME=${PROJECT_NAME:-federated_project}
GROUP_NAME=${GROUP_NAME:-federated_users}

IDP_ID=${IDP_ID:-samltest}
IDP_USERNAME=${IDP_USERNAME:-morty}
IDP_PASSWORD=${IDP_PASSWORD:-panic}
IDP_REMOTE_ID=${IDP_REMOTE_ID:-https://samltest.id/saml/idp}
IDP_ECP_URL=${IDP_ECP_URL:-https://samltest.id/idp/profile/SAML2/SOAP/ECP}
IDP_METADATA_URL=${IDP_METADATA_URL:-https://samltest.id/saml/idp}

MAPPING_REMOTE_TYPE=${MAPPING_REMOTE_TYPE:-uid}
MAPPING_USER_NAME=${MAPPING_USER_NAME:-"{0}"}

PROTOCOL_ID=${PROTOCOL_ID:-mapped}

# File paths
FEDERATION_FILES="$KEYSTONE_PLUGIN/files/federation"
SHIBBOLETH_XML="/etc/shibboleth/shibboleth2.xml"
ATTRIBUTE_MAP="/etc/shibboleth/attribute-map.xml"

function configure_apache {
    if [[ "$WSGI_MODE" == "uwsgi" ]]; then
        local keystone_apache_conf=$(apache_site_config_for keystone-wsgi-public)

        echo "ProxyPass /Shibboleth.sso !" | sudo tee -a $keystone_apache_conf

    else
        local keystone_apache_conf=$(apache_site_config_for keystone)

        # Add WSGIScriptAlias directive to vhost configuration for port 5000
        sudo sed -i -e "
            /<VirtualHost \*:5000>/r $KEYSTONE_PLUGIN/files/federation/shib_apache_alias.txt
        " $keystone_apache_conf
    fi

    # Append to the keystone.conf vhost file a <Location> directive for the Shibboleth module
    # and a <Location> directive for the identity provider
    cat $KEYSTONE_PLUGIN/files/federation/shib_apache_handler.txt | sudo tee -a $keystone_apache_conf

    sudo sed -i -e "s|%IDP_ID%|$IDP_ID|g;" $keystone_apache_conf

    restart_apache_server
}

function install_federation {
    if is_ubuntu; then
        install_package libapache2-mod-shib2

        # Create a new keypair for Shibboleth
        sudo shib-keygen -f

        # Enable the Shibboleth module for Apache
        sudo a2enmod shib2
    else
        # NOTE(knikolla): For CentOS/RHEL, installing shibboleth is tricky
        # It requires adding a separate repo not officially supported
        echo "Skipping installation of shibboleth for non ubuntu host"
    fi
}

function upload_sp_metadata_to_samltest {
    local metadata_fname=${HOST_IP//./}_"$RANDOM"_sp
    local metadata_url=http://$HOST_IP/Shibboleth.sso/Metadata

    wget $metadata_url -O $FILES/$metadata_fname
    if [[ $? -ne 0 ]]; then
        echo "Not found: $metadata_url"
        return
    fi

    curl --form userfile=@"$FILES/${metadata_fname}" --form "submit=OK" "https://samltest.id/upload.php"
}

function configure_federation {
    configure_apache

    # Copy a templated /etc/shibboleth/shibboleth2.xml file...
    sudo cp $FEDERATION_FILES/shibboleth2.xml $SHIBBOLETH_XML
    # ... and replace the %HOST_IP%, %IDP_REMOTE_ID%,and %IDP_METADATA_URL% placeholders
    sudo sed -i -e "
        s|%HOST_IP%|$HOST_IP|g;
        s|%IDP_REMOTE_ID%|$IDP_REMOTE_ID|g;
        s|%IDP_METADATA_URL%|$IDP_METADATA_URL|g;
        " $SHIBBOLETH_XML

    sudo cp "$FEDERATION_FILES/attribute-map.xml" $ATTRIBUTE_MAP

    restart_service shibd

    # Enable the mapped auth method in /etc/keystone.conf
    iniset $KEYSTONE_CONF auth methods "external,password,token,mapped"

    # Specify the header that contains information about the identity provider
    iniset $KEYSTONE_CONF mapped remote_id_attribute "Shib-Identity-Provider"

    if [[ "$WSGI_MODE" == "uwsgi" ]]; then
        restart_service "devstack@keystone"
    fi

    # TODO(knikolla): We should not be relying on an external service. This
    # will be removed once we have an idp deployed during devstack install.
    if [[ "$IDP_ID" == "samltest" ]]; then
        upload_sp_metadata_to_samltest
    fi
}

function register_federation {
    local federated_domain=$(get_or_create_domain $DOMAIN_NAME)
    local federated_project=$(get_or_create_project $PROJECT_NAME $DOMAIN_NAME)
    local federated_users=$(get_or_create_group $GROUP_NAME $DOMAIN_NAME)
    local member_role=$(get_or_create_role Member)

    openstack role add --group $federated_users --domain $federated_domain $member_role
    openstack role add --group $federated_users --project $federated_project $member_role
}

function configure_tests_settings {
    # Here we set any settings that might be need by the fed_scenario set of tests
    iniset $TEMPEST_CONFIG identity-feature-enabled federation True

    # Identity provider settings
    iniset $TEMPEST_CONFIG fed_scenario idp_id $IDP_ID
    iniset $TEMPEST_CONFIG fed_scenario idp_remote_ids $IDP_REMOTE_ID
    iniset $TEMPEST_CONFIG fed_scenario idp_username $IDP_USERNAME
    iniset $TEMPEST_CONFIG fed_scenario idp_password $IDP_PASSWORD
    iniset $TEMPEST_CONFIG fed_scenario idp_ecp_url $IDP_ECP_URL

    # Mapping rules settings
    iniset $TEMPEST_CONFIG fed_scenario mapping_remote_type $MAPPING_REMOTE_TYPE
    iniset $TEMPEST_CONFIG fed_scenario mapping_user_name $MAPPING_USER_NAME
    iniset $TEMPEST_CONFIG fed_scenario mapping_group_name $GROUP_NAME
    iniset $TEMPEST_CONFIG fed_scenario mapping_group_domain_name $DOMAIN_NAME

    # Protocol settings
    iniset $TEMPEST_CONFIG fed_scenario protocol_id $PROTOCOL_ID
}

function uninstall_federation {
    if is_ubuntu; then
        uninstall_package libapache2-mod-shib2
    else
        echo "Skipping uninstallation of shibboleth for non ubuntu host"
    fi
}
