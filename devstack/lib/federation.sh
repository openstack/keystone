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


IDP_ID=${IDP_ID:-testshib}


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

function upload_sp_metadata {
    local metadata_fname=${HOST_IP//./}_"$RANDOM"_sp
    local metadata_url=http://$HOST_IP/Shibboleth.sso/Metadata

    wget $metadata_url -O $FILES/$metadata_fname
    if [[ $? -ne 0 ]]; then
        echo "Not found: $metadata_url"
        return
    fi

    curl --form userfile=@"$FILES/${metadata_fname}" "https://www.testshib.org/procupload.php"
}

function configure_federation {
    local keystone_apache_conf=$(apache_site_config_for keystone)

    # Add WSGIScriptAlias directive to vhost configuration for port 5000
    sudo sed -i -e "
        /<VirtualHost \*:5000>/r $KEYSTONE_PLUGIN/files/federation/shib_apache_alias.txt
    " $keystone_apache_conf

    # Append to the keystone.conf vhost file a <Location> directive for the Shibboleth module
    # and a <Location> directive for the identity provider
    cat $KEYSTONE_PLUGIN/files/federation/shib_apache_handler.txt | sudo tee -a $keystone_apache_conf
    sudo sed -i -e "s|%IDP_ID%|$IDP_ID|g;" $keystone_apache_conf

    # Copy a templated /etc/shibboleth/shibboleth2.xml file...
    sudo cp $KEYSTONE_PLUGIN/files/federation/shibboleth2.xml /etc/shibboleth/shibboleth2.xml
    # ... and replace the %HOST_IP% placeholder with the host ip
    sudo sed -i -e "s|%HOST_IP%|$HOST_IP|g;" /etc/shibboleth/shibboleth2.xml

    restart_service shibd

    # Enable the mapped auth method in /etc/keystone.conf
    iniset $KEYSTONE_CONF auth methods "external,password,token,mapped"

    # Specify the header that contains information about the identity provider
    iniset $KEYSTONE_CONF mapped remote_id_attribute "Shib-Identity-Provider"

    # Register the service provider
    upload_sp_metadata
}

function register_federation {
    local federated_domain=$(get_or_create_domain federated_domain)
    local federated_project=$(get_or_create_project federated_project federated_domain)
    local federated_users=$(get_or_create_group federated_users federated_domain)
    local member_role=$(get_or_create_role Member)

    openstack role add --group $federated_users --domain $federated_domain $member_role
    openstack role add --group $federated_users --project $federated_project $member_role
}

function uninstall_federation {
    if is_ubuntu; then
        uninstall_package libapache2-mod-shib2
        sudo rm -rf /etc/shibboleth
    else
        echo "Skipping uninstallation of shibboleth for non ubuntu host"
    fi
}
