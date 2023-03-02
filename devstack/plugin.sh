#!/usr/bin/env bash
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

KEYSTONE_PLUGIN=$DEST/keystone/devstack

if is_service_enabled keystone-saml2-federation; then
    source $KEYSTONE_PLUGIN/lib/federation.sh
elif is_service_enabled keystone-oidc-federation; then
    source $KEYSTONE_PLUGIN/lib/oidc.sh
fi

source $KEYSTONE_PLUGIN/lib/scope.sh

# For more information on Devstack plugins, including a more detailed
# explanation on when the different steps are executed please see:
# https://docs.openstack.org/devstack/latest/plugins.html

if [[ "$1" == "stack" && "$2" == "install" ]]; then
    # This phase is executed after the projects have been installed
    echo "Keystone plugin - Install phase"
    if is_service_enabled keystone-saml2-federation; then
        echo "installing saml2 federation"
        install_federation
    elif is_service_enabled keystone-oidc-federation; then
        echo "installing oidc federation"
        install_federation
    fi

elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    # This phase is executed after the projects have been configured and
    # before they are started
    echo "Keystone plugin - Post-config phase"
    if is_service_enabled keystone-saml2-federation; then
        echo "configuring saml2 federation"
        configure_federation
    elif is_service_enabled keystone-oidc-federation; then
        echo "configuring oidc federation"
        configure_federation
    fi

elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
    # This phase is executed after the projects have been started
    echo "Keystone plugin - Extra phase"
    if is_service_enabled keystone-saml2-federation; then
        echo "registering saml2 federation"
        register_federation
    elif is_service_enabled keystone-oidc-federation; then
        echo "registering oidc federation"
        register_federation
    fi

elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
    # This phase is executed after Tempest was configured
    echo "Keystone plugin - Test-config phase"
    if is_service_enabled keystone-saml2-federation; then
        echo "config tests settings for saml"
        configure_tests_settings
    elif is_service_enabled keystone-oidc-federation; then
        echo "config tests settings for oidc"
        configure_tests_settings
    fi
    if [[ "$(trueorfalse False KEYSTONE_ENFORCE_SCOPE)" == "True" ]] ; then
        # devstack and tempest assume enforce_scope is false, so need to wait
        # until the final phase to turn it on
        configure_enforce_scope
        configure_protection_tests
    fi
fi

if [[ "$1" == "unstack" ]]; then
    # Called by unstack.sh and clean.sh
    # Undo what was performed during the "post-config" and "extra" phases
    :
fi

if [[ "$1" == "clean" ]]; then
    # Called by clean.sh after the "unstack" phase
    # Undo what was performed during the "install" phase
    if is_service_enabled keystone-saml2-federation; then
        echo "uninstalling saml"
        uninstall_federation
    elif is_service_enabled keystone-oidc-federation; then
        echo "uninstalling oidc"
        uninstall_federation
    fi
fi
