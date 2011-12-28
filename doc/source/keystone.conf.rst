..
      Copyright 2011 OpenStack, LLC
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

keystone.conf example
=====================
::

    [DEFAULT]
    # Show more verbose log output (sets INFO log level output)
    verbose = False

    # Show debugging output in logs (sets DEBUG log level output)
    debug = False

    # Which backend store should Keystone use by default.
    # Default: 'sqlite'
    # Available choices are 'sqlite' [future will include LDAP, PAM, etc]
    default_store = sqlite

    # Log to this file. Make sure you do not set the same log
    # file for both the API and registry servers!
    log_file = %DEST%/keystone/keystone.log

    # List of backends to be configured
    backends = keystone.backends.sqlalchemy
    #For LDAP support, add: ,keystone.backends.ldap

    # Dictionary Maps every service to a header.Missing services would get header
    # X_(SERVICE_NAME) Key => Service Name, Value => Header Name
    service-header-mappings = {
        'nova' : 'X-Server-Management-Url',
        'swift' : 'X-Storage-Url',
        'cdn' : 'X-CDN-Management-Url'}

	#List of extensions currently loaded.
	#Refer docs for list of supported extensions. 
	extensions= osksadm,oskscatalog
  
    # Address to bind the API server
    # TODO Properties defined within app not available via pipeline.
    service_host = 0.0.0.0

    # Port the bind the API server to
    service_port = 5000

    # Address to bind the Admin API server
    admin_host = 0.0.0.0

    # Port the bind the Admin API server to
    admin_port = 35357

    #Role that allows to perform admin operations.
    keystone-admin-role = KeystoneAdmin

    #Role that allows to perform service admin operations.
    keystone-service-admin-role = KeystoneServiceAdmin

    [keystone.backends.sqlalchemy]
    # SQLAlchemy connection string for the reference implementation registry
    # server. Any valid SQLAlchemy connection string is fine.
    # See: http://bit.ly/ideIpI
    #sql_connection = sqlite:///keystone.db
    sql_connection = %SQL_CONN%
    backend_entities = ['UserRoleAssociation', 'Endpoints', 'Role', 'Tenant',
                        'User', 'Credentials', 'EndpointTemplates', 'Token',
                        'Service']

    # Period in seconds after which SQLAlchemy should reestablish its connection
    # to the database.
    sql_idle_timeout = 30

    [pipeline:admin]
    pipeline =
        urlnormalizer
        d5_compat
        admin_api

    [pipeline:keystone-legacy-auth]
    pipeline =
        urlnormalizer
        legacy_auth
        d5_compat
        service_api

    [app:service_api]
    paste.app_factory = keystone.server:service_app_factory

    [app:admin_api]
    paste.app_factory = keystone.server:admin_app_factory

    [filter:urlnormalizer]
    paste.filter_factory = keystone.frontends.normalizer:filter_factory

    [filter:legacy_auth]
    paste.filter_factory = keystone.frontends.legacy_token_auth:filter_factory

    [filter:d5_compat]
    paste.filter_factory = keystone.frontends.d5_compat:filter_factory

