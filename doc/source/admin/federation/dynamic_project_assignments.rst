..
    Licensed under the Apache License, Version 2.0 (the "License"); you may not
    use this file except in compliance with the License. You may obtain a copy
    of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
    License for the specific language governing permissions and limitations
    under the License.


Dynamic project assignments
===========================

-----------
Description
-----------

The keystone federation, until the schema ``federation_attribute_mapping_schema_version == 2.0``, will only allow a static project assignment definition. Therefore, from the IdP, attributes are released (during the authentication process) for the authorization process in Keystone (which implies in project assignments). Keystone uses the attributes released from the IdP, such as username, project name, and others to assign users to projects with given roles. However, the processing of identity federation mappings are rather static and limited, see [1] and [2] for more contextual information.

The ``federation_attribute_mapping_schema_version == 3.0``, introduced with [3], enables operators to configure Keystone in a more dynamic and integrated fashion with IdPs. As follows, we present the use case for such a feature.

Let's imagine we want to also manage user and role assignment in the IdP, and make it (the IdP) the source of truth, not just for the authentication process, but also for the authorization process in Keystone (with respect to user assignment to projects). To achieve that, we would need to manage/control the role assignment in the IdP, and then release the needed attributes to Keystone, where the authorization process is then executed/processed.

Operators can adopt any IdP they wish, but we will assume that one is using Keycloak as the IdP for the identity federation to be used with Keystone acting as the SP. We can organize role assignment in Keycloak as a user attribute (let's call this user attribute as ``openstack-projects``), where role assignments of a user into projects are defined in the following pattern. Keycloak support list of data in attributes; therefore, a single attribute can hold a list of elements with the given pattern.

.. code-block:: none

    <openstack_domain_name>.<openstack_project_name>.<openstack_role_name>


By adopting the pattern to assign the role ``A`` and ``B`` for a user in project ``proj1`` of domain ``domain1``, we would define the items of the attribute that is used in Keycloak to hold the data as follows:

.. code-block:: none

    domain1.proj1.A
    domain1.proj1.B

The management of these properties in Keycloak can be handled by other systems that are connected in Keycloak, but that is out of the scope of this explanation.

Operators can configure Keycloak to generate an attribute, to be disseminated to the SP (Keystone), using attribute mappers; one can create an attribute mapper, for instance, called ``openstack-projects-client-mapper``, which can be a token claim in the IdP response to Keystone, when configuring the integration with OpenID Connect. The same is true if using SAML; someone can configure Keycloak to generate this attribute as well to be added in the SAML response for the SP.

As follows, we detail how to configure Keycloak and Keystone to make this integration work. Not all of the explanation is presented here, but if someone is missing some other detail, we can increment the explanation presented here.

----------------------
Keycloak configuration
----------------------

To enable Keycloak to generate complex attributes in the response for the SP, one would need to use the script mapper feature. The Keycloak script mappers are scripts injected into the Keycloak container during the build process that are made available for operators to configure the Keycloak client (SP) mapper.

Keycloak requires a JAR file to be generated with the script (which is developed in Javascript language). To generate this JAR file, we are assuming the following folder structure:

.. code-block:: none

    <base_folder>/<jar_file_folder_name>/META-INF/

Inside the ``<jar_file_folder_name>``, one can create a file called ``openstack-attribute-mapper.js`` (you can adapt the name as you wish), which is the actual script executed by Keycloak to generate the custom attribute.

The content of ``<base_folder>/<jar_file_folder_name>/META-INF/keycloak-scripts.json`` should be the following JSON structure:

.. code-block:: json

    {
      "providers" : {
        "mappers" : [ {
          "name" : "Name of the script that will be visible in Keycloak to configure the attribute mapper in the Keycloak client",
          "fileName" : "openstack-attribute-mapper.js",
          "description": "Some description that one can use"
        } ]
      }
    }

The content of the script ``openstack-attribute-mapper.js``, can be something like the following:

.. code-block:: javascript

    /**
     * Available variables:
     * user - the current user
     * realm - the current realm
     * token - the current token
     * userSession - the current userSession
     * keycloakSession - the current userSession
     */

    print("Starting the processing of the OpenStack projects attribute mapper.");

    var openstack_projects = user.getAttributeStream("openstack-projects").toArray();
    print("Value for 'openstack-projects' is: " + openstack_projects);
    print("Size for 'openstack-projects' is: " + openstack_projects.length);

    var arrayLength = openstack_projects.length;

    // We need to "unbind" the element from Java to JS. That is why we create a new variable here.
    var all_openstack_projects_javascript_variable = [];
    for (var i = 0; i < arrayLength; i++) {
        all_openstack_projects_javascript_variable.push(openstack_projects[i])
        print("Position "+ i + " for 'openstack-projects' is: " + all_openstack_projects_javascript_variable[i]);
    }

    print("Size for 'all_openstack_projects_javascript_variable' is: " + all_openstack_projects_javascript_variable.length);
    var all_projects_dictionary = {};
    if (all_openstack_projects_javascript_variable && all_openstack_projects_javascript_variable.length > 0){
        all_openstack_projects_javascript_variable.forEach(function(openstack_project, index){
            var project_and_role_and_maybe_domain = openstack_project.split(".");
            current_index = 0;
            var domain = "";
            if (project_and_role_and_maybe_domain.length > 2) {
                domain = project_and_role_and_maybe_domain[current_index];
                current_index +=1;
            }
            var project = project_and_role_and_maybe_domain[current_index];
            current_index +=1
            var role = project_and_role_and_maybe_domain[current_index];
            var map_key = domain;
            if (domain) {
                map_key = map_key + "-" + project;
            } else {
                map_key = project;
            }
            if (!all_projects_dictionary[map_key]){
                project_object = {"name": project, "roles": []};
                 if (domain) {
                    project_object["domain"] = {"name": domain}
                 }
                all_projects_dictionary[map_key] = project_object
            }
            all_projects_dictionary[map_key]["roles"].push({"name": role});
        });
    }

    print("All of the projects dictionary: [" + JSON.stringify(all_projects_dictionary) + "].")

    all_projects_list = [];
    all_keys = Object.keys(all_projects_dictionary);
    all_keys.forEach(function(key, index){
        all_projects_list.push(all_projects_dictionary[key]);
    });


    print("Projects and permissions to be disseminated to Keystone: [" + JSON.stringify(all_projects_list) + "].")
    exports = JSON.stringify(all_projects_list);

The above script will assume an attribute structure that may not have a domain defined; therefore, instead of ``<openstack_domain_name>.<openstack_project_name>.<openstack_role_name>``, one might have ``<openstack_project_name>.<openstack_role_name>``. Also, we assume that if the user has multiple roles in the same project, we will repeat the entries in the attribute list in Keycloak. Therefore, we need to handle all of these situations when processing all attributes and generating the JSON structure needed for Keystone.

It is important to mention that the script can be simplified and used to generate the JSON as needed. One can work with different data structure in Keycloak, and generate the message required by Keystone. The most important part it ``exports = JSON.stringify(all_projects_list)``, which is the part of the code that generate the JSON string that will be sent to Keystone, after the authentication process.

To build the JAR file one could use the following commands:

.. code-block:: bash

   cd <jar_file_folder_name>
   jar cf <jar_file_folder_name>.jar *

The JAR built needs to be included in the Keycloak container, when it is built. To build Keycloak, one could use the following Dockerfile (we are using version ``22.0.5``, because that is the latest version we validated this feature):

.. code-block:: none

    FROM quay.io/keycloak/keycloak:22.0.5 as builder

    # Enable health and metrics support
    ENV KC_HEALTH_ENABLED=true
    ENV KC_METRICS_ENABLED=true

    # Configure a database vendor
    ENV KC_DB=mysql
    ENV KC_CONFIG_FILE=/opt/keycloak/conf/keycloak.conf

    WORKDIR /opt/keycloak

    COPY <base_folder>/<jar_file_folder_name>/<jar_file_folder_name>.jar /opt/keycloak/providers/<jar_file_folder_name>.jar

    RUN /opt/keycloak/bin/kc.sh build --features="scripts"

    FROM quay.io/keycloak/keycloak:latest

    COPY --from=builder /opt/keycloak/ /opt/keycloak/

    ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]

With this Keycloak container, somebody should be able to see a "built in" attribute mapper that is able to generate the custom project JSON string that Keystone would need to execute dynamic project assignment with IdP data. It is important to mention here that one should read and take the information here as simple examples, and adapt to the context where they are working on.

----------------------
Keystone configuration
----------------------

After configuring the IdP (Keycloak) in our example, one can register the attribute mapping in Keystone with the following structure.

.. code-block:: json

    [
      {
        "local": [
          {
            "user": {
              "name": "{0}",
              "email": "{1}",
              "type": "ephemeral",
              "domain": {
                "name": "{2}"
              }
            },
            "domain": {
              "name": "{2}"
            },
            "projects_json": "{3}"
          }
        ],
        "remote": [
          {
            "type": "OIDC-preferred_username"
          },
          {
            "type": "OIDC-email"
          },
          {
            "type": "OIDC-openstack-user-domain"
          },
          {
            "type": "OIDC-openstack-projects-client-mapper"
          }
        ]
      }
    ]

In the above example of attribute mapping, we have the property ``OIDC-openstack-projects-client-mapper``, which is the JSON string that is being generated in Keycloak with the user attributes. This JSON string is then assigned to the `projects_json` option of the mapper.

Moreover, we are presenting a complete mapper, where we also received from the IdP the default domain of the user. Therefore, if a role assignment comes without the domain specified, the default domain is the one used. And last, but not least, the user data, such as username and email address that are used to create/bind the user in Keystone.

The ``OIDC`` string is appended in the attribute names that come from the IdP by the ``ModOIDC``, which is executed in the Apache HTTPD that sits in front of Keystone and handles the identity federation integration.

[1] https://bugs.launchpad.net/keystone/+bug/1887515

[2] https://bugs.launchpad.net/keystone/+bug/1888412

[3] https://review.opendev.org/c/openstack/keystone/+/742235
