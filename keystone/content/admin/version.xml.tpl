<?xml version="1.0" encoding="UTF-8"?>
<version xmlns="http://docs.openstack.org/common/api/v2.0"
         xmlns:atom="http://www.w3.org/2005/Atom"
         id="v{{API_VERSION}}" status="{{API_VERSION_STATUS}}" updated="{{API_VERSION_DATE}}">

    <media-types>
        <media-type base="application/xml"
                    type="application/vnd.openstack.identity-v{{API_VERSION}}+xml"/>
        <media-type base="application/json"
                    type="application/vnd.openstack.identity-v{{API_VERSION}}+json"/>
    </media-types>

     <atom:link rel="self"
                href="http://{{HOST}}:{{PORT}}/v{{API_VERSION}}/"/>

     <atom:link rel="describedby"
                type="text/html"
                href="http://docs.openstack.org/api/openstack-identity-service/{{API_VERSION}}/content/" />

     <atom:link rel="describedby"
                type="application/pdf"
                href="http://docs.openstack.org/api/openstack-identity-service/{{API_VERSION}}/identity-dev-guide-{{API_VERSION}}.pdf" />

     <atom:link rel="describedby"
                type="application/vnd.sun.wadl+xml"
                href="http://{{HOST}}:{{PORT}}/v2.0/identity-admin.wadl" />
</version>
