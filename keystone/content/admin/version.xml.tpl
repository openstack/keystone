<?xml version="1.0" encoding="UTF-8"?>
<version xmlns="http://docs.openstack.org/common/api/v2.0"
         xmlns:atom="http://www.w3.org/2005/Atom"
         id="v2.0" status="{{VERSION_STATUS}}" updated="{{VERSION_DATE}}">

    <media-types>
        <media-type base="application/xml"
                    type="application/vnd.openstack.identity-v2.0+xml"/>
        <media-type base="application/json"
                    type="application/vnd.openstack.identity-v2.0+json"/>
    </media-types>

     <atom:link rel="self"
                href="http://{{HOST}}:{{PORT}}/v2.0/"/>

     <atom:link rel="describedby"
                type="application/pdf"
                href="http://{{HOST}}:{{PORT}}/v2.0/identitydevguide.pdf" />

     <atom:link rel="describedby"
                type="application/vnd.sun.wadl+xml"
                href="http://{{HOST}}:{{PORT}}/v2.0/identity-admin.wadl" />
</version>
