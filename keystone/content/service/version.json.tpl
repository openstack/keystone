{
    "version" : {
        "id" : "v{{API_VERSION}}",
        "status" : "{{API_VERSION_STATUS}}",
        "updated" : "{{API_VERSION_DATE}}",
        "links": [
            {
                "rel" : "self",
                "href" : "http://{{HOST}}:{{PORT}}/v2.0/"
            },
            {
                "rel" : "describedby",
                "type" : "text/html",
                "href" : "http://docs.openstack.org/api/openstack-identity-service/{{API_VERSION}}/content/"
            },
            {
                "rel" : "describedby",
                "type" : "application/pdf",
                "href" : "http://docs.openstack.org/api/openstack-identity-service/{{API_VERSION}}/identity-dev-guide-{{API_VERSION}}.pdf"
            },
            {
                "rel" : "describedby",
                "type" : "application/vnd.sun.wadl+xml",
                "href" : "http://{{HOST}}:{{PORT}}/v2.0/identity.wadl"
            }
        ],
        "media-types": [
            {
                "base" : "application/xml",
                "type" : "application/vnd.openstack.identity-v2.0+xml"
            },
            {
                "base" : "application/json",
                "type" : "application/vnd.openstack.identity-v2.0+json"
            }
        ]
    }
}
