{
    "version" : {
        "id" : "v1.0",
        "status" : "{{VERSION_STATUS}}",
        "updated" : "{{VERSION_DATE}}",
        "links": [
            {
                "rel" : "self",
                "href" : "http://{{HOST}}:{{PORT}}/v1.0/"
            },
            {
                "rel" : "describedby",
                "type" : "application/pdf",
                "href" : "http://{{HOST}}:{{PORT}}/v1.0/idmdevguide.pdf"
            },
            {
                "rel" : "describedby",
                "type" : "application/vnd.sun.wadl+xml",
                "href" : "http://{{HOST}}:{{PORT}}/v1.0/identity.wadl"
            }
        ],
        "media-types": [
            {
                "base" : "application/xml",
                "type" : "application/vnd.openstack.idm-v1.0+xml"
            },
            {
                "base" : "application/json",
                "type" : "application/vnd.openstack.idm-v1.0+json"
            }
        ]
    }
}
