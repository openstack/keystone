{
  "choices": [
    {
      "id": "v{{API_VERSION}}",
      "status": "{{API_VERSION_STATUS}}",
      "links": [
        {
          "rel": "self",
          "href": "{{PROTOCOL}}://{{HOST}}:{{PORT}}/v{{API_VERSION}}{{RESOURCE_PATH}}"
        }
      ],
      "media-types": {
        "values": [
          {
            "base": "application/xml",
            "type": "application/vnd.openstack.identity+xml;version={{API_VERSION}}"
          },
          {
            "base": "application/json",
            "type": "application/vnd.openstack.identity+json;version={{API_VERSION}}"
          }
        ]
      }
    }
  ]
}