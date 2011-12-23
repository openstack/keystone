<?xml version="1.0" encoding="utf-8"?>
<choices
	xmlns="http://docs.openstack.org/common/api/v1.0"
	xmlns:atom="http://www.w3.org/2005/Atom">
	<version id="v{{API_VERSION}}" status="{{API_VERSION_STATUS}}">
		<media-types>
			<media-type
				base="application/xml"
				type="application/vnd.openstack.identity+xml;version={{API_VERSION}}" />
			<media-type
				base="application/json"
				type="application/vnd.openstack.identity+json;version={{API_VERSION}}" />
		</media-types>
		<atom:link rel="self" href="{{PROTOCOL}}://{{HOST}}:{{PORT}}/v{{API_VERSION}}{{RESOURCE_PATH}}" />
	</version>
</choices>