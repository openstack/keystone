<?xml version="1.0" encoding="UTF-8"?>

<transform xmlns="http://www.w3.org/1999/XSL/Transform"
           xmlns:echo="http://docs.openstack.org/echo/api/v1.0"
           version="1.0">
    <output method="text" encoding="UTF-8"/>

    <template match="echo:echo">
        <text>{ "echo" : { </text>
        <apply-templates  select="@*"/>
        <text>,</text>
        <apply-templates />
        <text>}}</text>
    </template>

    <template match="echo:content">
        <text>"content" : {</text>
        <apply-templates select="@*"/>
        <text>, "value" : "</text>
        <apply-templates />
        <text>" }</text>
    </template>

    <template match="@*">
        <if test="position() != 1">
            <text>,</text>
        </if>
        <text>"</text>
        <value-of select="name()"/>
        <text>" : "</text>
        <value-of select="."/>
        <text>"</text>
    </template>

    <template match="text()">
        <variable name="noeol"   select="translate(string(.),'&#x000a;','')"/>
        <variable name="noquote" select="translate($noeol,'&quot;',&quot;&apos;&quot;)"/>
        <value-of select="$noquote"/>
    </template>

</transform>
