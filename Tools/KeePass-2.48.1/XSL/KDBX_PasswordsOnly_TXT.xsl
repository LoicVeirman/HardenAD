<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text" encoding="UTF-8" omit-xml-declaration="yes" indent="no" />

<xsl:variable name="nl">
	<xsl:text>&#13;&#10;</xsl:text>
</xsl:variable>

<xsl:template match="/">
	<xsl:apply-templates select="KeePassFile" />
</xsl:template>

<xsl:template match="KeePassFile">
	<xsl:apply-templates select="Root" />
</xsl:template>

<xsl:template match="Root">
	<xsl:apply-templates select="Group" />
</xsl:template>

<xsl:template match="Group">
	<xsl:apply-templates select="Entry" />
	<xsl:apply-templates select="Group" />
</xsl:template>

<xsl:template match="Entry">
	<xsl:for-each select="String[(Key = 'Password') and (Value != '')]">
		<xsl:value-of select="Value" />
		<xsl:copy-of select="$nl" />
	</xsl:for-each>
</xsl:template>

</xsl:stylesheet>
