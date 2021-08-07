<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:import href="KDBX_Common.xsl" />
<xsl:output method="xml" encoding="UTF-8" omit-xml-declaration="yes" indent="no" />

<xsl:template match="/">
	<xsl:apply-templates select="KeePassFile" />
</xsl:template>

<xsl:template match="KeePassFile">
	<xsl:copy-of select="$HtmlHeader" />
	<head><xsl:copy-of select="$nl" />
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" /><xsl:copy-of select="$nl" />
		<xsl:apply-templates select="Meta" />
		<xsl:copy-of select="$DocStyle" />
	</head><xsl:copy-of select="$nl" />
	<body><xsl:copy-of select="$nl" />

	<xsl:apply-templates select="Root" />

	</body><xsl:copy-of select="$nl" />
	<xsl:copy-of select="$HtmlFooter" />
</xsl:template>

<xsl:template match="Meta">
	<title>
		<xsl:if test="DatabaseName != ''">
			<xsl:value-of select="DatabaseName" />
		</xsl:if>
		<xsl:if test="DatabaseName = ''">
			<xsl:text>Database</xsl:text>
		</xsl:if>
	</title><xsl:copy-of select="$nl" />
</xsl:template>

<xsl:template match="Root">
	<xsl:apply-templates select="Group" />
</xsl:template>

<xsl:template match="Group">
	<xsl:apply-templates select="Entry" />
	<xsl:apply-templates select="Group" />
</xsl:template>

<xsl:template match="Entry">

<table class="tablebox"><xsl:copy-of select="$nl" />
<tr><th>
	<xsl:for-each select="String[Key = 'Title']">
		<xsl:value-of select="Value" />
	</xsl:for-each>
</th></tr><xsl:copy-of select="$nl" />

<tr><td><xsl:copy-of select="$nl" />

<!-- <xsl:for-each select="String[(Key = 'Title') and (Value != '')]">
	<i>Title: </i>
	<xsl:value-of select="Value" /><xsl:copy-of select="$brnl" />
</xsl:for-each> -->
<xsl:for-each select="String[(Key = 'UserName') and (Value != '')]">
	<i>User Name: </i>
	<xsl:value-of select="Value" /><xsl:copy-of select="$brnl" />
</xsl:for-each>
<xsl:for-each select="String[(Key = 'Password') and (Value != '')]">
	<i>Password: </i>
	<code><xsl:value-of select="Value" /></code><xsl:copy-of select="$brnl" />
</xsl:for-each>

<xsl:for-each select="String[(Key = 'URL') and (Value != '')]">
	<i>URL: </i>
	<xsl:element name="a">
		<xsl:attribute name="href">
			<xsl:value-of select="Value" />
		</xsl:attribute>
		<xsl:value-of select="Value" />
	</xsl:element>
	<xsl:copy-of select="$brnl" />
</xsl:for-each>

<xsl:for-each select="String[(Key = 'Notes') and (Value != '')]">
	<i>Notes: </i>
	<xsl:value-of select="Value" /><xsl:copy-of select="$brnl" />
</xsl:for-each>

<xsl:for-each select="String">
	<xsl:if test="Key != 'Title'">
	<xsl:if test="Key != 'UserName'">
	<xsl:if test="Key != 'Password'">
	<xsl:if test="Key != 'URL'">
	<xsl:if test="Key != 'Notes'">
		<i><xsl:value-of select="Key" />: </i>
		<xsl:value-of select="Value" />
		<xsl:copy-of select="$brnl" />
	</xsl:if>
	</xsl:if>
	</xsl:if>
	</xsl:if>
	</xsl:if>
</xsl:for-each>

<i>Creation Time: </i>
<xsl:value-of select="Times/CreationTime" />
<xsl:copy-of select="$brnl" />
<i>Last Modification Time: </i>
<xsl:value-of select="Times/LastModificationTime" />
<xsl:copy-of select="$brnl" />

<i>Expires: </i>
<xsl:if test="Times/Expires = 'True'">
	<xsl:value-of select="Times/ExpiryTime" />
</xsl:if>
<xsl:if test="Times/Expires != 'True'">
	<xsl:text>Never expires</xsl:text>
</xsl:if>
<xsl:copy-of select="$nl" />

</td></tr></table>
<xsl:copy-of select="$brnl" />

</xsl:template>

</xsl:stylesheet>
