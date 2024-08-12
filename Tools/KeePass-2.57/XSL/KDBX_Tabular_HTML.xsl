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
	<h2><xsl:value-of select="Name" /></h2><xsl:copy-of select="$nl" />

	<table class="tablebox"><xsl:copy-of select="$nl" />
	<tr><xsl:copy-of select="$nl" />
		<th>Title</th><xsl:copy-of select="$nl" />
		<th>User Name</th><xsl:copy-of select="$nl" />
		<th>Password</th><xsl:copy-of select="$nl" />
		<th>URL</th><xsl:copy-of select="$nl" />
		<th>Notes</th><xsl:copy-of select="$nl" />
	</tr><xsl:copy-of select="$nl" />

	<xsl:apply-templates select="Entry" />

	</table><xsl:copy-of select="$nl" />

	<xsl:for-each select="Group">
		<xsl:text disable-output-escaping="yes"><![CDATA[<p><small>&nbsp;</small></p>]]></xsl:text>
		<xsl:copy-of select="$nl" />
		<xsl:apply-templates select="." />
	</xsl:for-each>
</xsl:template>

<xsl:template match="Entry">
	<tr>
	<td>
		<xsl:for-each select="String[(Key = 'Title') and (Value != '')]">
			<xsl:value-of select="Value" />
		</xsl:for-each>
	</td><xsl:copy-of select="$nl" />
	<td>
		<xsl:for-each select="String[(Key = 'UserName') and (Value != '')]">
			<xsl:value-of select="Value" />
		</xsl:for-each>
	</td><xsl:copy-of select="$nl" />
	<td>
		<xsl:for-each select="String[(Key = 'Password') and (Value != '')]">
			<code><xsl:value-of select="Value" /></code>
		</xsl:for-each>
	</td><xsl:copy-of select="$nl" />

	<td>
		<xsl:for-each select="String[(Key = 'URL') and (Value != '')]">
			<xsl:element name="a">
				<xsl:attribute name="href">
					<xsl:value-of select="Value" />
				</xsl:attribute>
				<xsl:value-of select="Value" />
			</xsl:element>
		</xsl:for-each>
	</td><xsl:copy-of select="$nl" />

	<td>
		<xsl:for-each select="String[(Key = 'Notes') and (Value != '')]">
			<xsl:value-of select="Value" />
		</xsl:for-each>
	</td><xsl:copy-of select="$nl" />
	</tr><xsl:copy-of select="$nl" />
</xsl:template>

</xsl:stylesheet>
