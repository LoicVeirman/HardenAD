<#
	.SYNOSPIS
	This script will load and rewrite an XML file to indent it with tab.
	
	.PARAMETER XmlFile
	Path to the xml file.
	
	.NOTES
	Version 02.00 by Loic VEIRMAN MSSec
#>
function Format-XMLFile {
	param(
		[Parameter(Mandatory = $True, Position = 0)]
		[String]
		$XMLFile
	)

	try {
		Test-Path $XMLFile -ErrorAction Stop
	}
	catch {
		Write-Host "Error: " -ForegroundColor Red -NoNewLine
		Write-Host "$XMLFile - File not found!" -ForegroundColor Yellow
		return
	}

	# Load the XML file content
	$XMLFileContent = [XML](Get-Content $XMLFile -Encoding UTF8)

	# Format the XML content
	Format-XMLData -XMLData $XMLFileContent
}

function Format-XMLData {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True, Position = 0)]
		[XML]
		$XMLData
	)

	# Set the indentation level
	$Indent = 1
	
	# Prepare the XML handler object
	$stringWriter = New-Object System.IO.StringWriter
	$xmlWriter = New-Object System.XMl.XmlTextWriter $stringWriter
		
	# Configure the XML handler object with our specific formatting expectation
	$xmlWriter.Formatting = 'indented'
	$xmlWriter.Indentation = $Indent
	$xmlWriter.IndentChar = "`t"
		
	# refomating the XML file
	$XMLData.WriteContentTo($xmlWriter)
	$xmlWriter.Flush()
	$stringWriter.Flush()
		
	# return the formatted XML
	return $stringWriter.ToString()
}