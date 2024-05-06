<#
	.SYNOSPIS
	This script will load and rewrite an XML file to indent it with tab.
	
	.PARAMETER XmlFile
	Path to the xml file.
	
	.NOTES
	Version 02.00 by Loic VEIRMAN MSSec
#>
function Format-XmlFile {
	param(
		[Parameter(Mandatory = $True)]
		[String]
		$XmlFile,
		[Parameter(Mandatory = $True)]
		[Int]
		$Indent = 1
	)

	# Prepare the XML handler object
	$StringWriter = New-Object System.IO.StringWriter
	$XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
	
	# Configure the XML handler with our specific formatting expectation
	$xmlWriter.Formatting = 'indented'
	$xmlWriter.Indentation = $Indent
	$xmlWriter.IndentChar = "`t"
	# Reformatting the XML...
	$xml.WriteContentTo($XmlWriter)
	$XmlWriter.Flush()
	$StringWriter.Flush()
	# Returning result.
	return $StringWriter.ToString()
}

<#
#.Check if file exists.
if (Test-Path $XmlFile) {
	$FilePath = (resolve-path $XmlFile).Path
	$myXML = [XML](Get-Content $FilePath -encoding UTF8)
	
	#.Save file
	Try {
		Format-XML $myXml | Out-File $FilePath -Encoding utf8 -Force
		Write-Host "+++ File $FilePath saved successfully." -foregroundColor Green
	}
 Catch {
		Write-Host "!!! File $FilePath could not be saved!" -foregroundColor Red
	}
}
else {
	Write-Host "Error: " -foregroundColor Red -NoNewLine
	Write-Host "File not found!" -foregroundColor Yellow
}
#>