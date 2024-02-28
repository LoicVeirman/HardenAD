<#
	.SYNOSPIS
	This script will load and rewrite an XML file to indent it with tab.
	
	.PARAMETER XmlFile
	Path to the xml file.
	
	.NOTES
	Version 01.00 by Loic VEIRMAN MSSec
#>

param(
	[Parameter(Mandatory=$True)]
	[String]
	$XmlFile
)

#.Function
function Format-XML ([xml]$xml, $indent=1)
{
	$StringWriter = New-Object System.IO.StringWriter
	$XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
	$xmlWriter.Formatting = "indented"
	$xmlWriter.Indentation = $Indent
	$xmlWriter.IndentChar = "`t"
	$xml.WriteContentTo($XmlWriter)
	$XmlWriter.Flush()
	$StringWriter.Flush()
	return $StringWriter.ToString()
}

#.Check if file exists.
if (Test-Path $XmlFile) 
{
	$FilePath = (resolve-path $XmlFile).Path
	$myXML    = [XML](Get-Content $FilePath -encoding UTF8)
	
	#.Save file
	Try {
		Format-XML $myXml | Out-File $FilePath -Encoding utf8 -Force
		Write-Host "+++ File $FilePath saved successfully." -foregroundColor Green
	} Catch {
		Write-Host "!!! File $FilePath could not be saved!" -foregroundColor Red
	}
}
else
{
	Write-Host "Error: " -foregroundColor Red -NoNewLine
	Write-Host "File not found!" -foregroundColor Yellow
}