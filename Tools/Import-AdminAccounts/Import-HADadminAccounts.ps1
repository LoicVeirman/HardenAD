<#
    .SYNOPSIS
    This function will add to the <Accounts> section and all the CSV data.

    .DETAILS
    ** BEWARE ** Use it with caution! 
    This is not a production tool, it has only be designed to prepare customer environment.

    .PARAMETER AddText
    Accepted value are: "Before csv data" or "After csv data".
    This wil add to the Description and DisplayName data the text from the config.xml file.

    .NOTES
    Version 0.1 by loic.veirman@mssec.fr 
#>

Param(
    [Parameter(mandatory)]
    [ValidateSet('BeforeCSVdata','AfterCSVdata')]
    $AddText
)

function Format-XML ([xml]$xml, $indent=1)
{
    $StringWriter = New-Object System.IO.StringWriter
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
    $xmlWriter.Formatting = “indented”
    $xmlWriter.Indentation = $Indent
    $xmlWriter.IndentChar = "`t"
    $xml.WriteContentTo($XmlWriter)
    $XmlWriter.Flush()
    $StringWriter.Flush()
    return $StringWriter.ToString()
}

#.Load XML file
$Config = [xml](Get-Content .\config.xml -Encoding UTF8)

#.Load XML from Harden AD and keeping formating
$HADFil = Convert-Path '..\..\Configs\TasksSequence_HardenAD.xml'

#$HADxml = New-Object System.Xml.XmlDocument
#$HADxml.PreserveWhitespace = $true
#$HADxml.Load($HADFil)

$HADxml = [xml](Get-Content $HADFil -Encoding UTF8)

#.Load Section for accounts
$ACCnode = Select-Xml $HADxml -XPath "//*/Accounts" | Select-Object -ExpandProperty "Node"

#.Load section for groups
$GRPnode = Select-Xml $HADxml -XPath "//*/Groups"   | Select-Object -ExpandProperty "Node"

#.Parsing elements to add or modify
$Accounts = Import-Csv .\admins.csv -Delimiter ";" -Encoding UTF8

foreach ($Account in $Accounts)
{
    Write-Host "> Working on " -ForegroundColor Gray -NoNewline
    Write-Host $Account.DisplayName -ForegroundColor White

    $FirstName   = $Account.Prenom
    $LastName    = $Account.Nom

    #.refresh data
    $DescData = $Account.Description
    $DispData = $Account.DisplayName


    #.Checking if $Description is empty or not
    if ($DescData -eq '' -or -not($DescData))
    {
        #.Default value...
        $myLength = $FirstName.length - 1
        $DescData  = "COMPUTED - "
        $DescData += ($FirstName.substring(0,1)).ToUpper() + ($FirstName.substring(1,$myLength)).Tolower() + " "
        $DescData += $LastName.Toupper()
    }

    #.Checking if $DisplayName is empty or not
    if ($DispData -eq '' -or -not($DispData))
    {
        #.Default value...
        $DispData  = "(Unknown) "
        $DispData += ($FirstName.substring(0,1)).ToUpper() + ($FirstName.substring(1,$myLength)).Tolower() + " "
        $DispData += $LastName.Toupper()
    }

    #.Building Tier 0 Manager account
    if ($Account.T0M -ne '' -and $Account.T0M -ne $null)
    {
        #.refresh data
        $Description = $DescData
        $DisplayName = $DispData

        #.Computed Text to append
        $DescPLus = $Config.Settings.User.DisplayName.T0M
        $DispPLus = $Config.Settings.User.DisplayName.T0M

        Switch($AddText)
        {
            'BeforeCSVdata'
            { 
                $Description = $DescPLus + $Description
                $DisplayName = $dispPlus + $DisplayName
            }
            
            'AfterCSVdata'
            {
                $Description = $Description + $DescPLus
                $DisplayName = $DisplayName + $dispPlus
            }
        }

        #.Append new user to the file, if not already present.
        $isPresent = Select-Xml $HADxml -XPath "//*/Accounts/User[@samAccountName='$($Account.T0M)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Accounts" | Select-Object -ExpandProperty "Node"
            
            $NewChild = $HADxml.CreateElement("User")

            $null = $NewChild.SetAttribute("DisplayName"   ,$DisplayName)
            $null = $NewChild.SetAttribute("Surname"       ,$LastName)
            $null = $NewChild.SetAttribute("GivenName"     ,$FirstName)
            $null = $NewChild.SetAttribute("Description"   ,$Description)
            $null = $NewChild.SetAttribute("samAccountName",($Account.T0M).ToUpper())
            $null = $NewChild.SetAttribute("Path"          ,$Config.Settings.User.Path.T0M)

            $null = $Node.AppendChild($NewChild)
        }

        #.Append new user to groups, if not already present
        $isPresent = Select-Xml $HADxml -XPath "//*/Groups/Group/Member[@samAccountName='$($Account.T0M)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Group[@name='$($Config.Settings.Group.samAccountName.T0M)']" | Select-Object -ExpandProperty "Node"
                            
            $NewChild = $HADxml.CreateElement("Member")
            
            $null = $NewChild.SetAttribute("samAccountName",$($Account.T0M))

            $null = $Node.AppendChild($NewChild) 
        }
    }

    #.Building Tier 0 Operator account
    if ($Account.T0O -ne '' -and $Account.T0O -ne $null)
    {
        #.refresh data
        $Description = $DescData
        $DisplayName = $DispData

        #.Computed Text to append
        $DescPLus = $Config.Settings.User.DisplayName.T0O
        $DispPLus = $Config.Settings.User.DisplayName.T0O

        Switch($AddText)
        {
            'BeforeCSVdata'
            { 
                $Description = $DescPLus + $Description
                $DisplayName = $dispPlus + $DisplayName
            }
            
            'AfterCSVdata'
            {
                $Description = $Description + $DescPLus
                $DisplayName = $DisplayName + $dispPlus
            }
        }

        #.Append new user to the file, if not already present.
        $isPresent = Select-Xml $HADxml -XPath "//*/Accounts/User[@samAccountName='$($Account.T0O)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Accounts" | Select-Object -ExpandProperty "Node"
            
            $NewChild = $HADxml.CreateElement("User")

            $null = $NewChild.SetAttribute("DisplayName"   ,$DisplayName)
            $null = $NewChild.SetAttribute("Surname"       ,$LastName)
            $null = $NewChild.SetAttribute("GivenName"     ,$FirstName)
            $null = $NewChild.SetAttribute("Description"   ,$Description)
            $null = $NewChild.SetAttribute("samAccountName",($Account.T0O).ToUpper())
            $null = $NewChild.SetAttribute("Path"          ,$Config.Settings.User.Path.T0O)

            $null = $Node.AppendChild($NewChild)
        }

        #.Append new user to groups, if not already present
        $isPresent = Select-Xml $HADxml -XPath "//*/Groups/Group/Member[@samAccountName='$($Account.T0O)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Group[@name='$($Config.Settings.Group.samAccountName.T0O)']" | Select-Object -ExpandProperty "Node"
                            
            $NewChild = $HADxml.CreateElement("Member")
            
            $null = $NewChild.SetAttribute("samAccountName",$($Account.T0O))

            $null = $Node.AppendChild($NewChild) 
        }
    }

    #.Building Tier 1 Manager account
    if ($Account.T1M -ne '' -and $Account.T1M -ne $null)
    {
        #.refresh data
        $Description = $DescData
        $DisplayName = $DispData

        #.Computed Text to append
        $DescPLus = $Config.Settings.User.DisplayName.T1M
        $DispPLus = $Config.Settings.User.DisplayName.T1M

        Switch($AddText)
        {
            'BeforeCSVdata'
            { 
                $Description = $DescPLus + $Description
                $DisplayName = $dispPlus + $DisplayName
            }
            
            'AfterCSVdata'
            {
                $Description = $Description + $DescPLus
                $DisplayName = $DisplayName + $dispPlus
            }
        }

        #.Append new user to the file, if not already present.
        $isPresent = Select-Xml $HADxml -XPath "//*/Accounts/User[@samAccountName='$($Account.T1M)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Accounts" | Select-Object -ExpandProperty "Node"
            
            $NewChild = $HADxml.CreateElement("User")

            $null = $NewChild.SetAttribute("DisplayName"   ,$DisplayName)
            $null = $NewChild.SetAttribute("Surname"       ,$LastName)
            $null = $NewChild.SetAttribute("GivenName"     ,$FirstName)
            $null = $NewChild.SetAttribute("Description"   ,$Description)
            $null = $NewChild.SetAttribute("samAccountName",($Account.T1M).ToUpper())
            $null = $NewChild.SetAttribute("Path"          ,$Config.Settings.User.Path.T1M)

            $null = $Node.AppendChild($NewChild)
        }

        #.Append new user to groups, if not already present
        $isPresent = Select-Xml $HADxml -XPath "//*/Groups/Group/Member[@samAccountName='$($Account.T1M)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Group[@name='$($Config.Settings.Group.samAccountName.T1M)']" | Select-Object -ExpandProperty "Node"
                            
            $NewChild = $HADxml.CreateElement("Member")
            
            $null = $NewChild.SetAttribute("samAccountName",$($Account.T1M))

            $null = $Node.AppendChild($NewChild) 
        }
    }

    #.Building Tier 1 Administrator account
    if ($Account.T1A -ne '' -and $Account.T1A -ne $null)
    {
        #.refresh data
        $Description = $DescData
        $DisplayName = $DispData

        #.Computed Text to append
        $DescPLus = $Config.Settings.User.DisplayName.T1A
        $DispPLus = $Config.Settings.User.DisplayName.T1A

        Switch($AddText)
        {
            'BeforeCSVdata'
            { 
                $Description = $DescPLus + $Description
                $DisplayName = $dispPlus + $DisplayName
            }
            
            'AfterCSVdata'
            {
                $Description = $Description + $DescPLus
                $DisplayName = $DisplayName + $dispPlus
            }
        }

        #.Append new user to the file, if not already present.
        $isPresent = Select-Xml $HADxml -XPath "//*/Accounts/User[@samAccountName='$($Account.T1A)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Accounts" | Select-Object -ExpandProperty "Node"
            
            $NewChild = $HADxml.CreateElement("User")

            $null = $NewChild.SetAttribute("DisplayName"   ,$DisplayName)
            $null = $NewChild.SetAttribute("Surname"       ,$LastName)
            $null = $NewChild.SetAttribute("GivenName"     ,$FirstName)
            $null = $NewChild.SetAttribute("Description"   ,$Description)
            $null = $NewChild.SetAttribute("samAccountName",($Account.T1A).ToUpper())
            $null = $NewChild.SetAttribute("Path"          ,$Config.Settings.User.Path.T1A)

            $null = $Node.AppendChild($NewChild)
        }

        #.Append new user to groups, if not already present
        $isPresent = Select-Xml $HADxml -XPath "//*/Groups/Group/Member[@samAccountName='$($Account.T1A)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Group[@name='$($Config.Settings.Group.samAccountName.T1A)']" | Select-Object -ExpandProperty "Node"
                            
            $NewChild = $HADxml.CreateElement("Member")
            
            $null = $NewChild.SetAttribute("samAccountName",$($Account.T1A))

            $null = $Node.AppendChild($NewChild) 
        }
    }

    #.Building Tier 1 Operator account
    if ($Account.T1O -ne '' -and $Account.T1O -ne $null)
    {
        #.refresh data
        $Description = $DescData
        $DisplayName = $DispData

        #.Computed Text to append
        $DescPLus = $Config.Settings.User.DisplayName.T1O
        $DispPLus = $Config.Settings.User.DisplayName.T1O

        Switch($AddText)
        {
            'BeforeCSVdata'
            { 
                $Description = $DescPLus + $Description
                $DisplayName = $dispPlus + $DisplayName
            }
            
            'AfterCSVdata'
            {
                $Description = $Description + $DescPLus
                $DisplayName = $DisplayName + $dispPlus
            }
        }

        #.Append new user to the file, if not already present.
        $isPresent = Select-Xml $HADxml -XPath "//*/Accounts/User[@samAccountName='$($Account.T1O)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Accounts" | Select-Object -ExpandProperty "Node"
            
            $NewChild = $HADxml.CreateElement("User")

            $null = $NewChild.SetAttribute("DisplayName"   ,$DisplayName)
            $null = $NewChild.SetAttribute("Surname"       ,$LastName)
            $null = $NewChild.SetAttribute("GivenName"     ,$FirstName)
            $null = $NewChild.SetAttribute("Description"   ,$Description)
            $null = $NewChild.SetAttribute("samAccountName",($Account.T1O).ToUpper())
            $null = $NewChild.SetAttribute("Path"          ,$Config.Settings.User.Path.T1O)

            $null = $Node.AppendChild($NewChild)
        }

        #.Append new user to groups, if not already present
        $isPresent = Select-Xml $HADxml -XPath "//*/Groups/Group/Member[@samAccountName='$($Account.T1O)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Group[@name='$($Config.Settings.Group.samAccountName.T1O)']" | Select-Object -ExpandProperty "Node"
                            
            $NewChild = $HADxml.CreateElement("Member")
            
            $null = $NewChild.SetAttribute("samAccountName",$($Account.T1O))

            $null = $Node.AppendChild($NewChild) 
        }
    }

    #.Building Tier 2 Manager account
    if ($Account.T2M -ne '' -and $Account.T2M -ne $null)
    {
        #.refresh data
        $Description = $DescData
        $DisplayName = $DispData

        #.Computed Text to append
        $DescPLus = $Config.Settings.User.DisplayName.T2M
        $DispPLus = $Config.Settings.User.DisplayName.T2M

        Switch($AddText)
        {
            'BeforeCSVdata'
            { 
                $Description = $DescPLus + $Description
                $DisplayName = $dispPlus + $DisplayName
            }
            
            'AfterCSVdata'
            {
                $Description = $Description + $DescPLus
                $DisplayName = $DisplayName + $dispPlus
            }
        }

        #.Append new user to the file, if not already present.
        $isPresent = Select-Xml $HADxml -XPath "//*/Accounts/User[@samAccountName='$($Account.T2M)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Accounts" | Select-Object -ExpandProperty "Node"
            
            $NewChild = $HADxml.CreateElement("User")

            $null = $NewChild.SetAttribute("DisplayName"   ,$DisplayName)
            $null = $NewChild.SetAttribute("Surname"       ,$LastName)
            $null = $NewChild.SetAttribute("GivenName"     ,$FirstName)
            $null = $NewChild.SetAttribute("Description"   ,$Description)
            $null = $NewChild.SetAttribute("samAccountName",($Account.T2M).ToUpper())
            $null = $NewChild.SetAttribute("Path"          ,$Config.Settings.User.Path.T2M)

            $null = $Node.AppendChild($NewChild)
        }

        #.Append new user to groups, if not already present
        $isPresent = Select-Xml $HADxml -XPath "//*/Groups/Group/Member[@samAccountName='$($Account.T2M)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Group[@name='$($Config.Settings.Group.samAccountName.T2M)']" | Select-Object -ExpandProperty "Node"
                            
            $NewChild = $HADxml.CreateElement("Member")
            
            $null = $NewChild.SetAttribute("samAccountName",$($Account.T2M))

            $null = $Node.AppendChild($NewChild) 
        }
    }

    #.Building Tier 2 Administrator account
    if ($Account.T2A -ne '' -and $Account.T2A -ne $null)
    {
        #.refresh data
        $Description = $DescData
        $DisplayName = $DispData

        #.Computed Text to append
        $DescPLus = $Config.Settings.User.DisplayName.T2A
        $DispPLus = $Config.Settings.User.DisplayName.T2A

        Switch($AddText)
        {
            'BeforeCSVdata'
            { 
                $Description = $DescPLus + $Description
                $DisplayName = $dispPlus + $DisplayName
            }
            
            'AfterCSVdata'
            {
                $Description = $Description + $DescPLus
                $DisplayName = $DisplayName + $dispPlus
            }
        }

        #.Append new user to the file, if not already present.
        $isPresent = Select-Xml $HADxml -XPath "//*/Accounts/User[@samAccountName='$($Account.T2A)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Accounts" | Select-Object -ExpandProperty "Node"
            
            $NewChild = $HADxml.CreateElement("User")

            $null = $NewChild.SetAttribute("DisplayName"   ,$DisplayName)
            $null = $NewChild.SetAttribute("Surname"       ,$LastName)
            $null = $NewChild.SetAttribute("GivenName"     ,$FirstName)
            $null = $NewChild.SetAttribute("Description"   ,$Description)
            $null = $NewChild.SetAttribute("samAccountName",($Account.T2A).ToUpper())
            $null = $NewChild.SetAttribute("Path"          ,$Config.Settings.User.Path.T2A)

            $null = $Node.AppendChild($NewChild)
        }

        #.Append new user to groups, if not already present
        $isPresent = Select-Xml $HADxml -XPath "//*/Groups/Group/Member[@samAccountName='$($Account.T2A)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Group[@name='$($Config.Settings.Group.samAccountName.T2A)']" | Select-Object -ExpandProperty "Node"
                            
            $NewChild = $HADxml.CreateElement("Member")
            
            $null = $NewChild.SetAttribute("samAccountName",$($Account.T2A))

            $null = $Node.AppendChild($NewChild) 
        }
    }

    #.Building Tier 2 Operator account
    if ($Account.T2O -ne '' -and $Account.T2O -ne $null)
    {
        #.refresh data
        $Description = $DescData
        $DisplayName = $DispData

        #.Computed Text to append
        $DescPLus = $Config.Settings.User.DisplayName.T2O
        $DispPLus = $Config.Settings.User.DisplayName.T2O

        Switch($AddText)
        {
            'BeforeCSVdata'
            { 
                $Description = $DescPLus + $Description
                $DisplayName = $dispPlus + $DisplayName
            }
            
            'AfterCSVdata'
            {
                $Description = $Description + $DescPLus
                $DisplayName = $DisplayName + $dispPlus
            }
        }

        #.Append new user to the file, if not already present.
        $isPresent = Select-Xml $HADxml -XPath "//*/Accounts/User[@samAccountName='$($Account.T2O)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Accounts" | Select-Object -ExpandProperty "Node"
            
            $NewChild = $HADxml.CreateElement("User")

            $null = $NewChild.SetAttribute("DisplayName"   ,$DisplayName)
            $null = $NewChild.SetAttribute("Surname"       ,$LastName)
            $null = $NewChild.SetAttribute("GivenName"     ,$FirstName)
            $null = $NewChild.SetAttribute("Description"   ,$Description)
            $null = $NewChild.SetAttribute("samAccountName",($Account.T2O).ToUpper())
            $null = $NewChild.SetAttribute("Path"          ,$Config.Settings.User.Path.T2O)

            $null = $Node.AppendChild($NewChild)
        }

        #.Append new user to groups, if not already present
        $isPresent = Select-Xml $HADxml -XPath "//*/Groups/Group/Member[@samAccountName='$($Account.T2O)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Group[@name='$($Config.Settings.Group.samAccountName.T2O)']" | Select-Object -ExpandProperty "Node"
                            
            $NewChild = $HADxml.CreateElement("Member")
            
            $null = $NewChild.SetAttribute("samAccountName",$($Account.T2O))

            $null = $Node.AppendChild($NewChild) 
        }
    }

    #.Building Tier 1 Legacy Operator account
    if ($Account.L1O -ne '' -and $Account.L1O -ne $null)
    {
        #.refresh data
        $Description = $DescData
        $DisplayName = $DispData

        #.Computed Text to append
        $DescPLus = $Config.Settings.User.DisplayName.L1O
        $DispPLus = $Config.Settings.User.DisplayName.L1O

        Switch($AddText)
        {
            'BeforeCSVdata'
            { 
                $Description = $DescPLus + $Description
                $DisplayName = $dispPlus + $DisplayName
            }
            
            'AfterCSVdata'
            {
                $Description = $Description + $DescPLus
                $DisplayName = $DisplayName + $dispPlus
            }
        }

        #.Append new user to the file, if not already present.
        $isPresent = Select-Xml $HADxml -XPath "//*/Accounts/User[@samAccountName='$($Account.L1O)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Accounts" | Select-Object -ExpandProperty "Node"
            
            $NewChild = $HADxml.CreateElement("User")

            $null = $NewChild.SetAttribute("DisplayName"   ,$DisplayName)
            $null = $NewChild.SetAttribute("Surname"       ,$LastName)
            $null = $NewChild.SetAttribute("GivenName"     ,$FirstName)
            $null = $NewChild.SetAttribute("Description"   ,$Description)
            $null = $NewChild.SetAttribute("samAccountName",($Account.L1O).ToUpper())
            $null = $NewChild.SetAttribute("Path"          ,$Config.Settings.User.Path.L1O)

            $null = $Node.AppendChild($NewChild)
        }

        #.Append new user to groups, if not already present
        $isPresent = Select-Xml $HADxml -XPath "//*/Groups/Group/Member[@samAccountName='$($Account.L1O)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Group[@name='$($Config.Settings.Group.samAccountName.L1O)']" | Select-Object -ExpandProperty "Node"
                            
            $NewChild = $HADxml.CreateElement("Member")
            
            $null = $NewChild.SetAttribute("samAccountName",$($Account.L1O))

            $null = $Node.AppendChild($NewChild) 
        }
    }

    #.Building Tier 2 Legacy Operator account
    if ($Account.L2O -ne '' -and $Account.L2O -ne $null)
    {
        #.refresh data
        $Description = $DescData
        $DisplayName = $DispData

        #.Computed Text to append
        $DescPLus = $Config.Settings.User.DisplayName.L2O
        $DispPLus = $Config.Settings.User.DisplayName.L2O

        Switch($AddText)
        {
            'BeforeCSVdata'
            { 
                $Description = $DescPLus + $Description
                $DisplayName = $dispPlus + $DisplayName
            }
            
            'AfterCSVdata'
            {
                $Description = $Description + $DescPLus
                $DisplayName = $DisplayName + $dispPlus
            }
        }

        #.Append new user to the file, if not already present.
        $isPresent = Select-Xml $HADxml -XPath "//*/Accounts/User[@samAccountName='$($Account.L2O)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Accounts" | Select-Object -ExpandProperty "Node"
            
            $NewChild = $HADxml.CreateElement("User")

            $null = $NewChild.SetAttribute("DisplayName"   ,$DisplayName)
            $null = $NewChild.SetAttribute("Surname"       ,$LastName)
            $null = $NewChild.SetAttribute("GivenName"     ,$FirstName)
            $null = $NewChild.SetAttribute("Description"   ,$Description)
            $null = $NewChild.SetAttribute("samAccountName",($Account.L2O).ToUpper())
            $null = $NewChild.SetAttribute("Path"          ,$Config.Settings.User.Path.L2O)

            $null = $Node.AppendChild($NewChild)
        }

        #.Append new user to groups, if not already present
        $isPresent = Select-Xml $HADxml -XPath "//*/Groups/Group/Member[@samAccountName='$($Account.L2O)']" | Select-Object -ExpandProperty "Node"

        if (-not $isPresent)
        {
            $Node = Select-Xml $HADxml -XPath "//*/Group[@name='$($Config.Settings.Group.samAccountName.L2O)']" | Select-Object -ExpandProperty "Node"
                            
            $NewChild = $HADxml.CreateElement("Member")
            
            $null = $NewChild.SetAttribute("samAccountName",$($Account.L2O))

            $null = $Node.AppendChild($NewChild) 
        }
    }
}

#.Saving file and keeping formating with tab...
Format-XML $HADxml | Out-File $HADFil -Encoding utf8 -Force

Write-Host "Done.`n" -ForegroundColor Yellow