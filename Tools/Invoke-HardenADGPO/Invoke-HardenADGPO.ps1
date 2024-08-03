<#
    .Synopsis
    Tool to configure which GPO haveto be imported.
#>
Param()

<#
    FUNCTION: FORMAT-XML
    This function out an XML with a TAB indentation - requiered when you modify an XML.
#>
Function Format-XML
{
    Param(
        # The XML data to be formatted
        [Parameter(mandatory,Position=0)]
        [XML]
        $XML
    )  
    # Prepare the XML handler object
    $StringWriter = New-Object System.IO.StringWriter
    $XmlWriter    = New-Object System.XMl.XmlTextWriter $StringWriter

    # Configure the XML handler with our specific formatting expectation
    $xmlWriter.Formatting  = 'indented'
    $xmlWriter.Indentation = 1
    $xmlWriter.IndentChar  = "`t"

    # Reformatting the XML...
    $xml.WriteContentTo($XmlWriter)
    $XmlWriter.Flush()
    $StringWriter.Flush()

    # Returning result.
    return $StringWriter.ToString()
}

#.Add type assemblies
Add-Type -AssemblyName PresentationFramework, System.Drawing, System.Windows.Forms, WindowsFormsIntegration
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

#.Loading modules
gci .\Modules\*.psm1 | % { Import-Module $_.fullname }

# get root path of the solution and other stuff...
$scriptRootPath    = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$configXMLFilePath = Join-Path -Path $scriptRootPath -ChildPath "Configs\TasksSequence_HardenAD.xml"
$configXMLFileName = $configXMLFilePath | Split-Path -Leaf
$TasksSeqConfig    = [xml](Get-Content $configXMLfilePath -Encoding utf8)
$icon              = "$PSScriptRoot\hardenAD.ico"

#.XML Gpo list
$GPOnodes = Select-Xml $TasksSeqConfig -XPath "//*/GroupPolicies/GPO" | Select-Object -ExpandProperty Node

#.Variables
$labelText1 = "The Security Model is base on GPO, each of them applying a set of customization."
$labelText2 = "Select the GPO you want to onboard and click Save."
$labelText3 = "The only purpose of the GUI is to configure HardenAD config file, it does not perform any actions!"

#.XAML Arrays
[System.Collections.Generic.List[PSObject]]$rowArray        = @()
[System.Collections.Generic.List[PSObject]]$checkboxesArray = @()

#.CheckBox Array
$checkboxesID = @{}

#.Filling Arrays
$myCol = -1
$myLin = -1
for ($i = 0; $i -lt $GPOnodes.Count; $i++) 
{
    #.Setting Col position
    if ($myCol -eq 3) { $myCol = 0 } else { $myCol++ }

    #.Getting node data
    $GpoNode = $GpoNodes[$i]
    
    #.Add a new row definition every 4 tasks because we have 4 columns
    if ($myCol -eq 0) 
    {
        $rowArray.Add("<RowDefinition Height='*'></RowDefinition>")
    }
    
    #.Calculate the row and column for the currentGPO
    #$row = [Math]::Floor($i / 4)
    if ($myCol -eq 0) { $myLin++ }

    #.If the task is on an even index, it will be on the first column, otherwise it will be on the second column
    $column = $myCol

    #.Check if the task is enabled. If it is, the checkbox will be checked, otherwise it will be unchecked
    $GpoEnabled = $GpoNode.Validation -eq 'Yes'
    $GpobackpID = "ID_$(($GpoNode.BackupID -split "-")[0] -replace "{",$null)"
    $checkboxesID.add($GpobackpID,$GpoNode.BackupID)
    
    #.Add to CheckBoxes array
    $checkboxesArray.Add("<CheckBox x:Name='$GpoBackpID' Content='$($GpoNode.Name)' IsChecked='$GpoEnabled' Grid.Row='$myLin' Grid.Column='$column' HorizontalAlignment='Left' VerticalAlignment='Center' Margin='5' ToolTip='Ask to the farting cat' />")
}

#.XAML Data
[xml]$XAML = @"
<Window x:Class="MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        Title="Harden AD" SizeToContent="WidthAndHeight" Icon="$icon">
    <StackPanel>
        <TextBlock Text="$labelText1" FontWeight="Bold" HorizontalAlignment="Center" TextWrapping="Wrap" TextAlignment="Center" />
        <TextBlock Text="$labelText2" FontWeight="Bold" HorizontalAlignment="Center" TextWrapping="Wrap" TextAlignment="Center" />
        <TextBlock Text="$labelText3" FontWeight="Bold" HorizontalAlignment="Center" TextWrapping="Wrap" TextAlignment="Center" Padding="5" Foreground="Red"/>
        <Grid Margin="5" x:Name="MyGrid">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"></ColumnDefinition>
                <ColumnDefinition Width="*"></ColumnDefinition>
                <ColumnDefinition Width="*"></ColumnDefinition>
                <ColumnDefinition Width="*"></ColumnDefinition>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                $($rowArray -join "`n")
            </Grid.RowDefinitions>
            $($checkboxesArray -join "`n")
        </Grid>
        <DockPanel LastChildFill="False" Background="#f3f3f3" HorizontalAlignment="Stretch" Width="Auto" VerticalAlignment="Center">
            <Button DockPanel.Dock="Left" x:Name="CheckUncheckAllButton" Content="Check/Uncheck All" Padding="7" Margin="5"/>
            <StackPanel Orientation="Horizontal" DockPanel.Dock="Right">
                <TextBlock x:Name="SaveLabel" Text="" VerticalAlignment="Center" Margin="5" FontStyle="Italic"/>
                <Button x:Name="SaveButton" Content="Save" Padding="7" Margin="5" Width="80"/>
                <Button x:Name="ExitButton" Content="Exit" Padding="7" Margin="5" Width="80"/>
            </StackPanel>
        </DockPanel>
    </StackPanel>
</Window>
"@  -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window' -replace 'x:Class="\S+"', ''

#.XAML Loader
Try {
    $reader = (New-Object System.Xml.XmlNodeReader $XAML)
    $Form   = [Windows.Markup.XamlReader]::Load($reader)
}
Catch {
       Write-Error "Fatal Error: $($_.ToString())"
       exit 1
        
}

#.XAML Variable Loader
Foreach ($xamlNode in $XAML.SelectNodes("//*[@Name]"))
{
    Try {
        Set-Variable -Name ($xamlNode.Name) -Value $Form.FindName($xamlNode.Name) 
    } 
    Catch {
        Write-Error "Fatal Error: $($_.ToString())"
        Exit 2
    }
}

#.Add Click event handler
$CheckUncheckAllButton.Add_Click(
    {
        #.Get all CheckBoxes
        $checkBoxes = $Form.FindName("MyGrid").Children | Where-Object { $_ -is [System.Windows.Controls.CheckBox] }
        
        #.Check if all CheckBoxes are checked
        $allChecked = ($checkBoxes | ForEach-Object { $_.IsChecked }) -notcontains $false
        
        #.Check or uncheck all CheckBoxes
        $checkBoxes | ForEach-Object { $_.IsChecked = -not $allChecked }
    }
)

#.Exit Button
$Form.FindName("ExitButton").Add_Click({ $Form.Close() })

#.Save Button
$SaveButton.Add_Click(
    {
        # get all CheckBoxes and update the XML configuration file
        $checkBoxes = $Form.FindName("MyGrid").Children | Where-Object { $_ -is [System.Windows.Controls.CheckBox] }

        foreach ($checkBox in $checkBoxes) 
        {
            $numberID = $checkboxesID[$CheckBox.Name]
            $GpoNode = Select-Xml $TasksSeqConfig -XPath "//*/GroupPolicies/GPO[@BackupID='$numberID']" | Select-Object -ExpandProperty "Node"
        
            if ($checkBox.IsChecked -eq $true) {
                $GpoNode.Validation = "Yes"
            }
            else {
                $GpoNode.Validation = "No"
            }
        }

        # Saving file
        Format-XML -XML $TasksSeqConfig | Out-File $configXMLFilePath -Encoding utf8 -Force
        
        $SaveLabel.Text = "$([System.DateTime]::Now.ToString('HH:mm:ss')) - File $configXMLFileName saved!"
    }
)
#.Display result
$dialogResult = $Form.ShowDialog()