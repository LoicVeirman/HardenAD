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

# get root path of the solution
$scriptRootPath = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

$configXMLFilePath = Join-Path -Path $scriptRootPath -ChildPath "Configs\TasksSequence_HardenAD.xml"

$configXMLFileName = $configXMLFilePath | Split-Path -Leaf

#.Loading modules
gci .\Modules\*.psm1 | % { Import-Module $_.fullname }

$TasksSeqConfig = [xml](Get-Content $configXMLfilePath -Encoding utf8)

$Tasks = $TasksSeqConfig.Settings.Sequence.ID | Sort-Object Number

[System.Collections.Generic.List[PSObject]]$rowArray = @()
[System.Collections.Generic.List[PSObject]]$checkboxesArray = @()

for ($i = 0; $i -lt $Tasks.Count; $i++) {
    $task = $Tasks[$i]
    # Add a new row definition every 2 tasks because we have 2 columns
    if ($i % 2 -eq 0) {
        $rowArray.Add("<RowDefinition Height='*'></RowDefinition>")
    }
    # Calculate the row and column for the current task
    $row = [Math]::Floor($i / 2)
    # If the task is on an even index, it will be on the first column, otherwise it will be on the second column
    $column = $i % 2

    # Check if the task is enabled. If it is, the checkbox will be checked, otherwise it will be unchecked
    $taskEnabled = $task.TaskEnabled -eq 'Yes'
    $taskDescription = $task.TaskDescription.Replace("'", "").Replace("`(", '')

    $checkboxesArray.Add("<CheckBox x:Name='ID_$($task.Number)' Content='$($task.Number) - $($task.Name)' IsChecked='$taskEnabled' Grid.Row='$row' Grid.Column='$column' HorizontalAlignment='Left' VerticalAlignment='Center' Margin='5' ToolTip='$taskDescription' />")
}

Add-Type -AssemblyName PresentationFramework, System.Drawing, System.Windows.Forms, WindowsFormsIntegration
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$labelText1 = "To prevent accidental changes, all the tasks are disabled by default in the XML configuration file."
$labelText2 = "Select the tasks you want to enable/disable and click Save."
$labelText3 = "The only purpose of the GUI is to configure HardenAD config file, it does not perform any actions!"

$icon = "$PSScriptRoot\hardenAD.ico"

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
"@ -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window' -replace 'x:Class="\S+"', ''

#Read XAML
$reader = (New-Object System.Xml.XmlNodeReader $XAML)
$Form = [Windows.Markup.XamlReader]::Load($reader)

$XAML.SelectNodes("//*[@Name]") | ForEach-Object { Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name) }

#endregion

# Add Click event handler
$CheckUncheckAllButton.Add_Click({
        # Get all CheckBoxes
        $checkBoxes = $Form.FindName("MyGrid").Children | Where-Object { $_ -is [System.Windows.Controls.CheckBox] }
        # Check if all CheckBoxes are checked
        $allChecked = ($checkBoxes | ForEach-Object { $_.IsChecked }) -notcontains $false
        # Check or uncheck all CheckBoxes
        $checkBoxes | ForEach-Object { $_.IsChecked = -not $allChecked }
    })

$Form.FindName("ExitButton").Add_Click({ $Form.Close() })

$SaveButton.Add_Click({
        # get all CheckBoxes and update the XML configuration file
        $checkBoxes = $Form.FindName("MyGrid").Children | Where-Object { $_ -is [System.Windows.Controls.CheckBox] }
        foreach ($checkBox in $checkBoxes) {
            $number = $checkBox.Name -replace 'ID_', ''
            $taskNode = Select-Xml $TasksSeqConfig -XPath "//Sequence/Id[@Number='$number']" | Select-Object -ExpandProperty "Node"
        
            if ($checkBox.IsChecked -eq $true) {
                $taskNode.TaskEnabled = "Yes"
            }
            else {
                $taskNode.TaskEnabled = "No"
            }
        }

        # Saving file
        Format-XML -XML $TasksSeqConfig | Out-File $configXMLFilePath -Encoding utf8 -Force
        
        $SaveLabel.Text = "$([System.DateTime]::Now.ToString('HH:mm:ss')) - File $configXMLFileName saved!"
    })

$dialogResult = $Form.ShowDialog()