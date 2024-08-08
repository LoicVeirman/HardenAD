# get root path of the solution
$scriptRootPath = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

$configXMLFilePath = Join-Path -Path $scriptRootPath -ChildPath "Configs\TasksSequence_HardenAD.xml"

$configXMLFileName = $configXMLFilePath | Split-Path -Leaf

$xmlModule = "$scriptRootPath\Modules\module-fileHandling\module-fileHandling.psm1"
Import-Module "$xmlModule"

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

	$checkboxesArray.Add("<CheckBox x:Name='ID_$($task.Number)' Content='$($task.Number) - $($task.Name)' IsChecked='$taskEnabled' Grid.Row='$row' Grid.Column='$column' HorizontalAlignment='Left' VerticalAlignment='Center' Margin='1, 1, 1, 1' ToolTip='$taskDescription' />")
}

$groupPolicies = $TasksSeqConfig.Settings.GroupPolicies.GPO

[System.Collections.Generic.List[PSObject]]$groupPoliciesRowsArray = @()
[System.Collections.Generic.List[PSObject]]$groupPoliciesCheckboxesArray = @()
$gpoGUIDHashTables = @{}

for ($i = 0; $i -lt $groupPolicies.Count; $i++) {
	$gpoGUIDHashTables.Add($i, $groupPolicies[$i].BackupID)

	# Add a new row definition every 4 gpos because we have 4 columns
	if ($i % 4 -eq 0) {
		$groupPoliciesRowsArray.Add("<RowDefinition Height='*'></RowDefinition>")
	}
	# Calculate the row and column for the current gpo
	$row = [Math]::Floor($i / 4)
	# If the gpo is on an index that modulo 4 gives 0, 1, 2 or 3, it will be on the first, second, third or fourth column respectively
	$column = $i % 4

	$groupPolicy = $groupPolicies[$i]
	$groupPolicyName = $groupPolicy.Name
	#$groupPolicyDescription = $groupPolicy.Description.Replace("'", "").Replace("`(", '')
	$groupPolicyEnabled = $groupPolicy.Validation -eq 'Yes'

	$groupPoliciesCheckboxesArray.Add("<CheckBox x:Name='ID_$i' Content='$groupPolicyName' IsChecked='$groupPolicyEnabled' Grid.Row='$row' Grid.Column='$column' HorizontalAlignment='Left' VerticalAlignment='Center' Margin='1, 1 ,1, 1' />")
}

Add-Type -AssemblyName PresentationFramework, System.Drawing, System.Windows.Forms, WindowsFormsIntegration, PresentationCore, WindowsBase


$labelText1 = "To prevent accidental changes, all the tasks are disabled by default in the XML configuration file."
$labelText2 = "In the tab 'Task Sequence', you can enable the tasks you want to run."
$labelText3 = "In the tab 'Group Policies', you can enable the GPOs you want to import."
$labelText4 = "After clicking 'Save', the XML file is overwritten with the new configuration."
$labelText5 = "The only purpose of the GUI is to configure HardenAD config file, it does not perform any actions!"

$icon = "$PSScriptRoot\hardenAD.ico"

[xml]$XAML = @"
<Window x:Class="MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        Title="Harden AD Configuration" Width="1010" Height="650" ResizeMode="NoResize" WindowStartupLocation="CenterScreen" mc:Ignorable="d" Icon="$icon">
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <StackPanel Grid.Row="0">
            <TextBlock Text="$labelText1" FontWeight="Bold" HorizontalAlignment="Center" TextWrapping="Wrap" TextAlignment="Center"	Padding="0,0,0,10"/>
			<TextBlock Text="$labelText2" FontWeight="Bold" HorizontalAlignment="Center" TextWrapping="Wrap" TextAlignment="Center" />
            <TextBlock Text="$labelText3" FontWeight="Bold" HorizontalAlignment="Center" TextWrapping="Wrap" TextAlignment="Center" />
            <TextBlock Text="$labelText4" FontWeight="Bold" HorizontalAlignment="Center" TextWrapping="Wrap" TextAlignment="Center" Padding="0,10,0,0"/>
			<TextBlock Text="$labelText5" FontWeight="Bold" HorizontalAlignment="Center" TextWrapping="Wrap" TextAlignment="Center" Foreground="Red" Padding="0,10,0,10"/>
        </StackPanel>
		<TabControl Grid.Row="1">
            <TabItem Header="Task Sequence">
				<ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
					<Grid>
						<Grid.RowDefinitions>
							<RowDefinition Height="Auto"/>
							<RowDefinition Height="*"/>
						</Grid.RowDefinitions>
						<Grid Margin="5" x:Name="MyGrid" Grid.Row="0">
							<Grid.ColumnDefinitions>
								<ColumnDefinition Width="*"></ColumnDefinition>
								<ColumnDefinition Width="*"></ColumnDefinition>
							</Grid.ColumnDefinitions>
							<Grid.RowDefinitions>
								$($rowArray -join "`n")
							</Grid.RowDefinitions>
							$($checkboxesArray -join "`n")
						</Grid>
						<Button x:Name="CheckUncheckAllButton_Tasks" Content="Check/Uncheck all tasks" Grid.Row="1" HorizontalAlignment="Center" Height="20"/>
					</Grid>
				</ScrollViewer>
            </TabItem>
            <TabItem Header="Group Policies">
       			<ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
					<Grid>
						<Grid.RowDefinitions>
							<RowDefinition Height="Auto"/>
							<RowDefinition Height="*"/>
						</Grid.RowDefinitions>
						<Grid Margin="5" x:Name="MyGrid2" Grid.Row="0">
							<Grid.ColumnDefinitions>
								<ColumnDefinition Width="*"></ColumnDefinition>
								<ColumnDefinition Width="*"></ColumnDefinition>
								<ColumnDefinition Width="*"></ColumnDefinition>
								<ColumnDefinition Width="*"></ColumnDefinition>
							</Grid.ColumnDefinitions>
							<Grid.RowDefinitions>
								$($groupPoliciesRowsArray -join "`n")
							</Grid.RowDefinitions>
							$($groupPoliciesCheckboxesArray -join "`n")
						</Grid>
						<Button x:Name="CheckUncheckAllButton_GPO" Content="Check/Uncheck all policies" Grid.Row="1" HorizontalAlignment="Center" Height="20"/>
					</Grid>
				</ScrollViewer>
            </TabItem>
        </TabControl>
        <DockPanel Grid.Row="2" LastChildFill="False" Background="#f3f3f3" HorizontalAlignment="Stretch" Width="Auto" VerticalAlignment="Center">
            <StackPanel Orientation="Horizontal" DockPanel.Dock="Right">
                <TextBlock x:Name="SaveLabel" Text="" VerticalAlignment="Center" Margin="5" FontStyle="Italic"/>
                <Button x:Name="SaveButton" Content="Save" Padding="7" Margin="5" Width="80"/>
                <Button x:Name="ExitButton" Content="Exit" Padding="7" Margin="5" Width="80"/>
            </StackPanel>
        </DockPanel>
    </Grid>
</Window>
"@ -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window' -replace 'x:Class="\S+"', ''

#Read XAML
$reader = (New-Object System.Xml.XmlNodeReader $XAML)
$Form = [Windows.Markup.XamlReader]::Load($reader)

$XAML.SelectNodes("//*[@Name]") | ForEach-Object { Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name) }

# Add Click event handler
$CheckUncheckAllButton_Tasks.Add_Click({
		# Get all CheckBoxes
		$checkBoxes = $Form.FindName("MyGrid").Children | Where-Object { $_ -is [System.Windows.Controls.CheckBox] }
		# Check if all CheckBoxes are checked
		$allChecked = ($checkBoxes | ForEach-Object { $_.IsChecked }) -notcontains $false
		# Check or uncheck all CheckBoxes
		$checkBoxes | ForEach-Object { $_.IsChecked = -not $allChecked }
	})

# Add Click event handler
$CheckUncheckAllButton_GPO.Add_Click({
		# Get all CheckBoxes
		$checkBoxes = $Form.FindName("MyGrid2").Children | Where-Object { $_ -is [System.Windows.Controls.CheckBox] }
		# Check if all CheckBoxes are checked
		$allChecked = ($checkBoxes | ForEach-Object { $_.IsChecked }) -notcontains $false
		# Check or uncheck all CheckBoxes
		$checkBoxes | ForEach-Object { $_.IsChecked = -not $allChecked }
	})

$SaveButton.Add_Click({
		$toSave = $true

		# get all CheckBoxes and update the XML configuration file
		$checkBoxes = $Form.FindName("MyGrid").Children | Where-Object { $_ -is [System.Windows.Controls.CheckBox] }
		# if ID 130 is checked, then ID 125 must be checked
		# If not, I want to raise a pop-up message
		$checkBox100 = $checkBoxes | Where-Object { $_.Name -eq "ID_100" }
		$checkBox101 = $checkBoxes | Where-Object { $_.Name -eq "ID_101" }
		$checkBox125 = $checkBoxes | Where-Object { $_.Name -eq "ID_125" }
		$checkBox300 = $checkBoxes | Where-Object { $_.Name -eq "ID_130" }
		
		if ($checkBox300.IsChecked -and (-not ($checkBox100.IsChecked) -or -not ($checkBox101.IsChecked) -or -not ($checkBox125.IsChecked))) {
			$ID100DisplayName = $checkBox100.Content
			$ID101DisplayName = $checkBox101.Content
			$ID125DisplayName = $checkBox125.Content
			$ID300DisplayName = $checkBox300.Content
			
			$message = "If you select the GPO `n$ID300DisplayName`:`n`nYou need to select the following GPOs:`n$ID100DisplayName`n$ID101DisplayName`n$ID125DisplayName`n`nPlease note if you click 'OK', the XML configuration file will be saved and you can encounter issues."
			[System.Windows.MessageBox]::Show($message, "Warning", [System.Windows.MessageBoxButton]::OKCancel, [System.Windows.MessageBoxImage]::Warning) | ForEach-Object {
				if ($_ -eq "Cancel") {
					$toSave = $false
				}
			}
		}

		if ($toSave) {
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

			# get all CheckBoxes and update the XML configuration file
			$checkBoxes = $Form.FindName("MyGrid2").Children | Where-Object { $_ -is [System.Windows.Controls.CheckBox] }
			foreach ($checkBox in $checkBoxes) {
				$number = [int]($checkBox.Name -replace 'ID_', '')
			
				# get GUID from ID
				$gpoGUID = $gpoGUIDHashTables[$number]

				$gpoNode = Select-Xml $TasksSeqConfig -XPath "//GPO[@BackupID='$gpoGUID']" | Select-Object -ExpandProperty "Node"

				if ($checkBox.IsChecked) {
					$gpoNode.Validation = "Yes"
				}
				else {
					$gpoNode.Validation = "No"
				}
			}

			# Saving file
			Format-XMLData -XMLData $TasksSeqConfig | Out-File $configXMLFilePath -Encoding utf8 -Force
        
			$SaveLabel.Text = "$([System.DateTime]::Now.ToString('HH:mm:ss')) - File $configXMLFileName saved!"
		}
	})

$Form.FindName("ExitButton").Add_Click({ $Form.Close() })

$dialogResult = $Form.ShowDialog()