<#
    .Synopsis
    Manage Harden AD GPO in production. 

    .Description
    Tools to ease GPO management in production during test, pilot or final activation.
    When Harden AD import its GPO to your domain, all of them are not applicable, either by the APPLY group which is empty or the fact that no GpLink exists for it.
    This script will allow you:
    > Add member to an apply group 
    > Add member to a deny group
    > Remove member from a deny group 
    > Remove member from an apply group
    > Link a GPO to an OU
    > Unlink a GPO from an OU

    The script need an access to the hardenAD_TasksSequence.xml file (dynamic call).

    .PArameter GPO
    Name of the GPO to be modified. Accept multiple inputs.

    .Parameter Enable
    Remove the group APPLY and replace it with Authenticated Users. The GPO is then activated by default.

    .Parameter Filter
    Add the group APPLY and remove Authenticated Users as filtering group. The GPO is then deactivated by default, except for member of the group APPLY.

    .Parameter Action
    Add or Remove a member to a group (either Apply or Deny).

    .Parameter Scope
    Define if the scope is upon the Apply or Deny group.

    .Parameter Link
    Link a GPO to an OU.

    .Parameter Unlink
    Unlink a GPO from an OU.

    .Parameter samAccountName
    samAccountName of the account to be removed or added from the group. Accept multiple inputs.

    .Parameter DistinguishedName
    DistinguishedName of the OU to be adressed. Accept multiple inputs and the use of the translation.wellKnownID data.

    .Example
    .\Set-hAD_GPO_Settings.ps1 -GPO "HAD-FIPS-Enabled" -Enable
    Set the GPO "HAD-FIPS-Enabled" enable for all, except members of the group L-S-GPO-DENY-HAD-FIPS-Enabled.

    .Example
    .\Set-hAD_GPO_Settings.ps1 -GPO "HAD-FIPS-Enabled" -Filter
    Filter the GPO "HAD-FIPS-Enabled" only to member of the group L-S-GPO-APPLY-HAD-FIPS-Enabled, except ofr members of the group L-S-GPO-DENY-HAD-FIPS-Enabled.

    .Example
    .\Set-hAD_GPO_Settings.ps1 -GPO "HAD-FIPS-Enabled" -Action Add -Scope Deny -samAccountName 'SRV001$'
    Add the computer 'SRV001$' to the group L-S-GPO-DENY-HAD-FIPS-Enabled.

    .Example
    .\Set-hAD_GPO_Settings.ps1 -GPO "HAD-FIPS-Enabled" -Unlink -DistinguishedName 'DC=Harden,DC=AD'
    Unlink the GPO HAD-FIPS-Enabled from the root.

    .Notes
    Author:     Loic VEIRMAN (MSSec)

    History:    v1.0.0  Script Creation
#>
[CmdletBinding(DefaultParameterSetName = 'GPO')]
Param(
    [Parameter(ParameterSetName="Group")]
    [Parameter(ParameterSetName="GPO")]
    [Parameter(Position=0)]
    [array]
    $GPO,

    [Parameter(Position=1)]
    [Parameter(ParameterSetName="Group")]
    [ValidateSet('Add','Remove')]
    [string]
    $Action,

    [Parameter(Position=2)]
    [Parameter(ParameterSetName="Group")]
    [ValidateSet('Apply','Deny')]
    [string]
    $Scope,

    [Parameter(Position=1)]
    [Parameter(ParameterSetName="GPO")]
    [switch]
    $Link,

    [Parameter(Position=1)]
    [Parameter(ParameterSetName="GPO")]
    [switch]
    $Unlink,

    [Parameter(Position=3)]
    [Parameter(ParameterSetName="Group")]
    [array]
    $samAccountName,

    [Parameter(Position=2)]
    [Parameter(ParameterSetName="GPO")]
    [Switch]
    $Enable,

    [Parameter(Position=2)]
    [Parameter(ParameterSetName="GPO")]
    [Switch]
    $Filter,

    [Parameter(Position=3)]
    [Parameter(ParameterSetName="GPO")]
    [array]
    $DistinguishedName
)
#region ColorSchema
# Color Schema
# Using ANSI Escape code
$FG_Purple      = "$([char]0x1b)[38;2;142;140;216;24m"                  # 38:Foreground, 2:RGB, Red:142, Green:140, Blue:216, 24: not underlined
$BG_Purple      = "$([char]0x1b)[48;2;142;140;216m"                     # 48:background, 2:RGB, Red:142, Green:140, Blue:216
$FG_Purple_U    = "$([char]0x1b)[38;2;142;140;216;4m"                   # 38:Foreground, 2:RGB, Red:142, Green:140, Blue:216, 4: underlined
$FG_Blue        = "$([char]0x1b)[38;2;94;153;255m"                      # 38:Foreground, 2:RGB, Red:94 , Green:153, Blue:255 
$FG_Turquoise   = "$([char]0x1b)[38;2;0;175;204;24m"                    # 38:Foreground, 2:RGB, Red:0  , Green:175, Blue:204, 24: not underlined
$FG_RedLight    = "$([char]0x1b)[38;2;244;135;69m"                      # 38:Foreground, 2:RGB, Red:244, Green:135, Blue:69
$FG_Orange      = "$([char]0x1b)[38;2;255;171;21m"                      # 38:Foreground, 2:RGB, Red:255, Green:171, Blue:21
$FG_GreenLight  = "$([char]0x1b)[38;5;42;24m"                           # 38:Foreground, 5:Indexed Color, 42: Green, 24: not underlined
$FG_PinkDark    = "$([char]0x1b)[38;2;218;101;167m"                     # 38:Foreground, 2:RGB, Red:218, Green:101, Blue:167
$FG_yellowLight = "$([char]0x1b)[38;2;220;220;170;24m"                  # 38:Foreground, 2:RGB, Red:22°, Green:220, Blue:170, 24: not underlined
$FG_Red         = "$([char]0x1b)[38;2;255;0;0m"                         # 38:Foreground, 2:RGB, Red:255, Green:0  , Blue:0
$FG_BrightCyan  = "$([char]0x1b)[96;24m"                                # 96:24 bits color code from standard VGA, 24: not underlined
$FG_brown       = "$([char]0x1b)[38;2;206;145;120m"                     # 38:Foreground, 2:RGB, Red:206, Green:146, Blue:120
$SelectedChoice = "$([char]0x1b)[38;2;255;210;0;48;2;0;175;204;24m"     # 38:Foreground, 2:RGB, Red:255, Green:210, Blue:0  , 48:Background, 2:RGB, Red:0  ,Green:175, Blue:204, 24: not underlined
$ANSI_End       = "$([char]0x1b)[0m"                                    # 0: end of ANSI, reset to default. 
#endregion

Switch ($PSCmdlet.ParameterSetName) {
    # Different use case to adress, depends on which parameterSet we are.
    #region ManageGroup
    # ParameterSetName is Group: dealing with GPO group.
    "Group" {
        Write-Host "${FG_GreenLight}Group identified${ANSI_End}"
        # Building array for action
        
        foreach ($GP in $GPO) {
            # Get the GPO data
            $GpData = Get-GPO $GP
            $GpPerm = Get-GPPermissions $GpData -All
            # Adding expectedValue to an array
            
            
        }
    }
    #endregion
    #region gpLinks
    # ParameterSetName is GPO: dealing with gplink and gpo activation.
    "GPO" {
        Write-Host "${FG_GreenLight}GPO identified${ANSI_End}"
    }
    # Other cases are ignored.
    Default {
        Write-Host "${FG_Red}Error${FG_yellowLight}: ${FG_RedLight}parameterSetName ${FG_yellowLight}not identified (should have identify ${FG_RedLight}Group ${FG_yellowLight}or ${FG_RedLight}GPO${FG_yellowLight})."
        Exit 0
    }
    #endregion
}