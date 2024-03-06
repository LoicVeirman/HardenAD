using module ..\HADLogger\HADLogger.psm1

enum ProductType {
    Unknown
    Workstation
    Server
}

enum ADObjectType {
    user
    group
    computer
}

class ADConfig {
    static [hashtable] $global:BuiltinGroups = @{}
    static [Microsoft.ActiveDirectory.Management.ADDomain] $CurrentDomain = (Get-ADDomain)

    static [void] Build() {
        [ADConfig]::CollectBuiltinGroups()
    }

    static [void] CollectBuiltinGroups() {
        [string] $DomainSID = [ADConfig]::CurrentDomain.DomainSID

        try {
            [ADConfig]::BuiltinGroups.Add("DomainAdmins", (Get-ADGroup ([System.Security.Principal.SecurityIdentifier]::new(("{0}-{1}" -f $DomainSID, "512"))) -Properties *))
            [ADConfig]::BuiltinGroups.Add("EnterpriseAdmins", (Get-ADGroup ([System.Security.Principal.SecurityIdentifier]::new(("{0}-{1}" -f $DomainSID, "519"))) -Properties *))
        }
        catch {
            Write-Host $_.exception.Message -ForegroundColor Red
        }
    }
}

class Harden {
    static [HADLogger] $Log
    static [xml] $XmlConfig

    static InitializeConfiguration([string] $ConfigPath) {
        [Harden]::XmlConfig = (Get-Content $ConfigPath -Encoding UTF8)
    }
    static [void] InitializeLog($LogObj) {
        [Harden]::Log = $LogObj
    }
}

class HADObjects : Harden {

    [string] $Name
    [string] $DN
    [ADObjectType] $ObjectType
     
    [void] ResetACL() {

        [string] $SchemaNamingContext = (Get-ADRootDSE).schemaNamingContext
        [string] $DefaultSecurityDescriptor = $null
        $ADObj = $null
        
        switch ($this.ObjectType) {
            group { 
                try {
                    $DefaultSecurityDescriptor = (Get-ADObject -Identity "CN=Group,$SchemaNamingContext" -Properties defaultSecurityDescriptor | Select-Object -ExpandProperty defaultSecurityDescriptor)
                    [Harden]::Log.NewLog(1300, "groups")
                }
                catch {
                    [Harden]::Log.NewLog(1301, "groups")
                }
                $ADObj = Get-ADGroup $this.DN -Properties nTSecurityDescriptor

            }
            user {
                try {
                    $DefaultSecurityDescriptor = (Get-ADObject -Identity "CN=User,$SchemaNamingContext" -Properties defaultSecurityDescriptor | Select-Object -ExpandProperty defaultSecurityDescriptor)
                    [Harden]::Log.NewLog(1300, "users")
                }
                catch {
                    [Harden]::Log.NewLog(1301, "users")
                }
                $ADObj = Get-ADUser $this.DN -Properties nTSecurityDescriptor
            }
            computer { 
                try {
                    $DefaultSecurityDescriptor = (Get-ADObject -Identity "CN=Computer,$SchemaNamingContext" -Properties defaultSecurityDescriptor | Select-Object -ExpandProperty defaultSecurityDescriptor)
                    [Harden]::Log.NewLog(1300, "users")
                }
                catch {
                    [Harden]::Log.NewLog(1301, "users")
                }
                $ADObj = Get-ADComputer $this.DN -Properties nTSecurityDescriptor
            }
            Default {
                throw "Unknow type of object."
            }
        }

        $ADObj.nTSecurityDescriptor.SetSecurityDescriptorSddlForm($DefaultSecurityDescriptor)

        try {
            Set-ADObject $this.DN -Replace @{
                nTSecurityDescriptor = $ADObj.nTSecurityDescriptor
            } -Confirm:$false
            [Harden]::Log.NewLog(1304, $this.Name)
        }
        catch {
            [Harden]::Log.NewLog(1305, $this.Name)
        }

    }

    [void] ResetOwner() {
        [adsi] $AdsiTarget = "LDAP://$($this.DN)"

        $CorrectOwner = [System.Security.Principal.NTAccount]::new(([ADConfig]::BuiltinGroups["DomainAdmins"]).Name)
        try {
            $AdsiTarget.PSBase.ObjectSecurity.SetOwner($CorrectOwner)
            $AdsiTarget.PSBase.CommitChanges()
            [Harden]::Log.NewLog(1302, @($this.Name, ([ADConfig]::BuiltinGroups["DomainAdmins"]).Name))
        }
        catch {
            [Harden]::Log.NewLog(1303, $this.Name)
        }
    }
}

class HADComputer : HADObjects {

    static [bool] $WorkstationOnly = $false
    static [bool] $ServerOnly = $false

    $ConfigFile
    [HADLocalAdminGroup] $AssociatedGroup

    [string] $Path
    [string] $Entity

    [bool] $isLegacy
    [ProductType] $ProductType = [ProductType]::Unknown
    [string] $Tier = "Unknown"

    HADComputer([System.Object] $ComputerObj) {
        $this.ObjectType = [ADObjectType]::computer

        $this.Name = $ComputerObj.Name
        $this.DN = $ComputerObj.DistinguishedName
        $this.Path = ($this.DN).Substring(($this.DN).IndexOf(",") + 1)

        $this.InstantiateOS($ComputerObj.OperatingSystem)
        $this.InstantiateTier()
    }
   
    hidden [void] InstantiateOS($OS) {
        if ($OS -like "Windows Server*") {
            $this.ProductType = [ProductType]::Server
        }
        elseif ($OS -like "Windows*") {
            $this.ProductType = [ProductType]::Workstation
        }
        else {
            $this.ProductType = [ProductType]::Unknown
        }

        if ($this.ProductType -ne [ProductType]::Unknown) {
            if (($OS -like "*Windows 10*") -or `
                    $OS -like "*Windows 11*" -or `
                    $OS -like "*2016*" -or `
                    $OS -like "*2019*" -or `
                    $OS -like "*2022*") {
                $this.isLegacy = $false
            }
            else {
                $this.isLegacy = $true
            }
        }
    }

    hidden [void] InstantiateTier() {

        $Tiers = $null
        if ([Harden]::XmlConfig) {
            $Tiers = ([Harden]::XmlConfig).Config.Tiers.Admin.Tier
            $Patterns = ([Harden]::XmlConfig).Config.Patterns.ProductionPatterns.Pattern
            
            foreach ($Pattern in $Patterns) {
                $Pattern = $Pattern -replace "%DomainDN%", (Get-ADDomain).DistinguishedName
                $res = $this.CheckPattern($this.Path, $Pattern)
                
                if ($res) {
                    break
                }
                else {
                    $this.Tier = "Unknown"
                }
            }
        }
        if ($this.Tier -eq "Unknown") {

            if (!($this.isLegacy)) {
                switch ($this.ProductType) {
                        ([ProductType]::Workstation) {
                        if ([Harden]::XmlConfig) {
                            $this.Tier = ($Tiers | Where-Object { $_.Tier -eq "T2" }).Name
                        }
                        else {
                            $this.Tier = "T2"
                        }
                    }
                        ([ProductType]::Server) { 
                        if ([Harden]::XmlConfig) {
                            $this.Tier = ($Tiers | Where-Object { $_.Tier -eq "T1" }).Name
                        }
                        else {
                            $this.Tier = "T1"
                        }
                    }
                    Default {
                        $this.Tier = "Unknown"
                    }
                }
            }
            else {
                switch ($this.ProductType) {
                        ([ProductType]::Workstation) { 
                        if ([Harden]::XmlConfig) {
                            $this.Tier = ($Tiers | Where-Object { $_.Tier -eq "T2L" }).Name
                        }
                        else {
                            $this.Tier = "T2L"
                        }
                    }
                        ([ProductType]::Server) { 
                        if ([Harden]::XmlConfig) {
                            $this.Tier = ($Tiers | Where-Object { $_.Tier -eq "T1L" }).Name
                        }
                        else {
                            $this.Tier = "T1L"
                        }
                    }
                    Default {
                        $this.Tier = "Unknown"
                    }
                }
            }
        }
    }

    hidden [bool] CheckPattern($Path, $Pattern) {
        if ($Pattern -eq "") {
            return $true
        }
        if ($Path -eq "") {
            return $false
        }
        elseif ($this.Right($Path) -eq $this.Right($Pattern)) {
            return $this.CheckPattern($this.Left($Path), $this.Left($Pattern))
        }
        else {
            $tmp = (($this.Right($Pattern)).Substring(3) -replace "%", "")
            $SelectedNodes = ([Harden]::XmlConfig).SelectNodes("//$tmp")

            if (($this.Right($Path)).Substring(3) -in $SelectedNodes.Name) {

                if ($tmp -eq "Entity") {
                    if (($SelectedNodes | Where-Object { $_.Name -eq (($this.Right($Path)).Substring(3)) })) {
                        $this.Entity = ($SelectedNodes | Where-Object { $_.Name -eq (($this.Right($Path)).Substring(3)) }).Name
                    }
                }

                if (($SelectedNodes | Where-Object {
                            $_.Name -eq (($this.Right($Path)).Substring(3)) 
                        }).Tier `
                        -and ($this.Tier -eq "Unknown" `
                            -or $this.Tier -eq "T12" `
                            -or $this.Tier -eq "TL")) {
                    if ($this.Tier -eq "TL") {
                        $this.Tier = ($SelectedNodes | Where-Object {
                                $_.Name -eq (($this.Right($Path)).Substring(3))
                            }).Tier + "L"
                    } 
                    else {
                        $this.Tier = ($SelectedNodes | Where-Object {
                                $_.Name -eq (($this.Right($Path)).Substring(3))
                            }).Tier
                    }
                        
                }
                return $this.CheckPattern($this.Left($Path), $this.Left($Pattern))
            }      
            else {
                return $false
            }
            return $false
        }
    }

    [string] Right($String) {
        return $String.Substring($String.LastIndexOf(",") + 1)
    }

    [string] Left($String) {
        if ($String.Contains(",")) {
            return $String.Substring(0, $String.LastIndexOf(","))
        }
        return ""
    }

    [void] UpdateLocalAdminGroup() {

        if ($this.Path -in (([Harden]::XmlConfig).Config.ExcludedOU.OU -replace "%DomainDN%", (Get-ADDomain).DistinguishedName)) {
            [Harden]::Log.NewLog(10000, @($this.Name, $this.Path))
            continue
        }
        $DomainControllers = Get-ADDomainController -Filter *

        if (($this.Name -in $DomainControllers.Name)) {
            [Harden]::Log.NewLog(1040, $this.Name)
            continue
        } 
        if ($this.ProductType -eq [ProductType]::Unknown) {
            [Harden]::Log.NewLog(1041, $this.Name)
            # BUG: Create the group in T0 ? 
            continue
        }
        # TODO: Refaire cette partie
        # if ([HADComputer]::WorkstationOnly -and $this.ProductType -ne [ProductType]::Workstation) {
        #     continue
        # }
        # if ([HADComputer]::ServerOnly -and $this.ProductType -ne [ProductType]::Server) {
        #     continue
        # }

        $this.AssociatedGroup = [HADLocalAdminGroup]::new($this)        
    }
}

class HADGroup : HADObjects {


    [string] $Description
    [string] $Path

    static [bool] $TTLCompatible = $false

    HADGroup() {
        $this.ObjectType = [ADObjectType]::group
    }
    
    HADGroup($Group) {
        $this.ObjectType = [ADObjectType]::group

        if ($Group.GetType() -eq [Microsoft.ActiveDirectory.Management.ADGroup]) {
            $this.Name = $Group.Name
            $this.DN = $Group.DistinguishedName
        }
        elseif ($Group.GetType() -eq [string]) {
            $ADGroup = Get-ADGroup -Identity $Group -Properties *
            if ($ADGroup) {
                $this.Name = $ADGroup.Name
                $this.DN = $ADGroup.DistinguishedName
            }
            else {
                # TODO: log not find
                continue
            }
        }
    }

    static [bool] CheckTTLPrerequisites() {

        [int] $ForestMode = (Get-ADForest).ForestMode

        if ($ForestMode -ge 7) {
            # 2016 forest at least
            [bool] $PrivilegeAccessFeature = ((Get-ADOptionalFeature -Filter { Name -eq "Privileged Access Management Feature" }).EnabledScopes.Count -gt 0)
        
            if (!$PrivilegeAccessFeature) {
                try {
                    # TODO : Check if it's working on a french or other languauge directory
                    # TODO : Checl if -confirm:$false is working too
                    Enable-ADOptionalFeature "Privileged Access Management Feature" -Scope ForestOrConfigurationSet -Target (Get-ADDomain).DNSRoot -Confirm:$false -ErrorAction Stop
                    return $true
                }
                catch {
                    # TODO : LOG  
                    return $false
                }
            }
            return $true
        }
        return $false
    }

    [void] AddMembersWithTTL($Members, [timespan] $TTL) {
        foreach ($Member in $Members) {
            try {
                Add-ADGroupMember -Identity $this.DN -Members $Members -MemberTimeToLive $TTL -Confirm:$false
            }
            catch {
                <#Do this if a terminating exception happens#>
            }
        }
    }

    [void] AddTTLToExistingMembers([timespan] $TTL) {
        if (![HADGroup]::TTLCompatible) {
            throw("Please use CheckTTLPrerequisites function prior adding a TTL")
        }
        else {
            [System.Array] $Members = Get-ADGroupMember -Identity $this.DN

            foreach ($Member in $Members) {
                try {
                    Remove-ADGroupMember -Identity $this.DN -Members $Member -Confirm:$false
                }
                catch {
                    <#Do this if a terminating exception happens#>
                }
                try {
                    $this.AddMembersWithTTL($Member, [timespan] $TTL)
                }
                catch {
                    <#Do this if a terminating exception happens#>
                }
            }
        }
    }

    [void] FlushMembers() {
        [Microsoft.ActiveDirectory.Management.ADPrincipal[]] $Members = @()
        try {
            $Members = Get-ADGroupMember -Identity $this.DN
            [Harden]::Log.NewLog(1160, @($this.Name, $Members.Count))
        }
        catch {
            [Harden]::Log.NewLog(1161, $this.Name)
        }

        if ($Members) {
            foreach ($Member in $Members) {
                try {
                    Remove-ADGroupMember -Identity $this.DN -Members $Members -Confirm:$false
                    [Harden]::Log.NewLog(1150, @($Member.Name, $this.Name))
                }
                catch {
                    [Harden]::Log.NewLog(1151, @($Member.Name, $this.Name))
                }
            }
        }
    }

    [void] Create() {
        try {
            New-ADGroup -Name $this.Name -GroupCategory Security -GroupScope DomainLocal -Description $this.Description -Path $this.Pattern
            [Harden]::Log.NewLog("1100", @($this.Name, $this.Pattern))
        }
        catch {
            [Harden]::Log.NewLog("1102", @($this.Name, $this.Pattern))
        }
    }

    [void] Delete() {
        try {
            Remove-ADGroup -Identity $this.DN -Confirm:$false
            [Harden]::Log.NewLog("1110", $this.Name)
        }
        catch {
            [Harden]::Log.NewLog("1111", $this.Name)
        }
    }

    [void] Move() {
        try {
            Move-ADObject -Identity $this.DN -TargetPath $this.Pattern
            [Harden]::Log.NewLog("1130", @($this.Name, $this.Pattern))
        }
        catch {
            [Harden]::Log.NewLog("1110", @($this.Name, $this.Pattern))
        }
    }

}

class HADLocalAdminGroup : HADGroup {

    hidden [string] $AdminPattern = ([Harden]::XmlConfig).Config.Patterns.LocalAdminsPattern.Pattern
    hidden [string] $GlobalAdminPattern = ([Harden]::XmlConfig).Config.Patterns.LocalAdminsPattern.GlobalPattern

    [string] $Pattern

    HADLocalAdminGroup([HADComputer] $Computer) : base() {
        $this.Name = ([Harden]::XmlConfig).Config.DefaultParameters.Naming -replace "%ComputerName%", $Computer.Name
        $this.Description = ("Members of this group will become member of the builtin\administrators group of {0}." -f $Computer.Name)

        if (!$Computer.Entity) {
            $this.Pattern = (($this.GlobalAdminPattern -replace "%DomainDN%", (Get-ADDomain).DistinguishedName) -replace "%Tier%", $Computer.Tier)
        }
        else {
            $this.Pattern = (($this.AdminPattern -replace "%DomainDN%", (Get-ADDomain).DistinguishedName) -replace "%Tier%", $Computer.Tier) -replace "%Entity%", $Computer.Entity
        }
        
        if ($this.SearchGroup()) {
            if ($this.Pattern -ne $this.Path) {

                $this.Path = $this.Pattern

                $this.FlushMembers()
                $this.ResetOwner()
                $this.ResetACL()
                $this.Move()
            }
        }
        else {
            $this.Create()
        }
    }

    static [void] RemoveNotMatchingGroups() {
        [string] $Naming = (([Harden]::XmlConfig).Config.DefaultParameters.Naming -replace "%ComputerName%", "")
        [string] $NamingWildcard = (([Harden]::XmlConfig).Config.DefaultParameters.Naming -replace "%ComputerName%", "") + "*"
        [Microsoft.ActiveDirectory.Management.ADGroup[]] $LocalAdminsGroups = $null

        try {
            $LocalAdminsGroups = Get-ADGroup -Filter { Name -like $NamingWildcard } -ErrorAction Stop
            [Harden]::Log.NewLog("1122", @($LocalAdminsGroups.Count, $NamingWildcard))
        }
        catch {
            [Harden]::Log.NewLog("1123", $NamingWildcard)
            exit
        }
        [string[]] $ConcatenedComputerGroups = (Get-ADComputer -Filter *).Name | ForEach-Object {
            $Naming + $_
        }
        
        foreach ($LocalAdminsGroup in $LocalAdminsGroups) {
            if (!($LocalAdminsGroup.Name -in $ConcatenedComputerGroups)) {
                try {
                    Remove-ADGroup $LocalAdminsGroup.DistinguishedName -confirm:$false
                    [Harden]::Log.NewLog("1131", $LocalAdminsGroup.Name)
                }
                catch {
                    [Harden]::Log.NewLog("1111", $LocalAdminsGroup.Name)
                }
            }
        }
        
    }

    static [void] RemoveNotMatchingGroups($ComputerName) {
        [string] $Naming = (([Harden]::XmlConfig).Config.DefaultParameters.Naming -replace "%ComputerName%", $ComputerName)

        try {
            Get-ADComputer $ComputerName
        }
        catch {
            try {
                $LocalAdminsGroup = Get-ADGroup -Filter { Name -eq $Naming } -ErrorAction Stop
                $Path = ($LocalAdminsGroup.DistinguishedName).Substring(($LocalAdminsGroup.DistinguishedName).IndexOf(",") + 1)
                [Harden]::Log.NewLog("1120", @($Naming, $Path))
            }
            catch {
                [Harden]::Log.NewLog("1121", $Naming)
                exit
            }

            try {
                Remove-ADGroup $LocalAdminsGroup.DistinguishedName -confirm:$false
                [Harden]::Log.NewLog("1110", $LocalAdminsGroup.Name)
            }
            catch {
                [Harden]::Log.NewLog("1111", $LocalAdminsGroup.Name)
            }
        }
            
        
    }

    [bool] SearchGroup() {
        try {
            $Group = Get-ADGroup -Identity $this.Name
            $this.DN = $Group.DistinguishedName
            $this.Path = ($this.DN).Substring(($this.DN).IndexOf(",") + 1)
            [Harden]::Log.NewLog(1120, @($this.Name, $this.Path))
            return $true
        }
        catch {
            $this.Path = $this.Pattern
            [Harden]::Log.NewLog(1121, $this.Name)
            return $false
        }
    }
}
