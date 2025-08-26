# CHANGE LOG: GroupPolicies  
Below information details all changes in TasksSequence_HardenAD.xml/GroupPolicies done in this edition.  
 
---  
### WMI Filters
 
Status|Name|Source
---|---|---  
No change|Windows-10|Windows-10.mof
No change|Windows-11|Windows-11.mof
No change|Windows-2000-XP|Windows-2000-XP.mof
No change|Windows-2003-2003R2-NoDC|Windows-2003-2003R2-NoDC.mof
No change|Windows-2008-Vista-and-Newer|Windows-2008-Vista-and-Newer.mof
No change|Windows-2008-NoDC|Windows-2008-NoDC.mof
No change|Windows-2008R2-NoDC|Windows-2008R2-NoDC.mof
No change|Windows-2012-NoDC|Windows-2012-NoDC.mof
No change|Windows-2012|Windows-2012.mof
No change|Windows-2012R2-NoDC|Windows-2012R2-NoDC.mof
No change|Windows-2012R2|Windows-2012R2.mof
No change|Windows-2016-and-Newer-NoDC|Windows-2016-and-Newer-NoDC.mof
No change|Windows-2016-and-Newer|Windows-2016-and-Newer.mof
No change|Windows-2016-NoDC|Windows-2016-NoDC.mof
No change|Windows-2016|Windows-2016.mof
No change|Windows-2019-NoDC|Windows-2019-NoDC.mof
No change|Windows-2019|Windows-2019.mof
No change|Windows-2022-NoDC|Windows-2022-NoDC.mof
No change|Windows-2022|Windows-2022.mof
No change|Windows-7|Windows-7.mof
No change|Windows-8|Windows-8.mof
No change|Windows-Legacy-NoDC|Windows-Legacy-NoDC.mof
No change|Windows-Legacy-OS-Clients|Windows-Legacy-OS-Clients.mof
No change|Windows-Legacy-OS-Servers-NoDC|Windows-Legacy-OS-Servers-NoDC.mof
No change|Windows-Legacy-OS-Servers|Windows-Legacy-OS-Servers.mof
No change|Windows-Legacy|Windows-Legacy.mof
No change|Windows-NoDC|Windows-NoDC.mof
No change|Windows-OS-Clients|Windows-OS-Clients.mof
No change|Windows-OS-Servers-NoDC|Windows-OS-Servers-NoDC.mof
No change|Windows-OS-Servers|Windows-OS-Servers.mof
No change|Windows-Supported-NoDC|Windows-Supported-NoDC.mof
No change|Windows-Supported-OS-Clients|Windows-Supported-OS-Clients.mof
No change|Windows-Supported-OS-Servers-NoDC|Windows-Supported-OS-Servers-NoDC.mof
No change|Windows-Supported-OS-Servers|Windows-Supported-OS-Servers.mof
No change|Windows-Supported|Windows-Supported.mof
No change|Windows-Vista|Windows-Vista.mof
No change|Windows-x64|Windows-x64.mof
No change|Windows-x64-NoDC|Windows-x64-NoDC.mof
No change|Windows-x86|Windows-x86.mof
No change|Windows-x86-NoDC|Windows-x86-NoDC.mof
No change|Windows-PDC|Windows-PDC.mof
Added|Windows-11_24h2-and-server-2025-NoDC|Windows-11_24h2-and-server-2025-NoDC.mof
Added|Legacy-LAPS-Deployment-x32|Legacy-LAPS-Deployment-x32.mof
Added|Legacy-LAPS-Deployment-x64|Legacy-LAPS-Deployment-x64.mof
Added|Legacy-LAPS-Configuration|Legacy-LAPS-Configuration.mof
Added|Windows-Laps-Supported|Windows-Laps-Supported.mof
  
### GPO
 
GPO|Status  
---|---  
HAD-Auto-Update-S1-Thu-0h-Srv|Updated (files mismatch)
HAD-Auto-Update-S1-Thu-1h-Srv|No change
HAD-Auto-Update-S3-Thu-0h-Srv|No change
HAD-Auto-Update-S3-Thu-1h-Srv|No change
HAD-Auto-Update-S4-Thu-0h-Srv|No change
HAD-Auto-Update-S4-Thu-1h-Srv|No change
HAD-Auto-Update-Win10-11|No change
HAD-Auto-Update-Win7-8|No change
HAD-BitLocker-TPMOnly-Enabled-Win10-11|Updated (new backupID)
HAD-BitLocker-PIN-Enabled-Win10-11|Updated (new backupID)
HAD-BitLocker-USB-Win10-11|No change
HAD-BloodHound-Mitigation|No change
HAD-Camera-on-lockon-Disabled|No change
HAD-DCLocaltor-Configuration|No change
HAD-DistributedFileSystem-Disabled|No change
HAD-Firewall-Audit-Only|No change
HAD-Firewall-Block-Inbound|No change
HAD-GPO-Refresh-Cycle|Updated (new backupID)
HAD-IPv6-Disabled|No change
HAD-Kerberos-AES-Enabled|No change
HAD-LAPS-Configuration|No change
HAD-LAPS-X64-Deployment|No change
HAD-LAPS-X86-Deployment|No change
HAD-LDAP-Audit-Enabled|No change
HAD-LDAP-CBT-Enabled|No change
HAD-LDAP-Client-Signing-Not-Required|No change
HAD-LDAP-Client-Signing-Required|No change
HAD-LDAP-Server-Signing-Required|No change
HAD-LDAP-Audit-Disabled|No change
HAD-LLMNR-Disabled|No change
HAD-LMHASH-Disabled|No change
HAD-NTLM-Audit-Enabled|No change
HAD-NTLM1-LMx-Disabled|No change
HAD-NTLMv2-128bits-Required|No change
HAD-LocalAdmins-Paw|Updated (files mismatch)
HAD-LocalAdmins-PawT0|Updated (files mismatch)
HAD-LocalAdmins-PawT12L|Updated (files mismatch)
HAD-LocalAdmins-T0-Srv|Updated (files mismatch)
HAD-LocalAdmins-T0-Wks|Updated (files mismatch)
HAD-LocalAdmins-T1|Updated (files mismatch)
HAD-LocalAdmins-T1L|Updated (files mismatch)
HAD-LocalAdmins-T2|Updated (files mismatch)
HAD-LocalAdmins-T2L|Updated (files mismatch)
HAD-Local-Accounts-Config|No change
HAD-LoginRestrictions-Paw|Updated (new backupID)
HAD-LoginRestrictions-PawT0|No change
HAD-LoginRestrictions-PawT12L|No change
HAD-LoginRestrictions-T0|Updated (files mismatch)
HAD-LoginRestrictions-T1|Updated (files mismatch)
HAD-LoginRestrictions-T1L|Updated (files mismatch)
HAD-LoginRestrictions-T2|Updated (files mismatch)
HAD-LoginRestrictions-T2L|Updated (files mismatch)
HAD-Logon-Cache-0|No change
HAD-MSLive-Accounts-Disabled|No change
HAD-NBT-NS-Disabled|Updated (new backupID)
HAD-PageFile-Shutdown-Cleared|No change
HAD-Print-Spooler-Disabled|No change
HAD-Remote-Assistance-Disabled|No change
HAD-Screenlock-Enabled|No change
HAD-Secure-NetLogon|No change
HAD-Svc-Browser-Disabled|No change
HAD-Svc-Server-Disabled|No change
HAD-UAC-Enabled|No change
HAD-WDigest-Disabled|No change
HAD-Windows-Defender-Config|No change
HAD-WinRM-Basic-Digest-Auth-Disabled|Updated (new backupID)
HAD-WebProxyAutoDiscovery-Disabled|Updated (new backupID)
HAD-PowerShell-Logs|No change
HAD-Security-Logs|No change
HAD-TS-Local-admins-groups|Updated (new backupID)
HAD-TS-PDC-Flush-admin-groups|Updated (new backupID)
HAD-TS-Reset-Computer-Sddl|Updated (new backupID)
HAD-RDP-Disabled|No change
HAD-RDP-Enabled|No change
HAD-RDP-NLA-Enabled|No change
HAD-Smart-Card-Required|No change
HAD-SMB-Signing-Configuration|Updated (new backupID)
HAD-SMB1-Audit-Enabled|Updated (new backupID)
HAD-SMB1-Client-Only-Enabled|Updated (new backupID)
HAD-SMB1-Disabled|Updated (new backupID)
HAD-SMB1-Enabled|Updated (new backupID)
HAD-SMB1-Server-Only-Enabled|Updated (new backupID)
HAD-UNC-Hardened-Path|Updated (files mismatch)
HAD-SSL2-SSL3-Disabled|Updated (new backupID)
HAD-SSL2-SSL3-Enabled|Updated (new backupID)
HAD-TLS-1_0-Disabled|Updated (new backupID)
HAD-TLS-1_0-Enabled|Updated (new backupID)
HAD-TLS-1_1-Disabled|Updated (new backupID)
HAD-TLS-1_1-Enabled|Updated (new backupID)
HAD-TLS-1_2-Enabled|Updated (new backupID)
HAD-DC-Allow-Computer-Account-ReUse|Updated (files mismatch)
HAD-QwantSearch|No change
HAD-BitLocker-RecoveryKey-Required|Added
HAD-LocalRDU-Paw|Added
HAD-LocalRDU-PawT0|Added
HAD-LocalRDU-PawT12L|Added
HAD-LocalRDU-T0-Srv|Added
HAD-LocalRDU-T0-Wks|Added
HAD-LocalRDU-T1|Added
HAD-LocalRDU-T1L|Added
HAD-LocalRDU-T2|Added
HAD-LocalRDU-T2L|Added
HAD-Logon-Cache-3|Added
HAD-Applocker-Win10-11|Added
HAD-CredentialManager-Disabled|Added
HAD-DEP-Config|Added
HAD-DMA-Protection|Added
HAD-Drivers-Config|Added
HAD-Inactivity-Config|Added
HAD-LSASS-Audit|Added
HAD-LSASS-Config|Added
HAD-mDNS-Disabled|Added
HAD-NTLM-Disabled|Added
HAD-Smart-Card-Config|Added
HAD-SMB-Config-24H2|Added
HAD-UAC-Advanced-Enabled|Added
HAD-User-Config|Added
HAD-Virtualization-Based-Protection-Enabled|Added
HAD-Windows-LAPS|Added
HAD-FIPS-Enabled|Removed
HAD-Logon-Cache-2|Removed
HAD-TLS-1_2-Disabled|Removed
  
**HAD-Auto-Update-S1-Thu-0h-Srv:**  
> File removed: trompette.tmp  
  
  
  
  
  
  
  
  
**HAD-BitLocker-TPMOnly-Enabled-Win10-11:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-BitLocker-PIN-Enabled-Win10-11:**  
> New backup ID that indicates potential changes.  
  
  
  
  
  
  
  
  
  
**HAD-GPO-Refresh-Cycle:**  
> New backup ID that indicates potential changes.  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**HAD-LocalAdmins-Paw:**  
> File modified: translation.xml  
  
**HAD-LocalAdmins-PawT0:**  
> File modified: translation.xml  
  
**HAD-LocalAdmins-PawT12L:**  
> File modified: translation.xml  
  
**HAD-LocalAdmins-T0-Srv:**  
> File modified: translation.xml  
  
**HAD-LocalAdmins-T0-Wks:**  
> File modified: translation.xml  
  
**HAD-LocalAdmins-T1:**  
> File modified: translation.xml  
  
**HAD-LocalAdmins-T1L:**  
> File modified: translation.xml  
  
**HAD-LocalAdmins-T2:**  
> File modified: translation.xml  
  
**HAD-LocalAdmins-T2L:**  
> File modified: translation.xml  
  
  
**HAD-LoginRestrictions-Paw:**  
> New backup ID that indicates potential changes.  
  
  
  
  
**HAD-LoginRestrictions-T0:**  
> File modified: Backup.xml  
> File modified: bkupInfo.xml  
> File modified: gpreport.xml  
> File modified: HardenAD.migtable  
  
**HAD-LoginRestrictions-T1:**  
> File modified: Backup.xml  
> File modified: bkupInfo.xml  
> File modified: gpreport.xml  
> File modified: HardenAD.migtable  
  
**HAD-LoginRestrictions-T1L:**  
> File modified: Backup.xml  
> File modified: bkupInfo.xml  
> File modified: gpreport.xml  
> File modified: HardenAD.migtable  
  
**HAD-LoginRestrictions-T2:**  
> File modified: Backup.xml  
> File modified: bkupInfo.xml  
> File modified: gpreport.xml  
> File modified: HardenAD.migtable  
  
**HAD-LoginRestrictions-T2L:**  
> File modified: Backup.xml  
> File modified: bkupInfo.xml  
> File modified: gpreport.xml  
> File modified: HardenAD.migtable  
  
  
  
**HAD-NBT-NS-Disabled:**  
> New backup ID that indicates potential changes.  
  
  
  
  
  
  
  
  
  
  
  
  
**HAD-WinRM-Basic-Digest-Auth-Disabled:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-WebProxyAutoDiscovery-Disabled:**  
> New backup ID that indicates potential changes.  
  
  
  
  
**HAD-TS-Local-admins-groups:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-TS-PDC-Flush-admin-groups:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-TS-Reset-Computer-Sddl:**  
> New backup ID that indicates potential changes.  
  
  
  
  
  
  
**HAD-SMB-Signing-Configuration:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-SMB1-Audit-Enabled:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-SMB1-Client-Only-Enabled:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-SMB1-Disabled:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-SMB1-Enabled:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-SMB1-Server-Only-Enabled:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-UNC-Hardened-Path:**  
> File modified: Backup.xml  
> File modified: bkupInfo.xml  
> File modified: gpreport.xml  
> File modified: comment.cmtx  
  
**HAD-SSL2-SSL3-Disabled:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-SSL2-SSL3-Enabled:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-TLS-1_0-Disabled:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-TLS-1_0-Enabled:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-TLS-1_1-Disabled:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-TLS-1_1-Enabled:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-TLS-1_2-Enabled:**  
> New backup ID that indicates potential changes.  
  
  
**HAD-DC-Allow-Computer-Account-ReUse:**  
> File modified: Backup.xml  
> File modified: bkupInfo.xml  
> File modified: gpreport.xml  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
