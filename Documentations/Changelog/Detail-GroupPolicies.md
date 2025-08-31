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
HAD-Auto-Update-S1-Thu-0h-Srv|GPO unmodified
HAD-Auto-Update-S1-Thu-1h-Srv|GPO unmodified
HAD-Auto-Update-S3-Thu-0h-Srv|GPO unmodified
HAD-Auto-Update-S3-Thu-1h-Srv|GPO unmodified
HAD-Auto-Update-S4-Thu-0h-Srv|GPO unmodified
HAD-Auto-Update-S4-Thu-1h-Srv|GPO unmodified
HAD-Auto-Update-Win10-11|GPO unmodified
HAD-Auto-Update-Win7-8|GPO unmodified
HAD-BitLocker-TPMOnly-Enabled-Win10-11|GPO updated
HAD-BitLocker-PIN-Enabled-Win10-11|GPO updated
HAD-BitLocker-USB-Win10-11|GPO unmodified
HAD-BloodHound-Mitigation|GPO unmodified
HAD-Camera-on-lockon-Disabled|GPO unmodified
HAD-DCLocaltor-Configuration|GPO unmodified
HAD-DistributedFileSystem-Disabled|GPO unmodified
HAD-Firewall-Audit-Only|GPO unmodified
HAD-Firewall-Block-Inbound|GPO unmodified
HAD-GPO-Refresh-Cycle|GPO updated
HAD-IPv6-Disabled|GPO unmodified
HAD-Kerberos-AES-Enabled|GPO unmodified
HAD-LAPS-Configuration|GPO unmodified
HAD-LAPS-X64-Deployment|GPO unmodified
HAD-LAPS-X86-Deployment|GPO unmodified
HAD-LDAP-Audit-Enabled|GPO unmodified
HAD-LDAP-CBT-Enabled|GPO unmodified
HAD-LDAP-Client-Signing-Not-Required|GPO unmodified
HAD-LDAP-Client-Signing-Required|GPO unmodified
HAD-LDAP-Server-Signing-Required|GPO unmodified
HAD-LDAP-Audit-Disabled|GPO unmodified
HAD-LLMNR-Disabled|GPO unmodified
HAD-LMHASH-Disabled|GPO unmodified
HAD-NTLM-Audit-Enabled|GPO unmodified
HAD-NTLM1-LMx-Disabled|GPO unmodified
HAD-NTLMv2-128bits-Required|GPO unmodified
HAD-LocalAdmins-Paw|GPO updated
HAD-LocalAdmins-PawT0|GPO updated
HAD-LocalAdmins-PawT12L|GPO updated
HAD-LocalAdmins-T0-Srv|GPO updated
HAD-LocalAdmins-T0-Wks|GPO updated
HAD-LocalAdmins-T1|GPO updated
HAD-LocalAdmins-T1L|GPO updated
HAD-LocalAdmins-T2|GPO updated
HAD-LocalAdmins-T2L|GPO updated
HAD-Local-Accounts-Config|GPO unmodified
HAD-LoginRestrictions-Paw|GPO updated
HAD-LoginRestrictions-PawT0|GPO unmodified
HAD-LoginRestrictions-PawT12L|GPO unmodified
HAD-LoginRestrictions-T0|GPO updated
HAD-LoginRestrictions-T1|GPO updated
HAD-LoginRestrictions-T1L|GPO updated
HAD-LoginRestrictions-T2|GPO updated
HAD-LoginRestrictions-T2L|GPO updated
HAD-Logon-Cache-0|GPO unmodified
HAD-MSLive-Accounts-Disabled|GPO unmodified
HAD-NBT-NS-Disabled|GPO updated
HAD-PageFile-Shutdown-Cleared|GPO unmodified
HAD-Print-Spooler-Disabled|GPO unmodified
HAD-Remote-Assistance-Disabled|GPO unmodified
HAD-Screenlock-Enabled|GPO unmodified
HAD-Secure-NetLogon|GPO unmodified
HAD-Svc-Browser-Disabled|GPO unmodified
HAD-Svc-Server-Disabled|GPO unmodified
HAD-UAC-Enabled|GPO unmodified
HAD-WDigest-Disabled|GPO unmodified
HAD-Windows-Defender-Config|GPO unmodified
HAD-WinRM-Basic-Digest-Auth-Disabled|GPO updated
HAD-WebProxyAutoDiscovery-Disabled|GPO updated
HAD-PowerShell-Logs|GPO unmodified
HAD-Security-Logs|GPO unmodified
HAD-TS-Local-admins-groups|GPO updated
HAD-TS-PDC-Flush-admin-groups|GPO updated
HAD-TS-Reset-Computer-Sddl|GPO updated
HAD-RDP-Disabled|GPO unmodified
HAD-RDP-Enabled|GPO unmodified
HAD-RDP-NLA-Enabled|GPO unmodified
HAD-Smart-Card-Required|GPO unmodified
HAD-SMB-Signing-Configuration|GPO updated
HAD-SMB1-Audit-Enabled|GPO updated
HAD-SMB1-Client-Only-Enabled|GPO updated
HAD-SMB1-Disabled|GPO updated
HAD-SMB1-Enabled|GPO updated
HAD-SMB1-Server-Only-Enabled|GPO updated
HAD-UNC-Hardened-Path|GPO updated
HAD-SSL2-SSL3-Disabled|GPO updated
HAD-SSL2-SSL3-Enabled|GPO updated
HAD-TLS-1_0-Disabled|GPO updated
HAD-TLS-1_0-Enabled|GPO updated
HAD-TLS-1_1-Disabled|GPO updated
HAD-TLS-1_1-Enabled|GPO updated
HAD-TLS-1_2-Enabled|GPO updated
HAD-DC-Allow-Computer-Account-ReUse|GPO updated
HAD-QwantSearch|GPO unmodified
HAD-BitLocker-RecoveryKey-Required|GPO added
HAD-LocalRDU-Paw|GPO added
HAD-LocalRDU-PawT0|GPO added
HAD-LocalRDU-PawT12L|GPO added
HAD-LocalRDU-T0-Srv|GPO added
HAD-LocalRDU-T0-Wks|GPO added
HAD-LocalRDU-T1|GPO added
HAD-LocalRDU-T1L|GPO added
HAD-LocalRDU-T2|GPO added
HAD-LocalRDU-T2L|GPO added
HAD-Logon-Cache-3|GPO added
HAD-Applocker-Win10-11|GPO added
HAD-CredentialManager-Disabled|GPO added
HAD-DEP-Config|GPO added
HAD-DMA-Protection|GPO added
HAD-Drivers-Config|GPO added
HAD-Inactivity-Config|GPO added
HAD-LSASS-Audit|GPO added
HAD-LSASS-Config|GPO added
HAD-mDNS-Disabled|GPO added
HAD-NTLM-Disabled|GPO added
HAD-Smart-Card-Config|GPO added
HAD-SMB-Config-24H2|GPO added
HAD-UAC-Advanced-Enabled|GPO added
HAD-User-Config|GPO added
HAD-Virtualization-Based-Protection-Enabled|GPO added
HAD-Windows-LAPS|GPO added
HAD-FIPS-Enabled|GPO removed
HAD-Logon-Cache-2|GPO removed
HAD-TLS-1_2-Disabled|GPO removed
  
  
  
  
  
  
  
  
  
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
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
