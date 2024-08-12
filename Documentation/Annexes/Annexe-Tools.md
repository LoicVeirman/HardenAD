# ANNEXE: TOOLS  
Version 2024/07/30  
  
## Goals  
This document list tools available with Harden AD and how to use them.  

## Invoke-HardenADTask  
Script used to select which tasks should be activated in the script sequence through a graphic user interface.  

## Invoke-HardenADGpo  
Script used to select which GPO should be activated in the script sequence through a graphic user interface.  

## Keepass-2.57
Keepass binaries used by HardenAD to store password when creating a new user.
Now a custom password could be used.

### KPScript 2.57
Additionnal Keepass plugin used there to apply the custom database password.
  
## Scripts Fix  
### Fix-LocalAdminGroups
Fix the local Admin Group name issue in HAD-LocalAdmin GPO (up-to release 2.9.8 QuickFix May 2024).  
Replace the wrong value in translation.xml to match with the correct one in the following GPO folders:  
> HAD-LocalAdmins-Paw  
> HAD-LocalAdmins-PawT0  
> HAD-LocalAdmins-PawT12L  
> HAD-LocalAdmins-T0-Srv  
> HAD-LocalAdmins-T0-Wks  
> HAD-LocalAdmins-T1  
> HAD-LocalAdmins-T1L  
> HAD-LocalAdmins-T2  
> HAD-LocalAdmins-T2L  

This have to be run prior to the GPO import. If you already have imported the GPO in concern, you can simply delete them from your domain, run this script and then rerun harden AD - the GPO will be reimported.  
  
### Fix-LoginRestriction
Fix the Guest account issue in Login Restirction GPO.  
Replace the *Guest* account per the *Guests* Group in the following GPO:   
> HAD-LoginRestrictions-T0  
> HAD-LoginRestrictions-T1  
> HAD-LoginRestrictions-T2  
> HAD-LoginRestrictions-T1L  
> HAD-LoginRestrictions-T2L  
  
This have to be run prior to the GPO import. If you already have imported the GPO in concern, you can simply delete them from your domain, run this script and then rerun harden AD - the GPO will be reimported.  
  
## Scripts import  
### Import-AdminAccounts  
** BEWARE ** *Use it with caution!*
This is not a production tool, it has only be designed to prepare customer environment. The community gracefully share it with you, but you'll have to adapt it to your needs. The CSV is not provided.
  
This function will add to the *Accounts* section all the CSV data.
  
## Scripts Manage  
### Clean-ADComputerACL
this script will parse again a target all computer objects and:   
1. Set computer object owner to Domain Admins.  
2. Reset Computer ACL to their default value.  
  
This script is required when non domain admins user add computer to the domain and should be run at least once before running HardenAD (a mecanism is in place to handle this through scheduling).  
  
### Reset-ADComputerACLandOwner
this script will execute against a single computer object and:   
1. Set computer object owner to Domain Admins.  
2. Reset Computer ACL to their default value.  
  
### Reset-adminSDholderBadObjects
This script reset the admincount attribute, the owner and the ACL of a user or group object if the account is not really protected by AdminSDholder.  

When a user or a group object is moved to an adminSDHolder protected group, the admincount of the object is set to 1 and will not be removed even if this one is moved away from those groups.
When adminCount is set to 1, the ACL inheritance for this object is broken and its ACL are replaced by the one from the adminSDholder - this could lead to a security risks if not remediate.
The script seek for objects with the adminCount equal to 1 and not member of a protect adminSDholder group, then clear the attribute, reset the ACL and change the object owner accordingly.
  
This script is tailored to reset authorization upon a one-time call (mainly to run through a schedule task).
