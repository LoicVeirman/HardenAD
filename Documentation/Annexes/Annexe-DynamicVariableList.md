# Variables list

## Version 2.10.0
  
TranslateFrom | TranslateTo | Description
---|---|---
%Administrators%|Administrators| Domain Group *Administrator* (dynamically translated to proper regional language)
%DomainAdmins%|Domain Admins| Domain group *Domain Admins* (dynamically translated to proper regional language)
%SchemaAdmins%|Schema Admins| Domain group *Schema Admins* (dynamically translated to proper regional language)
%EnterpriseAdmins%|Enterprise Admins| Domain group *Enterprise Admins* (dynamically translated to proper regional language)
%Users%|Users| Domain group *Users* (dynamically translated to proper regional language)
%Guest%|Guest| Domain user *Guest* (dynamically translated to proper regional language)
%Guests%|Guests| Domain group *Guests* (dynamically translated to proper regional language)
%AuthenticatedUsers%|Authenticated Users| Domain Group *Authenticated Users* (dynamically translated to proper regional language)
%RemoteDesktopUsers%|Remote Desktop Users| Domain group *Remote Desktop USers* (dynamically translated to proper regional language)
%NetBios%|HARDEN| Running domain netbios name
%domaindns%|HARDEN.AD| Running domain dns name
%DN%|DC=HARDEN,DC=AD| Running domain distinguishedName
%RootNetBios%|HARDEN| Running domain *Forest root domain* name
%domain%|HARDEN| Running domain *Forest root netbios domain* name
%Rootdomaindns%|HARDEN.AD| Running domain *Forest root dns domain* name
%RootDN%|DC=HARDEN,DC=AD| Running domain *forest root domain* distinguishedName
%DnsAdmins%|DnsAdmins| Domain group DnsAdmins
%isT0%|T0| Shortened name to identify a Tier 0 object (group name, gpo, ...)
%isT1%|T1| Shortened name to identify a Tier 1 object (group name, gpo, ...)
%isT2%|T2| Shortened name to identify a Tier 2 object (group name, gpo, ...)
%isT1leg%|T1L| Shortened name to identify a Tier 1 Legacy object (group name, gpo, ...)
%isT2Leg%|T2L| Shortened name to identify a Tier 2 Legacy object (group name, gpo, ...)
%t0-global%|L-S-T0| Group name: all Tier 0 admins groups
%t1-global%|L-S-T1| Group name: all Tier 1 admins groups
%t2-global%|L-S-T2| Group name: all Tier 2 admins groups
%t1l-global%|L-S-T1L| Group name: all Tier 1 legacy admins groups
%t2l-global%|L-S-T2L| Group name: all Tier 2 legacy admins groups
%t0-managers%|G-S-T0-Managers| Group name: Tier 0 managers
%t0-operators%|G-S-T0-Operators| Groupe name: Tier 0 Operators
%pamt0-logon%|L-S-T0-Pam| Group name: PAM Group for Tier 0
%pamt1-logon%|L-S-T1-Pam| Group name: PAM Group for Tier 1
%paml1-logon%|L-S-T1L-Pam| Group name: PAM Group for Tier 1 Legacy
%pamt2-logon%|L-S-T2-Pam| Group name: PAM Group for Tier 2
%paml1-logon%|L-S-T2L-Pam| Group name: PAM Group for Tier 2 Legacy
%t0-localAdmin-servers%|L-S-T0-LocalAdmins-Servers| Group name: Server Local admins in Tier 0
%t0-localAdmin-workstations%|L-S-T0-LocalAdmins-Workstations| Group name: workstation local admins in Tier 0
%t1-managers%|G-S-T1-Managers| Group name: Tier 1 managers
%t1-administrators%|G-S-T1-Administrators| Group name: Tier 1 administrators
%t1-operators%|G-S-T1-Operators| Group name: Tier 1 operators
%t1-localAdmin-servers%|L-S-T1-LocalAdmins-Servers|Group name: Server Local admins in Tier 1
%t2-managers%|G-S-T2-Managers| Group name: Tier 1 managers
%t2-administrators%|G-S-T2-Administrators| Group name: Tier 2 administrators
%t2-operators%|G-S-T2-Operators| Group name: Tier 2 operators
%t2-localAdmin-workstations%|L-S-T2-LocalAdmins-Workstations|Group name: Workstation Local admins in Tier 2
%t1l-Operators%|G-S-L1-Operators| Group name: Tier 1 Legacy operators
%t2l-operators%|G-S-L2-Operators| Group name: Tier 2 Legacy operators
%t1l-localAdmin-servers%|L-S-T1L-LocalAdmins-Servers| Group name: Server local admins in Tier 1 Legacy
%t2l-localAdmin-workstations%|L-S-T2L-LocalAdmins-Workstations| Group name: Workstation local admins in Tier 2 Legacy
%T1-LAPS-PasswordReset%|L-S-T1-DELEG-LAPS-PwdReset| Group name: Password Reset Users on Tier 1, Legacy included, computer objects
%T2-LAPS-PasswordReset%|L-S-T2-DELEG-LAPS-PwdReset| Group name: Password Reset Users on Tier 2, Legacy included, computer objects
%T1-LAPS-PasswordReader%|L-S-T1-DELEG-LAPS-PwdRead| Group name: Password read Users on Tier 1, Legacy included, computer objects
%T2-LAPS-PasswordReader%|L-S-T2-DELEG-LAPS-PwdRead| Group name: Password read Users on Tier 2, Legacy included, computer objects
%T0-DLG-CptrDomJoin%|L-S-T0-DELEG-Computer - Join Domain| Group name: Delegation group to join a computer to the Tier 0
%T1-DLG-CptrDomJoin%|L-S-T1-DELEG-Computer - Join Domain| Group name: Delegation group to join a computer to the Tier 1
%T2-DLG-CptrDomJoin%|L-S-T2-DELEG-Computer - Join Domain| Group name: Delegation group to join a computer to the Tier 2
%Prefix%|L-S| Prefix used for Domain Local Security groups (with no ending char)
%Prefix-domLoc%|L-S-| Prefix used for Domain Local Security groups (with ending char)
%Prefix-global%|G-S-| Prefix used for Global Security groups (with ending char)
%Groups_Computers%|LocalAdmins-%ComputerName%| Suffix used to compute LocalAdmins groups. If changed, do not forget to update "HAD-LocalAdmins-Tx" to reflect this change (before importing)
%OU-ADM%|_Administration| OU Name: Administration OU (top level)
%OU-ADM-PAM%"|PAM|OU Name: Privileged Administration Management OU (child of admin / Tier )
%OU-ADM-LOCALADMINS%|LocalAdmins| OU Name: Default name used for the LocalAdmins group objects (child of Admin / Tier X / Groups)
%OU-ADM-DELEGATION%|Deleg| OU Name: Default name used for the delegation group objects (child of Admin / Tier X)
%OU-ADM-GROUPS%|Groups|OU Name: Default name used for the group objects (child of Admin / Tier X)
%OU-ADM-USERS%|Users|OU Name: Default name used for the admin user account objects (child of Admin / Tier X)
%OU-ADM-GPO%|GPO|OU Name: Default name used for the GPO group objects (child of Admin / Tier X / Groups)
%OU-ADM-GPO-APPLY%|Apply| OU Name: Default name used for the APPLY GPO group objects (child of Admin / Tier X / Groups / GPO)
%OU-ADM-GPO-DENY%|Deny|OU Name: Default name used for the DENY GPO group objects (child of Admin / Tier X / Groups / GPO)
%OU-ADM-T0%|Tier 0|OU Name: Default name used for the Tier 0 administration objects (child of Admin)
%OU-ADM-T1%|Tier 1|OU Name: Default name used for the Tier 1 administration objects (child of Admin)
%OU-ADM-L1%|Tier 1 Legacy|OU Name: Default name used for the Tier 1 Legacy administration objects (child of Admin)
%OU-ADM-T2%|Tier 2|OU Name: Default name used for the Tier 2 administration objects (child of Admin)
%OU-ADM-L2%|Tier 2 Legacy|OU Name: Default name used for the Tier 2 Legacy administration objects (child of Admin)
%OU-ADM-Groups-T0%|%OU-ADM-GROUPS%,OU=%OU-ADM-T0%|OU Path: DistinguishedName to the Tier 0 Group OU (legacy code)
%OU-ADM-Groups-T1%|%OU-ADM-GROUPS%,OU=%OU-ADM-T1%|OU Path: DistinguishedName to the Tier 1 Group OU (legacy code)
%OU-ADM-Groups-T2%|%OU-ADM-GROUPS%,OU=%OU-ADM-L1%|OU Path: DistinguishedName to the Tier 1 Legacy Group OU (legacy code)
%OU-ADM-Groups-L1%|%OU-ADM-GROUPS%,OU=%OU-ADM-T2%|OU Path: DistinguishedName to the Tier 2 Group OU (legacy code)
%OU-ADM-Groups-L2%|%OU-ADM-GROUPS%,OU=%OU-ADM-L2%|OU Path: DistinguishedName to the Tier 2 Legacy Group OU (legacy code)
%OU-PRD-DISABLED%|Disabled|OU Name: disabled object (child of OU containing users, service or computer objects)
%OU-PRD-AADSYNC%|DoNotSync|OU Name: Object not synched with EntraID (Child of OU containing sync'd objects)
%OU-PRD-GROUPS%|Groups|OU Name: OU containing group objects
%OU-PRD-USERS%|Users|OU Name: OU containing user objects (not service accounts)
%OU-PRD-SERVICES%|Services|OU Name: OU containing service accounts (user objects)
%OU-PRD-WORKSTATIONS%|Workstations|OU Name: OU containing Tier 2 computer objects (client OS)
%OU-PRD-SERVERS%|Servers|OU Name: OU containing Tier 1 computer objects (server OS)
%OU-PRD-EXCHANGE%|Exchange|OU Name: OU dedicated to mail systems (exchange on premise or online)
%OU-PRD-EXCHANGE-CONTACTS%|Contacts|OU Name: OU containing contact objects
%OU-PRD-EXCHANGE-DL%|Distribution Lists|OU Name: OU containing objects used as distribution list
%OU-PRD-EXCHANGE-SHAREDMBX%|Shared Mailboxes|OU Name: OU containing user account linked to shared mailboxes
%OU-PRD-EXCHANGE-RESOURCES%|Resources|OU Name: OU containing objects linked to an Exchange resource (room, car, computer, ...)
%OU-PRD-T0%|Harden_T0|OU Name: Tier 0
%OU-PRD-T12%|Harden_T12|OU Name: Tier 1 and Tier 2
%OU-PRD-T12-Provisioning%|Provisioning|OU Name: Default object location on creation
%OU-PRD-T12-Provisioning-User%|Users|OU Name: Default user object location on creation (child of provisioning)
%OU-PRD-T12-Provisioning-Cptr%|Computers|OU Name: Default computer object location on creation (child of provisioning)
%OU-PRD-TL%|Harden_TL|OU Name: Tier Legacy
%pwdLength%|16|Password length for newly generated password by the script
%pwdNonAlphaNumChar%|3|Minimum non-alphanumeric car to be present in the generated password
