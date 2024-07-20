<img src="https://hardenad.net/wp-content/uploads/2021/12/Logo-HARDEN-AD-Horizontal-RVB@4x-300x86.png" align="center">
This is the version 2.9.9 of the Hardening Active Directory project by then Harden Community. 
Feel free to use it and adapt following your needs!

## Release update list
*Bugs:* 
> 1. Fixed a misconfiguration in HAD-LoginRestrictions-Tx, where the Deny Network Logon was set on the guest user instead of the guests group.  

*Tools:*
> 1. Added a script to fix HAD-LoginRestrictions-Tx bug (see upper). to be used on 2.9.8 edition BEFORE implementing it.  

*Enhancements:*
> 1. Clean-up of useless files/folders (.vs, .git, .dsStore, ...)  
> 2. Added a .gitignore file to ease maintenance  
 
## Just a word...
Welcome to our GitHub Repo dedicated to enhance the security of Active Directory. We both believe in a world were knowledge have to be shared, especialy when we are talking of protecting companies against cyber attacks. Our IT journey drove us to many situation in which we had to harden an existing directory hierarchy, most oftenly lacking of a security posture due to a lack of technical knowledge or usefull guidance.

This script is intended to assist you in setting-up a hardened directory, based on a strategy derivated from the Microsoft's red-forest model (also known as ESEA). 

## Documentation...
You can review our documentation here:
Administrator Guide:  
> https://hardenad.net/wp-content/uploads/2022/12/Harden-AD-2.9-User-Manual.pdf  

Quick Setup for lazy guys: 
> https://hardenad.net/wp-content/uploads/2023/03/Harden-AD-2.9-deploiement-et-personnalisation-du-modele.pdf  

AD Security Training Simplified: 
> https://hardenad.net/wp-content/uploads/2022/08/Harden-AD-formation-AD-cybsersecurite.pdf  

## Some videos (French speaks)
When Guillaume demonstrate Harden AD: https://www.linkedin.com/events/7132717233872474112/comments/
