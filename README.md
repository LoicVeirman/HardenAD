<p align="left">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://hardenad.net/wp-content/uploads/2025/11/Logo-HARDEN-AD-RVB@4x-texte-Blanc.png">
  <source media="(prefers-color-scheme: light)" srcset="https://hardenad.net/wp-content/uploads/2025/11/Logo-HARDEN-AD-RVB@4x.png">
  <img src="https://github.com/LoicVeirman/HardenAD/blob/main/Logo_hardenad.png" lign="center"/>
</picture>

This is the version **2.9.9** of the Hardening Active Directory project by then Harden Community. Please refer to the release update logs to review the change.

# Special Thanks
A big-Up to **Hugo SANCHEZ**, who worked a lot on this release to deliver a powerfull and efficient edition. Keep-on dude!  


# 🔐 Overview
HardenAD is an open-source toolkit designed to help system and security administrators strengthen the security of Microsoft Active Directory environments. It provides automated checks, actionable recommendations, and remediation scripts to reduce the attack surface and enforce best practices. 

# 🚀 Features
✅ Automated detection of common AD misconfigurations  
📋 Recommendations based on CIS Benchmarks and Microsoft Security Guidelines  
🛠️ Scripts for remediation and hardening  
📊 Reporting to track security improvements over time  
🔌 Modular design for easy customization and extension  

# 👥 Target Audience  
This project is intended for:
* IT administrators managing AD infrastructures  
* Security teams conducting internal audits  
* Penetration testers and red teamers assessing AD environments  
* Anyone looking to improve AD resilience against cyber threats  

# 🎯 Why HardenAD?
Active Directory is a core component of most enterprise networks. Misconfigurations or weak security practices can lead to privilege escalation and full domain compromise. HardenAD helps you proactively secure your AD before attackers exploit its weaknesses by setting a Tier Modeling delegation principle - historically known as ESAE (Enhanced Security Administrative Environment).

# 📦 Getting Started
Download the latest stable edition from this page. Unpack on your PDC __to the root of your target drive__ - this is mandatory to avoid corruption with GPO backup folders on unzip. Once done, unblock all files before running the script:  

``PS:> Get-ChildItem c:\HAD -recurse | unblock-file``

Check the documentation for usage instructions and examples.

# 📚 Documentation
Detailed documentation is available in the docs/ folder. It includes:  
* Setup instructions
* Module descriptions
* Example use cases
* Contribution guidelines

The official documentation is present on the community website (https://hardenad.net).

# ?? Need Help
Use the Discussion tab or the Issue tab to ask directly the author some explanation!  

# 🤝 Contributing
We welcome contributions! Feel free to submit issues, feature requests, or pull requests. See CONTRIBUTING.md for more details.

# 📄 License
This project is licensed under the GNU GPL3 License. See LICENSE for more information.
