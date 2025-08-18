<img src="https://hardenad.net/wp-content/uploads/2021/12/Logo-HARDEN-AD-Horizontal-RVB@4x-300x86.png" align="center">  

This is the version **2.9.9** of the Hardening Active Directory project by then Harden Community. Please refer to the release update logs to review the change.

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

# 🤝 Contributing
We welcome contributions! Feel free to submit issues, feature requests, or pull requests. See CONTRIBUTING.md for more details.

# 📄 License
This project is licensed under the GNU GPL3 License. See LICENSE for more information.
