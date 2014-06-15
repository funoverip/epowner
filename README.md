INTRODUCTION
============

- This is **"ePolicy 0wner"**, a sexy exploit aginst **McAfee ePolicy Orchestrator** versions 4.6.0 -> 4.6.5

 + Author:  jerome.nokin@gmail.com
 + Blog:  http://funoverip.net
 + Discovered on:  20 November 2012 
 + Fixed on:  25 April 2013

- In short, this tool registers a rogue agent on the ePo server and then takes advantage of the following vulnerabilities to perform multiple actions :

 + **CVE-2013-0140** : Pre-auth SQL Injection
 + **CVE-2013-0141** : Pre-auth Directory Path Traversal

- The tool manages the following actions, called "mode" :

 + **--register**              Register a new agent on the ePo server (it's free)
 + **--check**                 Check the SQL Injection vunerability
 + **--add-admin**             Add a new web admin account into the DB
 + **--readdb**                Retrieve various information from the database
 + **--get-install-path**      Retrieve the installation path of ePo software (needed for other modes)
 + **--ad-creds**              Retrieve and decrypt cached domain credentials from ePo database.
 + **--wipe**                  Wipe our traces from the database and file system
 + **--srv-exec**              Perform remote command execution on the ePo server
 + **--srv-upload**            Upload files on the ePo server
 + **--cli-deploy**            Deploy commands or softwares on clients

- It is strongly advised to read the manual which explains how to use these modes (see README). But basically, your two first actions must be:

 + 1) Register a rogue agent using **--register**
 + 2) Setup Remote Code execution using **--srv-exec --wizard**
	   
- You may find a vulnerable version of the ePo software on my blog (http://funoverip.net/tag/epowner/). Deploy 2 VMs (eposrv + epocli) and test it !

- The tool was developed/tested on Backtrack 5r3, Kali Linux 1.0.6 and Ubuntu 12.04. It won't work under Windows due to linux tools dependencies.
 + ePolicy Orchestrator was running on Win2003 and Win2003 R2
 + The managed stations were running on WinXPsp3 and Win7

ADDITIONAL INFORMATION 
======================

- See http://funoverip.net/tag/epowner/
- See the main **README** file for the manual.

