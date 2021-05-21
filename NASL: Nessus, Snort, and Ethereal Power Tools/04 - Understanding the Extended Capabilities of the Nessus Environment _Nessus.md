# In This Toolbox
Some of the more advanced functions that Nessus’ include files provide allow a user to write more than just banner comparison or service detection tests; they also allow users to very easily utilize Windows’ internal functions to determine whether a certain Windows service pack or hotfix has been installed on a remote machine, or even whether a certain UNIX patch has been installed.

This chapter covers Nessus’ include files implementation of the SMB (Server Message Block) protocol, followed by Nessus’ include files implementation of Windows-related hotfix and service pack verification. This chapter also addresses how a similar kind of hotfix and service pack verification can be done for different UNIX flavors by utilizing the relevant include files.

# Windows Testing Functionality Provided by the smb_nt.inc Include File
Nessus can connect to a remote Windows machine by utilizing Microsoft’s SMB protocol. Once SMB connectivity has been established, many types of functionality can be implemented, including the ability to query the remote host’s service list, connect to file shares and open files that reside under it, access the remote host’s registry, and determine user and group lists.

***
**Swiss Army Knife: SMB Protocol Description**

SMB (Server Message Block), aka CIFS (Common Internet File System), is an intricate protocol used for sharing files, printers, and general-purpose communications via pipes. Contrary to popular belief, Microsoft did not create SMB; rather, in 1985 IBM published the earliest paper describing the SMB protocol. Back then, the SMB protocol was referred to as the IBM PC Network SMB Protocol. Microsoft adopted the protocol later and extended it to what it looks like today. You can learn more on the SMB protocol and its history at http://samba.anu.edu.au/cifs/docs/what-is-smb.html.
***

In the following list of all the different functions provided by the smb_nt.inc file, some of the functions replace or provide a wrapper to the functions found in smb_nt.inc:

- **kb_smb_name**. Returns the SMB hostname stored in the knowledge base; if none is defined, the IP (Internet Protocol) address of the machine is returned.
- **kb_smb_domain**. Returns the SMB domain name stored in the knowledge base.
- **kb_smb_login**. Returns the SMB username stored in the knowledge base.
- **kb_smb_password**. Returns the SMB password stored in the knowledge base.
- **kb_smb_transport**. Returns the port on the remote host that supports SMB traffic (either 139 or 445).
- **unicode**. Converts a provided string to its unicode representation by appending for each of the provided characters in the original string a NULL character.

The following functions do not require any kind of initialization before being called. They take care of opening a socket to port 139 or 445 and logging in to the remote server. The registry functions automatically connect to \winreg and open HKLM, whereas smb_file_read() connects to the appropriate share to read the files.

- **registry_key_exists**. Returns if the provided key is found under the HKEY_LOCAL_MACHINE registry hive. For example: if (registry_key_exists(key:“SOFTWARE\Microsoft”)).
- **registry_get_sz**. Returns the value of the item found under the HKEY_LOCAL_MACHINE registry hive. For example, the following will return the CSDVersion item’s value found under the HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion registyr location:
```NASL
 service_pack = registry_get_sz(key:"SOFTWARE\Microsoft\Windows
NT\CurrentVersion", item:"CSDVersion");
```
- **smb_file_read**. Returns the n number of bytes found at the specified offset of the provided filename. For example, the following will return the first 4096 bytes of the boot.ini file:
```NASL
data = smb_file_read(file:"C:\boot.ini", offset:0, count:4096);
```

To use the following lower-level functions, you need to set up a socket to the appropriate host and log in to the remote host:

- **smb_session_request**. Returns a session object when it is provided with a socket and a NetBIOS name. The smb_session_request function sends a NetBIOS SESSION REQUEST message to the remote host. The NetBIOS name is stored in the Nessus knowledge base and can be retrieved by issuing a call to the kb_smb_name() function. The function also receives an optional argument called *transport*, which defines the port that the socket is connected to. If the socket is connected to port 445, then this function does nothing. If it’s connected to port 139, a NetBIOS message is sent, and this function returns an unparsed message from the remote host.
- **smb_neg_prot**. Returns the negotiated response when it is provided with a socket. This function negotiates an authentication protocol with the remote host and returns a blob to be used with smb_session_setup() or NULL upon failure.
- **smb_session_setup**. Returns a session object when it is provided with a socket, login name, login password, and the object returned by the smb_neg_prot. This function logs in to the remote host and returns NULL upon failure (could not log in) or a blob to be used with session_extract_uid().
- **session_extract_uid**. Returns the UID (user identifier) from the session object response. This function extracts the UID sent by the remote server after a successful login. The UID is needed in all the subsequent SMB functions.
- **smb_tconx**. Returns a session context when it is provided with a socket, NetBIOS name, unique identifier, and a share name. This function can be used to connect to IPC$ (Inter Process Connection) or to any physical share on the remote host. It returns a blob to use with smb_tconx_extract_tid() upon success or NULL if it’s not possible to connect to the remote share. For example, the following line will try to connect to the remote host’s IPC$:
```NASL
if (smb_tconx(soc:socket, name:kb_smb_name(), uid:my_uid, share:"IPC$") == NULL
) exit(0);
```
- **smb_tconx_extract_tid**. Returns the TID (tree id) from the session context reply.
- **smbntcreatex**. Returns the session context when it is provided with a socket, user id, tree id, and name. This function connects to a named pipe (such as \winreg). It returns NULL on failure or a blob suitable to be used by smbntcreatex_extract_pipe().
- **smbntcreatex_extract_pipe**. Returns the pipe id from the session context returned by smbntcreatex().
- **pipe_accessible_registry**. Returns either NULL if it has failed or non-NULL if it has succeeded in connecting to the pipe when it is provided with a socket, user id, tree id, and pipe name. This function binds to the winreg MSRPC service and returns NULL if binding failed, or non-null if you could connect to the service successfully.
- **registry_open_hklm, registry_open_hkcu, registry_open_hkcr**. Returns the equivalent to the MSDN’s RegConnectRegistry() when its provided with a socket, user id, tree id, and a pipe name. The return value is suitable to be used by registry_get_key().
- **registry_get_key**. Returns the MSDN’s RegOpenKey() when it is provided with a socket, user id, tree id, pipe name, key name, and the response returned by one of the registry_open_hk* functions. The return value is suitable to be used by registry_get_key_item*() functions.
- **registry_get_item_sz**. Returns the string object found under the provided registry key when it is provided with a socket, user id, tree id, pipe name, item name, and the response returned by the registry_get_key function. The return value needs to be processed by the registry_decode_sz() function.
- **registry_decode_sz**. Returns the string content when it is provided with the reply returned by the registry_get_item_sz function.

The following functions are not used in any script, but could be useful to clean up a computer filled with spyware:

- **registry_delete_key**. Deletes the specified registry key when it is provided with a socket, user id, pipe name, key name, and the response returned by the registry_open_hk* functions.
- **registry_delete_value**. Deletes the specified registry key value when it is provided with a socket, user id, pipe name, key name, the response returned by the registry_open_hk* functions, and the name of the value to delete.
- **registry_shutdown**. This function will cause the remote computer to shutdown or restart after the specified timeout. Before the actual shutdown process starts, a message will be displayed, when it is provided with a socket, user id, tree id, pipe name, message to display, and timeout in seconds. This message will also need to be provided with instructions on whether to reboot or shutdown and whether to close all the applications properly.

The following example shows how to determine whether the remote host’s Norton Antivirus service is installed and whether it is running. If Norton Antivirus is not running, the example shows how to start it by utilizing the Microsoft Windows service control manager.

To determine whether the remote host has Norton AntiVirus or Symantec AntiVirus installed, first run the smb_enum_services.nasl test, which will return a list of all the services available on the remote host. Next, accommodate the required dependencies for smb_enum_services.nasl (netbios_name_get.nasl, smb_login.nasl, cifs445.nasl, find_service.nes, and logins.nasl). Next, get the value stored in the knowledge base item called SMB/svcs; this knowledge base item holds a list of all the services that are present on the remote host. You do this by using the following code:

```NASL
service_present = 0;
services = get_kb_item("SMB/svcs");
if(services)
{
 if("[Norton AntiVirus Server]" >!< services || "[Symantec AntiVirus Server]" >!<
services)
 {
  service_present = 1;
 }
}
```

# Windows Testing Functionality Provided by the smb_hotfixes.inc Include File
If the remote host’s registry has been allowed access from a remote location, Nessus can gather information from it and store it in the knowledge base. Once the information is in the knowledge base, different types of tests can be created. The most common tests are service pack and hotfix presence verification.

All of the following functions work only if the remote host’s registry has been enumerated. If the registry hasn’t been enumerated, version-returning functions will return NULL, while product installation-checking functions will return *minus one* (-1) as the result. Furthermore, because registry enumeration relies on the ability to successfully launch the smb_hotfixes.nasl test, it has to be provided as a dependency to tests you write using any of the following functions:
- **hotfix_check_exchange_installed**. This function returns the version of the Exchange Server if one has been installed on the remote host.
- **hotfix_data_access_version**. This function returns the version of the Access program if one has been installed on the remote host.
- **hotfix_check_office_version**. This function returns the version of the remote host’s Office installation. To determine the version, one of the following programs must be installed on the remote host: Outlook, Word, Excel, or PowerPoint.
- **hotfix_check_word_version**, hotfix_check_excel_version, hotfix_check_powerpoint_version, hotfix_check_outlook_version. These functions return the version of the Word, Excel, PowerPoint, or Outlook program if one has been installed on the remote host.
- **hotfix_check_works_installed**. This function returns the version of the MS Works program if one has been installed on the remote host.
- **hotfix_check_iis_installed**. This function returns either the value of *one* or *zero* depending on whether the remote host has IIS (Internet Information Server) installed or not.
- **hotfix_check_wins_installed**, hotfix_check_dhcpserver_installed. These functions return either the value of *one* or *minus* one depending on whether the remote host has the WINS (Windows Internet Naming Service) server or DCHP (Dynamic Host Control Protocol) server present or not.
- **hotfix_check_nt_server**. This function returns either zero or one depending on whether the remote host is a Windows NT server or not.
- **hotfix_check_domain_controler**. This function returns either zero or one depending on whether the remote host is a Windows Domain Controller or not.
- **hotfix_get_programfilesdir**. This function returns the location of the Program Files directory on the remote host.
- **hotfix_get_commonfilesdir**. This function returns the location of the Common Files directory on the remote host.
- **hotfix_get_systemroot**. This function returns the location of the System Root directory on the remote host.
- **hotfix_check_sp**. This function verifies whether a certain service pack has been installed on the remote host. The function uses the provided services pack levels to verify whether the remote host is running the specified product type and whether the remote host has the appropriate service pack installed. The function returns *minus one* if the registry hasn’t been enumerated, *zero* if the requested service pack level has been properly installed, and one if the requested service pack level hasn’t been installed.
- **hotfix_missing**. This function verifies whether a certain hotfix has been installed on the remote host. The function returns *minus one* if the registry hasn’t been enumerated, *zero* if the requested hotfix has been properly installed, and one if the requested hotfix hasn’t been installed.

***
**Master Craftsman: Registry Keys Stored in the Knowledge Base**

The functions provided by the smb_hotfixes.inc include file all return values stored in the registry. By extending the amount of information Nessus holds in its knowledge base, you can speed up the scanning process. One example of doing this would be to include information about whether the ISA (Internet Security and Acceleration) server is installed on the remote server, what version is installed, and if any service packs/feature packs are installed for it. As of the writing of this book, seven tests can verify if the ISA server is installed on a remote server. Because all these tests call cached registry items, the time it takes to verify whether the remote host is vulnerable is negligible to reconnecting to the remote host’s registry and pulling the required registry keys seven times.
***

For example, Microsoft has recently released an advisory called *Vulnerability in Web View Could Allow Remote Code Execution*. The vulnerability described in this advisory affects Windows 2000, Windows 98, Windows 98SE, and Windows ME. As you will see later in this chapter, it is fairly easy to add a registry-based test for the aforementioned security advisory’s hotfix presence and to inform the user if it is in fact not present on the remote host.

Currently, Nessus supports security testing for only Windows NT, 2000, 2003, and XP. Moreover, as stated in the advisory, once Service Pack 5 is installed on the remote host, the Windows 2000 installation will be immune.

To create a test that verifies whether the remote host is immune to the vulnerability, you first need to verify that such a service pack has not been installed and that in fact the remote host is running Windows 2000. To do this, utilize the following lines:

```NASL
nt_sp_version = NULL;
win2k_sp_version = 5;
xp_sp_version = NULL;
win2003_sp_version = NULL;


if ( hotfix_check_sp(  nt:nt_sp_version,
                                    win2k:win2k_sp_version,
                                    xp:xp_sp_version,
                                    win2003:win2003_sp_version) <= 0 ) exit(0);
									
```

Before calling the aforementioned lines, you must first satisfy a dependency on smb_hotfixes.nasl and verify that the remote registry has been enumerated. That is done by ensuring that the knowledge base item *SMB/Registry/Enumerated* is present. This is done by adding the following lines to the script:

```NASL
script_dependencies("smb_hotfixes.nasl");
script_require_keys("SMB/Registry/Enumerated");
```

Next, verify that hotfix Q894320 has been installed on the remote host. Do this by executing the following lines:

```NASL
if ( hotfix_missing(name: "Q894320") > 0 )
        security_hole(get_kb_item("SMB/transport"));
```

The two functions you used in the code in the previous example are defined in the smb_hotfixes.inc file, which must be included before the functions can be called by adding the following line to your code:

```NASL
include("smb_hotfixes.inc");
```

***
**Swiss Army Knife: Microsoft’s MSSecure.xml**

Microsoft’s Windows Update, Microsoft Baseline Security Analyzer, and Shavilk’s HFNetCheck all use an XML file that contains the most current information on the latest software versions, service packs, and security updates available for various Microsoft operating systems, BackOffice components, services, and so on. Microsoft provides this file to the public for free. The MSSecure.xml file is both machine readable and human readable; thus, administrators can use the file to easily spot relevant patches or make an automated script that performs this task for them.

All the information required for the above Hotfix testing sample can be found in the MSSecure.xml’s MS05-024 advisory section.
***


# UNIX Testing Functionality Provided by the Local Testing Include Files
Nessus can connect to a remote UNIX host that supports SSH (Secure Shell). Currently, the following operating systems have tests that verify whether a remote host contains an appropriate path for a vulnerability: AIX, Debian, Fedora, FreeBSD, Geneto, HP-UNIX, Mandrake, Red Hat, Solaris, and SuSE.

Verifying whether a remote host has installed the appropriate patch is done via several query mechanisms, depending on the type of operating system and the type of package querying mechanism used by that operating system.

In most cases, pkg_list or dpkg, programs whose purpose is to list all available installed software on the remote host and each software’s version, are used to retrieve a list of all the products on the remote host. This information is then quantified and stored in the knowledge base under the item Host/OS Type. For example, in the case of Red Hat, the program *rpm* is launched, and the content returned by it is stored in Host/RedHat/rpm-list.

You do not have to directly access the content found in a knowledge base item; rather, several helper functions analyze the data found in the software list and return whether the appropriate patch has been installed or not.

A list of the software components of an operating system is not the only information that is indexed by the helper functions; the operating system’s level, or more specifically its patch level, is also stored in the knowledge base and is used to verify whether a certain patch has been installed on the remote host.

Currently, several automated scripts take official advisories published by the operating system vendors and convert them into simple NASL (Nessus Attack Scripting Language) scripts that verify whether the advisory is relevant to the remote host being scanned. Let’s discuss these scripts now.

The rpm_check function determines whether the remote host contains a specific RPM (RPM Package Manager, originally called Red Hat Package Manager) package and whether the remote host is of a certain release type. Possible release types are MDK, SUSE, FC1, FC2, FC3, RHEL4, RHEL3, and RHEL2.1. These correspond to Mandrake, SuSE, Fedora Core 1, Fedora Core 2, Fedora Core 3, Red Hat Enterprise Linux 4, Red Hat Enterprise Linux 3, and Red Hat Enterprise Linux 2.1, respectively.

The value of one is returned if the package installed on the remote host is newer or exactly as the version provided, whereas the value of zero is returned if the package installed on the remote host is newer or exactly the same as the version provided.

For example, the following code will verify whether the remote host is a Red Hat Enterprise Level 2.1 and whether the remote host has a Gaim package that is the same or later than version 0.59.9-4:

```NASL
if ( rpm_check( reference:"gaim-0.59.9-4.el2", release:"RHEL2.1") )
```

The same test can be done for Red Hat Enterprise Level 3 and Red Hat Enterprise Level 4:

```NASL
if ( rpm_check( reference:"gaim-1.2.1-6.el3", release:"RHEL3") || rpm_check(
reference:"gaim-1.2.1-6.el4", release:"RHEL4") )
```

However, in the preceding case, the Gaim version available for Red Hat Enterprise Level 3 and 4 is newer than the version available for Red Hat Enterprise Level 2.1.

The rpm_exists function is very similar to rpm_check. However, in this case, rpm_exists tests not for which version of the package is running, but for only whether the RPM package exists on the remote host. The value of one is returned if the package exists, whereas the value of *zero* is returned if the package does not exist.

The return values of rpm_check function are zero if the remote host’s distribution is irrelevant and one if the package exists on the remote host.

For example, you can determine whether the remote Fedora Core 2 host has the mldonkey package installed; if it does, your cooperation policy is broken, and you will want to be informed of it:

```NASL
if ( rpm_exists(rpm:"mldonkey", release:"FC2") )
```

The aix_check_patch function is very similar to rpm_check; however, AIX software patches are bundled together in a manner similar to the Microsoft’s service packs; therefore, you verify whether a certain bundle has been installed, not whether a certain software version is present on a remote host.

The return values of this function are zero if the release checked is irrelevant, one if the remote host does not contain the appropriate patch, and minus one if the remote host has a newer version than the provided reference.

– The deb_check function is equivalent to the rpm_check function, but unlike the rpm_check, the different Debian versions are provided as input instead of providing a release type (such as Red Hat/Fedora/Mandrake/SuSE). In addition, unlike the rpm_check function, the version and the package name are broken into two parts: prefix, which holds the package name, and reference, which holds the version you want to be present on the remote host.

The return values of this function are one if the version found on the remote host is older than the provided reference and zero if the architecture is not relevant or the version found on the remote host is newer or equal to the provided reference.

For example, in Debian’s DSA-727, available from www.debian.org/security/2005/dsa-727, you can see that for stable distribution (woody) this problem has been fixed in version 0.201-2woody1; therefore, you conduct the following test:

```NASL
if (deb_check(prefix: 'libconvert-uulib-perl', release: '3.0', reference: '0.201-2woody1'))
```

For the testing (sarge) and unstable (sid) distributions, this problem has been fixed in version 1.0.5.1-1; therefore, you conduct the following test:

```NASL
if (deb_check(prefix: 'libconvert-uulib-perl', release: '3.2', reference: '1.0.5.1-1'))
if (deb_check(prefix: 'libconvert-uulib-perl', release: '3.1', reference: '1.0.5.1-1'))
```

The pkg_cmp function is equivalent to the rpm_check, but is used for the FreeBSD operating system. The function pkg_cmp doesn’t verify which version of FreeBSD is being queried; this has to be done beforehand by grabbing the information found under the *Host/FreeBSD/release* knowledge base key and comparing it with the FreeBSD release version. The return values of this function are one or larger if the remote host’s version of the package is older than the provided reference, zero if both versions match, and minus one or smaller if the package is irrelevant to the remote host or the version running on the remote host is newer than the provided reference.

The hpux_check_ctx function determines whether the remote host is of a certain HP UNIX hardware version and HP UNIX operating system version. This is done by providing values separated by a space for each relevant hardware and operating system pair. Each such pair is separated by a colon. The return values of this function are one for architecture matched against the remote host and zero for architecture that does not match against the remote host.

For example, the string 800:10.20 700:10.20 indicates that you have two relevant sets for testing. The first hardware version is 800, and its operating system version is 10.20. The second hardware version is 700, and its operating system version is also 10.20. If one of the pairs is an exact match, a value of one is returned; if none of them match, the value of zero is returned. The value of the remote host’s hardware version is stored under the *Host/HP-UX/version* knowledge base item key, and the remote host’s operating system version is stored under the *Host/HPUX/hardware* knowledge base item key.

The hpux_patch_installed function determines whether a remote HP-UNIX host has an appropriate patch installed, such as AIX. HP-UNIX releases patches in bundles named in the following convention: PHCO_XXXXX. The return values of this function are one if the patch has been installed and zero if the patch has not been installed.

Once you have used the hpux_check_ctx function to determine that the remote host’s hardware and operating system versions are relevant, you can call the hpux_patch_installed function and determine whether the patch has been installed. Multiple patches can be provided by separating each patch with a space character.

For example, to create a test for the vulnerability patched by PCHO_22107, available at ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHCO_22107.txt, you’ll start by verifying that the remote host’s hardware and system operating system versions are correct:

```NASL
if ( ! hpux_check_ctx ( ctx:"800:11.04 700:11.04 " ) )
{
 exit(0);
}
```

Follow up by testing whether the remote host has the appropriate PHCO installed and all the ones this PHCO_22107 depends on:

```NASL
if ( !hpux_patch_installed (patches:"PCHO_22107 PHCO_21187 PHCO_19047 PHCO_17792
PHCO_17631 PHCO_17058 PHCO_16576 PHCO_16345 PHCO_15784 PHCO_14887 PHCO_14051 PHCO_13606
PHCO_13249"))
{
 security_hole(0);
}
```

However, the code in the previous example doesn’t verify whether the remote host’s patch files have been installed; instead, it verifies only whether the remote host has launched the appropriate patches. To verify whether the remote host has been properly patched, you need to call the hpux_check_patch function.

The hpux_check_patch function verifies whether a remote HP-UNIX system has installed a patch and if the user has let the patch modify the operating system’s files. The return values of this function are one if the package is not installed on a remote host and zero if the patch has been installed or is irrelevant for a remote host.

For example, for the aforementioned PHCO_22107 advisory, you must confirm that *OS-Core.UX-CORE*’s version is B.11.04. The following code will verify that OS-Core.UX-CORE is in fact of the right version; if it is not, it will notify that the remote host is vulnerable:

```NASL
if ( hpux_check_patch( app:"OS-Core. UX-CORE", version:"B.11.04") )
{
 security_hole(0);
 exit(0);
}
```

The qpkg_check function is equivalent to the rpm_check, but it is used for testing the existence of packages on Gentoo distributions. The function verifies that the package has been installed on the remote host and then verifies whether a certain version is *equal to, lower than, or greater than* the provided version of vulnerable and immune versions.

The return values of this function are *zero* for irrelevant architecture or when a package is not installed on a remote host, and *one* if the patch has been installed.

In the following example, you will verify whether a remote host contains the patches provided for the gdb package, as described in www.gentoo.org/security/en/glsa/glsa-200505-15.xml:

For the GLSA-200505-15 you need to check first the package named *sys-devel/gdb* and then the unaffected version >= 6.3-r3, meaning you need to write **ge 6.3-r3** followed by the vulnerable version < 6.3-r3. So you need to write **l 6.3-r3**. The complete line of this code reads as follows:

```NASL
if (qpkg_check(package: "sys-devel/gdb", unaffected: make_list("ge 6.3-r3"), vulnerable:
make_list("lt 6.3-r3") ))
{
 security_hole(0);
 exit(0);
}
```

***
**Master Craftsman: Adding Additional Operating Systems**

The aforementioned functions do not cover all available UNIX-based operating systems. Extending these functions to support other operating systems is easy. Operating systems that are extensions of other operating systems would require little, if any, changes; for example, Ubuntu, which is an extension of Debian. Other operating systems would require more changes; however, if you can provide two functions to the Nessus environment, you can easily add support to your operating system:

- SSH connectivity

- A way to list all the packages/products installed on the operating systems and their corresponding versions

If the preceding two functions are available, you can index the list of packages and their versions through the SSH channel. You then can create a test that determines whether the package is installed and if its version is lower than the one that is immune to attack.
***

The solaris_check_patch function verifies whether a certain patch exists on a remote Solaris machine. As in the case of HP-UNIX, the function verifies the release type, architecture—hardware type, patch (which can be made obsolete by some other patch), followed by the name of the vulnerable package. The vulnerable packages can be more than one, in which case they are separated by the character space.

The return values of this function are *minus one* if the patch is not installed, *zero* for irrelevant architecture or if the package is not installed on the remote host, and *one* if the patch has been installed.

**Final Touches**
You have learned different functions provided by the smb_nt.inc include file and the smb_hotfixes.inc file that can be used to test Windows-based devices. Furthermore, you have seen what functions are provided by the aix.inc, debian_package.inc, freebsd_package.inc, hpux.inc, qpkg.inc, rpm.inc, and solaris.inc include files to test UNIX-based devices. After viewing examples in this chapter, you should understand how to use these various functions.