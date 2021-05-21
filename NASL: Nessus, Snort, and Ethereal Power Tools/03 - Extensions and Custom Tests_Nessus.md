# In This Toolbox
Most of the security vulnerabilities being discovered utilize the same attack vectors. These attack vectors can be rewritten in each NASL (Nessus Attack Scripting Language) or can be written once using an include file that is referenced in different NASLs. The include files provided with the Nessus environment give an interface to protocols such as Server Message Block (SMB) and Remote Procedure Call (RPC) that are too complex to be written in a single NASL, or should not be written in more than one NASL file.

# Extending NASL Using Include Files
The Nessus NASL language provides only the most basic needs for the tests written with it. This includes socket connectivity, string manipulation function, Nessus knowledge base accessibility, and so on.

Much of the functionality used by tests such as SMB, SSH (Secure Shell), and extended HTTP (Hypertext Transfer Protocol) connectivity were written externally using include files. This is due to two main reasons. First, building them within Nesuss’s NASL language implementation would require the user wanting to change the functionality of any of the extended function to recompile the Nessus NASL interpreter. On the other hand, providing them through external include files minimizes the memory footprint of tests that do not require the extended functionality provided by these files.

# Include Files
As of April 2005, there were 38 include files. These include files provide functionality for:
- AIX, Debian, FreeBSD, HPUX, Mandrake, Red Hat, and Solaris local security patch conformance
- Account verification methods
- NASL debugging routines
- FTP, IMAP, Kerberos, NetOP, NFS, NNTP, POP3, SMB, SMTP, SSH, SSL, Telnet, and TFTP connectivity
- Extended HTTP (keep-alive, banners, etcetera)
- Cisco security compliance checks
- Nessus global settings
- Base64 encoding functions
- Miscellaneous related functions
- Test backporting-related functions
- Cryptographic-related functions
- NetOP connectivity
- Extended network functions
- Ping Pong denial-of-service testing functions
- Windows compliance testing functions

The aforementioned include files are very extensive and in most cases can provide any functionality your test would require. However, in some cases, new include files are needed, but before you start writing a new include file, you should understand the difference between an include file and a test. Once you understand this point, you can more easily decide whether a new include file is necessary or not.

Include files are portions of NASL code shared by one ore more tests, making it possible to not write the same code more than once. In addition, include files can be used to provide a single interface to a defined set of function calls. Unlike NASLs, include files do not include either a script_id or a description. Furthermore, they are not loaded until they are called through the include() directive, unlike NASLs, which are launched whenever the Nessus daemon is restarted.

In every occasion where a NASL calls upon the same include file, a copy of the include file is read from the disk and loaded into the memory. Once that NASL has exited and no other NASL is using the same include file, the include file is removed from the memory.

Before providing an example we will give some background on the include file we are going to build. One of the many tests Nessus does is to try to determine whether a certain server contains a server-side script, also known as CGI (Common Gateway Interface) and whether this script is vulnerable to cross-site scripting. More than two hundred tests do practically all the following steps with minor differences:

1. Determine which ports support HTTP, such as Web traffic.
2. Determine whether the port in question is still open.
3. Depending on the type of server-side script, test whether it is supported. For example, for PHP (Hypertext Preprocessor)-based server-side scripts, determine whether the remote host supports PHP scripts.
4. Determine whether the remote host is generically vulnerable to cross-site scripting; that is, any cross-site scripting attack would succeed regardless of whether the script exists or not on the remote host.
5. Try a list of possible directories where the script might be found.
6. Try a list of possible filenames for the script.
7. Construct the attack vector using some injection script code, in most cases %3cscript%3ealert(‘foobar’)%3c/script%3e.
8. Try to use the attack vector on each of the directories and filename combination.
9. Return success if `<script>alert(‘foobar’)</script>` has been found.

The aforementioned steps are part of a classic include file; further parts of the aforementioned code are already provided inside include files (for example, the functionality of connecting to the remote host using keep-alive, determining whether the remote host supports PHP, and so on).

We can break the aforementioned steps into a single function and include it in an include file, and then modify any existing tests to use it instead of using their current code. We will start off with the original code:

```NASL
#
# Script by Noam Rathaus of Beyond Security Ltd. <noamr@beyondsecurity.com>
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if (get_kb_item(string("www/", port, "/generic_xss"))) exit(0);


function check(loc)
{
 req = http_get(item: string(loc,
"/calendar_scheduler.php?start=%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E"),
port:port);


 r = http_keepalive_send_recv(port:port, data:req);


 if( r == NULL )exit(0);
 if('<script>alert(document.cookie)</script>"' >< r)
 {
  security_warning(port);
  exit(0);
 }
}


foreach dir (make_list("/phpbb", cgi_dirs()))
{
 check(loc:dir);
}
```

The script in the previous example can be easily converted to the following more generic code. The following parameters will hold the attack vector that we will use to detect the presence of the vulnerability:

```NASL
attack_vector_encoded = "%3Cscript%3Ealert('foobar')%3C/script%3E";
attack_vector = "<script>alert('foobar')</script>";
```
The function we will construct will receive the values as parameters:

```NASL
function test_xss(port, directory_list, filename, other_parameters, inject_parameter)
{
```

As before, we will first determine whether the port is open:

```NASL
if(!get_port_state(port))exit(0);
```

Next, we will determine whether the server is prone to cross-site scripting, regardless of which CGI is attacked:

```NASL
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
```

We will also determine whether it supports PHP if the filename provided ends with a PHP-related extension:

```NASL
if (egrep(pattern:"(.php(3?))|(.phtml)$", string:filename, icase:1))
{
 if(!can_host_php(port:port))exit(0);
}
```

Next we will determine whether it supports ASP (Active Server Pages), if the filename provided ends with an ASP-related extension:

```NASL
if (egrep(pattern:".asp(x?)$", string:filename, icase:1))
{
 if(!can_host_asp(port:port))exit(0);
}
```

Then for each of the directories provided in the directory_list parameter, we generate a request with the directory, filename, other_parameters, inject_parameter, and attack_vector_encoded:

```NASL
 foreach directory (directory_list)
{
 req = http_get(item:string(directory, filename, "?", other_parameters, "&",
inject_parameter, "=", attack_vector_encoded), port:port);
```

We then send it off to the server and analyze the response. If the response includes the attack_vector, we return a warning; otherwise, we continue to the next directory:

```NASL
res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if( res == NULL ) exit(0);
if( egrep(pattern:attack_vector, string:res) ){
       security_warning(port);
       exit(0);
}
```

If we have called the aforementioned function test_xss and the file in which it is stored xss.inc, the original code will now look like:

```NASL
 #
# Script by Noam Rathaus of Beyond Security Ltd. <noamr@beyondsecurity.com>
include("xss.inc");


port = get_kb_item("Services/www");
if(!port)port = 80;
```

The filename parameter will list the filename of the vulnerable script:

```NASL
filename = "vulnerablescript.php";
```

This directory_list parameter will house a list of paths we will use as the location where the filename might be housed under:

```NASL
directory_list = make_list( "/phpbb", cgi_dirs());
```

Under the other_parameters value we will store all the required name and value combinations that are not relevant to the attack:

```NASL
other_parameters = "id=1&username=a";
```

Under the inject_parameter value, we will store the name of the vulnerable parameter:

```NASL
inject_parameter = "password";
```

Finally, we will call up the new test_xss function:

```NASL
test_xss(port, port, directory_list, filename, other_parameters, inject_parameter);
```

***
**Swiss Army Knife...: Testing for Other Vulnerabilities**

The code in the previous example verifies whether the remote host is vulnerable to cross-site scripting. The same code can be extended to test for other types of Web-based security vulnerabilities. For example, we can test for SQL injection vulnerabilities by modifying the tested attack_vector with an SQL injecting attack vector and modifying the tested response for SQL injected responses.
***

Repeating this procedure for more than 200 existing tests will reduce the tests’ complexity to very few lines for each of them, not to mention that this will make the testing more standardized and easier to implement.

For an additional example see Chapter 5, where we discuss how one of the commonly used functions, GetFileVersion(), can be improved to provide faster response time and save on network resources. The GetFileVersion() function can either be placed in every NASL we want the improved version to be present at, or we can replace the original GetFileVersion() found in the smb_nt.inc include file. In the first case, one or more NASLs will use the new GetFileVersion() function, while in the second case, roughly 20 tests will use the new version, as they all include the same smb_nt.inc include file.

# Extending the Capabilities of Tests Using the Nessus Knowledge Base
The Nessus daemon utilizes a database to store information that may be useful for one or more tests. This database is called the knowledge base. The knowledge base is a connected list-style database, where a father element has one or more child elements, which in turn may have additional child elements.

For example, some of the most commonly used knowledge base items are the SMB-related items, more specifically the registry-related SMB items. These are stored under the following hierarchy: SMB/Registry/HKLM/. Each item in this hierarchy will correspond to some part of the registry. For example, the registry location of HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC and the value of ImagePath are stored in the knowledge base under the SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/W3SVC/ImagePath key.

***
**Swiss Army Knife...: Storing More of the Registry in the Knowledge Base**

Some parts of the Windows registry are stored inside the Nessus knowledge base. While other parts of the registry are accessed by different NASLs tests, these repeated registry accesses are both bandwidth and time consuming.

Registry reading and storing should be done in one centralized NASL and latter accessed only through the knowledge base. As most of Nessus’ current registry reading is done in smb_hotfixes.nasl, any additional registry reading and storing should be added in it.
***

The entire registry tree is not mapped to the knowledge base; rather, essential parts of it are mapped smb_hotfixes.nasl, which uses RPC-based functionality to access the registry and requires administrative privileges or equivalent on the remote machine.

Once the values are there, the majority of NASLs that require information from the registry no longer access the registry to determine whether the test is relevant or not; rather, they access the knowledge base.

A good example of a set of NASLs is the smb_nt_msXX-XXX.nasl tests. Each of these tests utilizes the functions provided by smb_hotfixes.inc to determine whether a hotfix and service pack were installed on the remote machine, and if not, report a vulnerability. The functionally provided by smb_hotfixes.inc enumerates beforehand all the installed hotfixes and service packs, and can perform a simple regular expression search on the knowledge base to determine whether the patch has been installed or not.

The same method of collaborating information between two NASLs, as in the case of smb_hotfixes.nasl and the different smb_nt_msXX-XXX.nasl, can be done by your own tests. One very relevant case is when a certain type of product is found to be present on the remote machine, and this information can be stored in the knowledge base with any other information such as the product’s banner. Therefore, if in the future any additional tests require the same information, network traffic can be spared and the knowledge base can be queried instead.

# Extending the Capabilities of Tests Using Process Launching and Results Analysis
Nessus 2.1.0 introduced a mechanism that allows certain scripts to run more sensitive functions that would allow such things as the retrieval of locally stored files, execution of arbitrary commands, and so on.

Because these functions can be used maliciously by a normal user through the Nessus daemon to gain elevated privileges on the host running Nessus, they have been restricted to those scripts that are trusted/authenticated. Each test that has a line that starts with #TRUSTED, which will be checked to determine whether it is actually tested by taking the string that follows the #TRUSTED mark and verifying the signature found there with the public key provided with each installation of Nessus. The public key is stored in a file called nessus_org.pem. The nessus_org.pem file holds just the RSA public key, which can be used to verify the authenticity of the scripts, but not the RSA private key, which can be used to sign additional scripts and make them authenticated.

As authenticated scripts can be used for numerous tasks that cannot be carried out unless they are authenticated, the only method to allow creation of additional authenticated scripts is by adding to the nessusd.conf file the directive nasl_no_signature_check with the value of **yes**.

The change to nessusd.conf allows the creation of authenticated scripts. However, an alternative such as replacing the public key can also be considered. In both cases either of the following two problems may arise: First, Nessus.org signed tests may be no longer usable until you re-sign them with your own public/private key combinations. Second, arbitrary scripts may have been planted in www.nessus.org’s host by a malicious attacker who compromised the host. Such a malicious script would be blindly executed by the Nessus daemon and in turn could be used to cause harm to the host running Nessus or to the network upon which this test is being launched.

Even though the latter option is more dangerous, we believe it is easier to do and maintain because it requires a single change in the Nessus configuration file to enable, whereas the first option requires constant maintenance every time an authenticated script changes.



# What Can We Do with TRUSTED Functions?
The script_get_preference_file_content function allows authenticated scripts to read files stored in the Nessus daemon’s file system. This function is executed under root privileges and the user running the Nessus client doesn’t have to be a root user, so this function has the potential to read files that might allow the user to compromise the machine. Thus, the function cannot be accessed by unauthenticated scripts.

The script_get_preference_file_location function allows authenticated scripts to retrieve a file’s preference location from the user. This function by itself poses no security problem because it does nothing other than get the string of the filename. This function is used in conjunction with the script_get_preference_file_content function, which requires authentication, and thus, the script_get_preference_file_location function is deemed allowed by authenticated functions only.

Nessus uses the shared_socket_register, shared_socket_acquire, and shared_socket_release functions to allow different types of scripts to use the same existing socket for its ongoing communication. Unlike Nessus’s keep-alive support, which isn’t essential, the support for shared sockets is essential for such connections as SSH because repeatedly disconnecting from, reconnecting to, and authenticating with the SSH server would cause some stress to the SSH server and could potentially hinder the tests that rely on the results returned by the SSH connection.

The same_host function allows a script to compare two provided strings containing either a qualified hostname or a dotted IP (Internet Protocol) address. The same_host function determines whether they are the same by translating both strings to their dotted IP form and comparing them. The function has no use for normal tests, so you can’t control the hostname or IP you test; rather, the test can test only a single IP address that it was launched against. This function has been made to require authentication, as it could be used to send packets to a third-party host using the DNS server.

pem_to and rsa_sign are two cryptographic functions that require authentication. The functions utilize the SSL library’s PEM_read_bio_RSAPrivateKey/PEM_read_bio_DSAPrivateKey and RSA_sign functions, respectively. The first two functions allow for reading a PEM (Privacy Enhanced Mail) and extracting from inside of it the RSA private key or the DSA private key. The second function allows RSA to sign a provided block of data. These functions are required in the case where a public/private authentication mechanism is requested for the SSH traffic generated between the SSH client and SSH server.

The dsa_do_sign function utilizes the SSL’s library DSA_do_verify function. The DSA_do_ verify function confirms the validity of cryptographically signed content. The dsa_do_sign function is used by the ssh_func.inc include file to determine whether the traffic being received from the remote host is trustworthy. The same function is used in the dropbear_ssh.nasl test to determine the existence of a Dropbear SSH based Trojan as it has a special cryptographic signature.

The pread function allows NASL scripts to execute a command-line program and retrieve the standard output returned by the program. The aforementioned list of NASLs utilizes the function to execute the different programs and take the content returned by the pread function and analyze it for interesting results.

The find_in_path function allows Nessus to determine whether the program being requested for execution is in fact available; that is, in the path provided to the Nessus daemon for execution.

The get_tmp_dir function allows the NASL interpreter to determine which path on the remote host is used as a temporary storage location.

The fwrite, fread, unlink, file_stat, file_open, file_close, file_read, file_write, and file_seek functions allow the NASL scripts to perform local file manipulation, including writing, reading, deleting, checking the status of files, and jumping to a specific location inside a file.



# Creating a TRUSTED Test
As a demonstration of how trusted tests can be used to build custom tests that can do more than just probe external ports for vulnerabilities, we have decided to build a ps scanner. For those who are not familiar with ps, it is a program that reports back to the user the status of the processes currently running on the machine.

If we take it a step further, by analyzing from a remote location the list retrieved using this command, an administrator can easily determine which hosts are currently running a certain process, such as tcpdump, ethereal, or even nessus, which in turn might be disallowed by the company policy.

To maintain simplicity we will explain how such a test is created that is only compatible with UNIX or more specifically with Linux’s ps command-line program. The test can be easily extended to allow enumeration of running processes via a ps-like tool, such as PsList, which is available from www.sysinternals.com/ntw2k/freeware/pslist.shtml.

```NASL
#
# This script was written by Noam Rathaus of Beyond Security Ltd.
<noamr@beyondsecurity.com>
#
# GPL
#
```

First we need to confirm that our NASL environment supports the function pread. If it does not, we need to exit, or any subsequent function calls will be useless, and might also cause false positives:

```NASL
if ( ! defined_func("pread") ) exit(0);
```
We then define how our test is called, as well as its version and description. You might have noticed that the following code does not define a script_id(); this is intentional because only the maintainers of Nessus can provide you with a unique script_id number. However, if you do not provide this number, the Nessus daemon will refuse to load the script; instead the Nessus maintainers provide the code with a script_id that wouldn’t be used by any future scripts, thus preventing collisions. For example, script_id 90001:

```NASL
if(description)
{
 script_id();
 script_version ("1.0");
 name["english"] = "Ps 'scanner'";
 script_name(english:name["english"]);


 desc["english"] = "
This plug-in runs ps on the remote machine to retrieve a list of active processes. You can
also run a regular expression match on the results retrieved to try and detect malicious
or illegal programs.
See the section 'plugins options' to configure it.


Risk factor : None";


 script_description(english:desc["english"]);


 summary["english"] = "Find running processes with ps";
 script_summary(english:summary["english"]);


 script_category(ACT_SCANNER);


 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 ```
 
 To provide an interface between the Nessus GUI (graphical user interface) and the test, we will tell the Nessus daemon that we are interested in users being able to configure one of my parameters, Alert if the following process names are found (regular expression), which in turn will make the Nessus GUI show an edit box configuration setting under the **Plugin Settings** tab. The following code and additional scripts discussed in this section are available on the Syngress Web site:

```NASL
 script_add_preference(name: "Alert if the following process names are found (Regular
expression)", type: "entry", value: ".*");
```

Our test requires two things to run—a live host and SSH connectivity, so we need to highlight that we are dependent on them by using the following dependency directive:

```NASL
 script_dependencies("ping_host.nasl", "ssh_settings.nasl");
 exit(0);
}
```

The functions required to execute SSH-based commands can be found inside the ssh_func.inc file; therefore, we need to include them.

```NASL
include("ssh_func.inc");

buf = "";
```

If we are running this test on the local machine, we can just run the command without having to establish an SSH connection. This has two advantages, the first making it very easy to debug the test we are about to write, and the second is that no SSH environment is required, thus we can save on computer and network resources.

```NASL
if (islocalhost())
```

In those cases where we are running the test locally, we can call the pread function, which receives two parameters—the command being called and the list of arguments. UNIX’s style of executing programs requires that the command being executed be provided as the first argument of the argument list:

```NASL
buf = pread(cmd: "ps", argv: make_list("ps", "axje"));
```

***
**Master Craftsman...: Rogue Process Detection**

Rogue processes such as backdoors or Trojan horses, have become the number one threat of today’s corporate environment. However, executing the ps process might not be a good idea if the remote host has been compromised, as the values returned by the ps process might be incorrect or misleading.

A better approach would be to read the content of the /proc directory, which contains the raw data that is later processed and returned in nicer form by the ps program.
***

We need to remember that if we use the pread function to call a program that does not return, the function pread will not return either. Therefore, it is important to call the program with those parameters that will ensure the fastest possible execution time on the program.

A very good example of this is the time it takes to run the netstat command in comparison with running the command **netstat -n**. The directive -n instructs netstat not to resolve any of the IPs it has, thus cutting back on the time it takes the command to return.

If we are not running locally, we need to initiate the SSH environment. This is done by calling the function ssh_login_or_reuse_connection, which will use an existing SSH connection to carry on any command execution we desire. If that isn’t possible, it will open a new connection and then carry on any command we desire.

```NASL
else
{
 sock = ssh_login_or_reuse_connection();
 if (! sock)  exit(0);
 ```
 
 Once the connection has been established, we can call the same command we just wrote for the local test, but we provide it via a different function, in this case the function ssh_cmd. This function receives three parameters—SSH socket, command to execute, and the time-out for the command. The last parameter is very important because tests that take too long to complete are stopped by the Nessus daemon. We want to prevent such cases by providing a timeout setting:
 
 ```NASL
 buf = ssh_cmd(socket:sock, cmd:"ps axje", timeout:60);
 ```
 Once the command has been sent and a response has been received or a timeout has occurred, we can close the SSH connection:

```NASL
ssh_close_connection();
```

If the ssh_cmd function returned nothing, we terminate the test:

```NASL
 if (! buf) { display("could not send command\n"); exit(0); }
}
```

In most cases, buffers returned by command-line programs can be processed line by line; in the case of the ps command the same rule applies. This means that we can split our incoming buffer into lines by using the split function, which takes a buffer and breaks it down into an array of lines by making each entry in the array a single line received from the buffer:

```NASL
lines = split(buf);
```
Using the max_index function, we can determine how many lines have been retrieved from the buffer we received:

```NASL
n = max_index(lines);
```

If the number of lines is equal to zero, it means that there is a single line in the buffer, and we need to modify the value of n to compensate:

```NASL
if (n == 0) n = 1;
```

We will use the **i** variable to count the number of lines we have processed so far:

```NASL
i = 0;
```

Because some interaction with the Nessus daemon that will also trickle down to the Nessus GUI is always a good idea, we inform the GUI that we are going to start scanning the response we received to the ps command by issuing the scanner_status function. The scanner_status function receives two parameters: first, a number smaller than or equal to the total number stating what is the current status and second, another number stating the total that we will reach. Because we just started, we will tell the Nessus daemon that we are at position 0 and we have n entries to go:

```NASL
scanner_status(current: 0, total: n);
```

The matched parameter will store all the ps lines that have matched the user provided regular expression string:

```NASL
matched = "";
```

The script_get_preference will return the regular expression requested by the user that will be matched against the buffer returned by the ps command. The default value provided for this entry,.*, will match all lines in the buffer:

```NASL
check = script_get_preference("Alert if the following process names are found (Regular
expression)");


foreach line (lines)
{
 #          1         2         3         4         5         6         7
 #01234567890123456789012345678901234567890123456789012345678901234567890
 # 12345 12345 12345 12345 12345678 12345 123456 123 123456 ...
 #  PPID   PID  PGID   SID TTY      TPGID STAT   UID   TIME COMMAND
 #     0     1     0     0 ?           -1 S        0   0:05 init [2]
 # 22935 22936 11983 24059 pts/132  24564 S        0   0:00 /bin/bash /etc/init.d/xprint
restart
 #     3 14751     0     0 ?           -1 S        0   0:00 [pdflush]


 if (debug) display("line: ", line, "\n");
```

As the ps command returns values in predefined locations, we will utilize the substr function to retrieve the content found in each of the positions:


```NASL
PPID = substr(line, 0, 4);
 PID = substr(line, 5, 10);
 PGID = substr(line, 11, 16);
 SID = substr(line, 17, 22);
 TTY = substr(line, 24, 31);
 TPGID = substr(line, 33, 37);
 STAT = substr(line, 39, 44);
 UID = substr(line, 46, 48);
 TIME = substr(line, 50, 55);


 left = strlen(line)-2;
 COMMAND = substr(line, 57, left);


 if (debug) display("PPID: [", PPID, "], PID: [", PID, "] PGID: [", PGID, "] SID: [", SID,
"] TTY: [", TTY, "]\n");
 if (debug) display("COMMAND: [", COMMAND, "]\n");
 ```
 
 Once we have all the data, we can execute the regular expression:

```NASL
v = eregmatch(pattern:check, string:COMMAND);
```

Next we test whether it has matched anything:

```NASL
if (!isnull(v))
{
```

If it has matched, append the content of the COMMAND variable to our matched variable:

```NASL
matched = string(matched, "cmd: ", COMMAND, "\n");
 if (debug) display("Yurika on:\n", COMMAND, "\n");
}
```

***
**Master Craftsman...: Advance Rogue Process Detection**

The sample code can be easily extended to include the execution of such programs as md5sum, a program that returns the MD5 value of the remote file, to better determine whether a certain program is allowed to be executed. This is especially true for those cases where a user knows you are looking for a certain program’s name and might try to hide it by changing the file’s name. Conversely, the user might be unintentionally using a suspicious program name that is falsely detected.
***

As before, to make the test nicer looking, we will increment the i counter by one, and update location using the scanner_status function:

```NASL
 scanner_status(current: i++, total: n);
}
```

If we have matched at least one line, we will return it using the security_note function:

```NASL
if (matched)
{
 security_note(port:0, data:matched);
}
```

Once we have completed running the test, we can inform the GUI that we are done by moving the location to the end using the following line:

```NASL
scanner_status(current: n, total: n);
exit(0);
```

# Final Touches
You have learned how to extend the NASL language and the Nessus environment to support more advance functionality. You have also learned how to use the knowledge base to improve both the accuracy of tests and the time they take to return whether a remote host is vulnerable or not. You also now know how to create advanced tests that utilize advanced Nessus functions, such as those that allow the execution of processes on a remote host, and how to gather the results returned by those processes.