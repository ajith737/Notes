# Introduction

One of the most attractive attributes of Nessus is the simplicity of creating custom extensions (or plugins) to be run with the Nessus engine. This benefit is gained via the specialized language NASL (Nessus Attack Scripting Language). NASL supplies the infrastructure to write network-based scripts without the need to implement the underlying protocols. As NASL does not need to compile, plugins can be run at once, and development is fast. After understanding these benefits, it should be an easy decision to write your next network-based script using NASL. In this introduction we will overview how this is done, with an emphasis on usability and tips for writing your own scripts. If you are already familiar with the NASL language, we hope you will still find useful insights in this chapter.

# What Is NASL?

NASL, as the name implies, is a scripting language specifically designed to run using the Nessus engine. The language is designed to provide the developer with all the tools he/she needs to write a network-based script, supporting as many network protocols as required.

Every NASL is intended to be run as a test. Thus, its first part will always describe what the test is and what a positive result means. In most cases, the test is being done for a specific vulnerability, and a successful test means that the target (host/service) is vulnerable. The second part of the script runs NASL commands to provide a success/fail result. The script can also use the Nessus registry (the knowledge base) to provide more information on the target.

## Structure of a NASL Script

NASL scripts consist of a description section and a test section. Even though the test section is the one that does the actual testing, the description is equally important. The description part is crucial to the Nessus environment; without it, the environment would be unable to determine the order in which tests should be executed, unable to determine which tests require information from which other test or tests, unable to determine which test might need to be avoided as it may cause harm to the host being tested, and finally unable to determine which tests affect which service on the remote host, thus avoiding running them on irrelevant services or even hosts. Let’s briefly discuss these sections.

### THE DESCRIPTION SECTION

The first part of a NASL file, the NASL description, is used by the Nessus engine to identify the plugin and provide the user with a description of the plugin. Finally, if the plugin run was successful, the engine will use this section to provide the user with the results. The description section should look something like the following (code taken from wu\_ftpd\_overflow):

```NASL
if(description)
{
 script_id(10318);
 script_bugtraq_id(113, 2242, 599, 747);
 script_version ("$Revision: 1.36 $");
 script_cve_id("CVE-1999-0368");

 name["english"] = "wu-ftpd buffer overflow";
 script_name(english:name["english"]);

 desc["english"] = "
It was possible to make the remote FTP server crash
by creating a huge directory structure.
This is usually called the 'wu-ftpd buffer overflow'
even though it affects other FTP servers.
It is very likely that an attacker can use this
flaw to execute arbitrary code on the remote
server. This will give him a shell on your system,
which is not a good thing.
Solution : upgrade your FTP server.
Consider removing directories writable by 'anonymous'.

Risk factor : High";
 script_description(english:desc["english"]);

 script_summary(english:"Checks if the remote ftp can be buffer overflown");
 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");

 script_dependencies("find_service.nes", "ftp_write_dirs.nes");
 script_require_keys("ftp/login", "ftp/writeable_dir");
 script_require_ports("Services/ftp", 21);
 exit(0);
}
```

The section contained in the preceding if command is the description section of the NASL. When the NASL script is run with the description parameter set, it will run the code in this clause and exit, instead of running the actual script.

The description sets the following attributes:

- `script_id`. This globally unique ID helps Nessus identify the script in the knowledge base, as well as in any other script dependencies.
- `script_bugtraq_id` and `script_cve_id`. These functions set CVE and Bugtraq information, searchable in the Nessus user interface. This helps to index vulnerabilities and provide external resources for every vulnerability.
- `script_name`. A short descriptive name to help the user understand the purpose of the script.
- `script_description`. This sets the information displayed to the user if the script result was successful. The description should describe the test that was done, the consequences, and any possible solution available. It is also a good idea to set a risk factor for the script. This can help the user prioritize work when encountering the results of the script.
- `script_category`. The script category is used by the Nessus engine to determine when the plugins should be launched.
- `script_family`. A plugin might belong to one or more families. This helps the user to narrow down the amount of tests to run according to a specific family.
- `script_dependencies`. If your NASL requires other scripts to be run, their *script_ids* should be written here. This is very useful, for example, to cause a specific service to run on the target machine. After all, there is little sense in running a test that overflows a command in an FTP (File Transfer Protocol) server if there is no FTP server actually running on the target host.
- `script_require_keys`. The usage of the knowledge base as a registry will be explained later on, but this command can set certain requirements for knowledge base keys to exist before running the script.
- `script_require_ports`. One of Nessus’ capabilities is running a service mapping on the remote host in several ways; we can use this to detect servers running on non-standard ports. If in our example the target runs an FTP server on port 2100 instead of the default port 21, and Nessus was able to detect this, we are able to run the test more accurately, independent of the actual port where the service is running.

### THE TEST SECTION

A lot of information is presented in the following sections on how to write plugins effectively and how to benefit from various capabilities of the NASL language, but first of all, what does a NASL test look like?

The first step will usually be to detect if the target runs the service or network protocol we want to test. This can be done either via Nessus’ knowledge base or by probing ourselves. If we discovered the host runs the service we want to test, we will probably want to connect to this service and send some sort of test request. The request can be for the host to provide a specially crafted packet, read the service banner, or use the service to get information on the target. After getting a reply from the server, we will probably search for something in the reply to decide if the test was successful or not. Based on this decision, we will notify Nessus of our findings and exit.

For example, the test part of a script reading the banner of a target Web server can be written like the following:

```NASL
include("http_func.inc"); #include the NASL http library functions
#Use the knowledge base to check if the target runs a web server
port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);
#Create a new HTTP request
req = http_get(item:"/", port:port);
#Connect to the target port, and send the request
soc = http_open_socket(port);
if(!soc) exit(0);
send(socket:soc, data:req);
r = http_recv(socket:soc);
http_close_socket(soc);
#If the server replied, notify of our success
if(r)
    security_note(port:port, data:r);
```

## Writing Your First Script

When writing NASL scripts, it is common practice to test them with the nasl command-line interpreter before launching them as part of a Nessus scan. The nasl utility is part of the Nessus installation and takes the following arguments:
`nasl [–t <target>] [-T tracefile] script1.nasl [script2.nasl ...]`
where:

- `-t <target>` is the IP (Internet Protocol) address or hostname against which you would like to test your script. The NASL networking functions do not allow you to specify the destination address when establishing connections or sending raw packets. This limitation is as much for safety as for convenience and has worked very well so far. If this option is not specified, all connections will be made to the loopback address, 127.0.0.1 (localhost).
- `-T <tracefile>` forces the interpreter to write debugging information to the specified file. This option is invaluable when diagnosing problems in complex scripts. An argument of - will result in the output being written to the console.

This utility has a few other options covered later in this chapter. For a complete listing of available options, execute this program with the *-h* argument.

For our first NASL script, we will write a simple tool that connects to an FTP server on TCP (Transmission Control Protocol) port 21, reads the banner, and then displays it on screen. The following NASL code demonstrates how easy it is to accomplish this task:

```NASL
soc = open_sock_tcp(21);
if ( ! soc ) exit(0);
banner = recv_line(socket:soc, length:4096);
display(banner);
```

Let’s walk through this small example:

`soc = open_sock_tcp(21);`

This function opens a TCP socket on port 21 of the current target (as specified with *nasl –t*). This function returns NULL on failure (the remote port is closed or not responding) and a nonzero file descriptor on success.

`banner = recv_line(socket:soc, length:4096);`

This function reads data from the socket until the number of bytes specified by the length parameter has been received, or until the character \\n is received, whichever comes first.

As you can see, the function *open\_sock\_tcp()* takes a single, non-named argument, while the function *recv_line()* takes two arguments that are prefixed by their names. These are referred to as anonymous and named functions. Named functions allow the plugin writer to specify only the parameters that he needs, instead of having to supply values for each parameter supported by the function. Additionally, the writer does not need to remember the exact order of the parameters, preventing simple errors when calling a function that supports many options. For example, the following two lines produce identical results:

`banner = recv_line(socket:soc, length:4096);`
`banner = recv_line(length:4096, socket:soc);`

Save this script as test.nasl and execute it on the command line:

> $ /usr/local/bin/nasl –t ftp.nessus.org test.nasl
> \*\* WARNING : packet forgery will not work
> \*\* as NASL is not running as root
> 220 ftp.nessus.org Ready

If you run *nasl* as a nonroot user, you will notice that it displays a warning message about packet forgery. NASL scripts are capable of creating, sending, and receiving raw IP packets, but they require root privileges to do so. In this example, we are not using raw sockets and can safely ignore this message.

Now, let’s modify our script to display the FTP banner in a Nessus report. To do so, we need to use one of the three special-purpose reporting functions: *security\_hole(), security\_warning(), and security_note()*. These functions tell the Nessus engine that a plugin is successful (a vulnerability was found), and each denotes a different severity level. A call to the *security_note()* function will result in a low-risk vulnerability being added to the report, a call to *security_warn()* will result in a medium-risk vulnerability, and *security_hole()* is used to report a high-risk vulnerability. These functions can be invoked in two ways:

`security_note(<port>)`

or

`security_note(port:<port>, data:<report>, proto:<protocol>)`
In the first case, the plugin simply tells the Nessus engine that it was successful. The Nessus engine will copy the plugin description (as registered with *script_description()*) and will place it into the report. This is sufficient for most plugins; either a vulnerability is there and we provide a generic description, or it is not and we do not report anything. In some cases, you might want to include dynamic text in the report. This dynamic text could be the version number of the remote web server, the FTP banner, the list of exported shares, or even the contents of a captured password file.

In this particular example, we want to report the FTP banner that we received from the target system, and we will use the long form of the *security_note()* function to do this:

```NASL
soc = open_sock_tcp(21);
if ( ! soc ) exit(0);
banner = recv_line(socket:soc, length:4096);
security_note(port:21, data:"The remote FTP banner is : " + banner, proto:"tcp");
```

If you execute this script from the command line, you will notice that the data parameter is written to the console. If no data parameter was specified, it will default to the string “Successful.” When this plugin is launched by the Nessus engine, this data will be used as the vulnerability description in the final report.

Now that our plugin code has been modified to report the FTP banner, we need to create the description section. This section will allow the plugin to be loaded by the Nessus engine:

```NASL
if ( description )
{
        script_id( 90001);
        script_name(english:"Simple FTP banner grabber");
        script_description(english:"
This script establishes a connection to the remote host on port 21 and
extracts the FTP banner of the remote host");

        script_summary(english:"retrieves the remote FTP banner");
        script_category(ACT_GATHER_INFO);
        script_family(english:"Nessus Book");
        script_copyright(english:"(C) 2004 Renaud Deraison");
        exit(0);
}

soc = open_sock_tcp(21);
if ( ! soc ) exit(0);
banner = recv_line(socket:soc, length:4096);
security_note(port:21, data:"The remote FTP banner is : " + banner, proto:"tcp");
```

# Commonly Used Functions

The Nessus NASL language is very versatile and has many different basic functions used for manipulating strings, opening sockets, sending traffic, generating raw packets, and more. In addition, many more advanced functions utilize the underlying basic functions to provide more advanced functionality, such as SSH (Secure Shell) connectivity, SMB (Server Message Block) protocol support, and advanced HTTP (Hypertext Transmission Protocol) traffic generation.

When writing a NASL you don’t have to know all the functions available via the NASL interface; rather, you can use the most basic functions when low-level work is necessary or use more advanced functions that wrap these basic functions when more abstract work is needed, such as in the case where SQL injection or cross-site scripting vulnerabilities are being tested.

One example of this is using the open\_sock\_tcp() function to open a socket to a remote host or using the more common get\_http\_port() function when connectivity to a Web server is necessary. get\_http\_port() does everything for you—from opening the socket to marking it in the knowledge base as a functioning HTTP host that will be used later to speed up any future connectivity to this port.

At the time of this writing, more than 1,500 tests utilize the advanced functions provided for communication with Web servers. These functions reside inside the http\_func.inc and http\_keepalive.inc include files. They provide easy access to functionality that allows querying a remote host for the existence of a certain file, querying a remote host using a special URI (Universal Resource Identifier) that in turn might or might not trigger the vulnerability.

The functions included in the http\_func.inc and http\_keepalive.inc files make the NASL writer’s life a lot easier, as they take away the hassle of opening the ports, generating HTTP traffic, sending this traffic to the remote host, receiving the response, breaking the response into its two parts (header and body), and finally closing the connection.

Writing a test for a Web-based vulnerability requires writing roughly 22 lines of code starting with a request to open a Web port if it hasn’t been opened already:

```NASL
port = get_http_port(default:80);
if ( ! port ) exit(0);
```

The get\_http\_port is called with a default port number for this specific vulnerability. In most cases the default value for the *default* parameter is 80, as the vulnerability is not expected to sit on any other port than the default Web server’s port. However, in some cases the product might be listening by default on another port, for example in the case where a page resides on a Web server’s administrative port.

Once we have confirmed that the host is in fact listening to HTTP traffic, we can continue by providing a list of directories under which we want to look for the vulnerability. This is done using the foreach function, which will call the lines that follow for each of the values provided by it:

`foreach dir (cgi_dirs())`

Next we issue a call to the http_get function that in turn will construct an HTTP GET request for us, we need to provide the function with the URI we want it to retrieve for us. The URI doesn’t have to be a static one, rather we can use the string function or the plus sign to generate dynamic URIs:

`buf = http_get(item:dir + "/store/BrowseCategories.asp?Cat0='1", port:port);`

Next we need to send the generated HTTP traffic to the remote server. By utilizing the wrapper function http\_keepalive\_send_recv, we can avoid the need to actually call the send/recv function. Furthermore, we can utilize the remote host’s, HTTP keepalive mechanism so that we will not be required to close our connection and reopen it whenever we want to send HTTP traffic to it:

`r1 = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);`

In some cases we want to analyze only the HTTP response’s body, discarding the header. This is for two reasons; first, the header might confuse our subsequent analysis of the response, and second, the content we are looking for will not appear in the header and analyzing its data would be a waste of time. In such cases where we only want to analyze the body, we can instruct the http\_keepalive\_send_recv function to return only the body by providing the *bodyonly* variable with the value of 1.

Once the data has returned to us, we can do either a static match:

`if ( "Microsoft OLE DB Provider for ODBC Drivers error '80040e14'" >< r1 )`

Or a more dynamic match:

`if(egrep(pattern:"Microsoft.*ODBC.*80040e14", string:r1 ) )`

The value of doing a dynamic match is that error messages are usually localized and statically testing for a match might cause the test to return a false negative (in which the test determines that the remote host is immune when in fact it is vulnerable). Therefore, whenever possible, try to use dynamic rather than static matching.

All that is left is to notify the Nessus environment that a vulnerability has been detected. This is done by calling up the security\_hole, security\_warning, or security_note function:

`security_note(port: port);`

# Regular Expressions in NASL

Other commonly used functions are a set of functions that implement an interface to regular expression processing and handling. A full description of regular expressions is outside the scope of this book, but a good starting point is the article found at http://en.wikipedia.org/wiki/Regular_expressions.

To give you an idea of how common the regular expressions are in Nessus, there are over 2000 different tests that utilize the *egrep* function and over 400 different tests that utilize the *eregmatch* function. These two numbers do not take into account that many of the tests use the functionality provided by http\_func.inc and http\_keepalive.inc, which in turn utilize regular expressions’ abilities parse data to great extent.

NASL supports egrep(1)-style operations through the *ereg(), egrep()*, and *ereg_replace()* functions. These functions use POSIX extended regular expression syntax. If you are familiar with Perl’s regular expression support, please keep in mind that there are significant differences between how NASL and Perl will handle the same regular expression.

The *ereg()* function returns TRUE if a string matches a given pattern. The string must be a one-line string (in other words, it should not contain any carriage return character). In the following example, the string “Matched!” will be printed to the console:

```NASL
if (ereg(string:"My dog is brown", pattern:"dog"))
{
      display("Matched\n");
}
```

The egrep() function works like ereg(), except that it accepts multiline strings. This function will return the actual string that matched the pattern or FALSE if no match was found. In the following example, the variable text contains the content of a UNIX passwd file. We will use egrep() to only return the lines that correspond to users whose ID value (the third field) is lower than 50.

> text = "
> root:*:0:0:System Administrator:/var/root:/bin/tcsh
> daemon:*:1:1:System Services:/var/root:/dev/null
> unknown:*:99:99:Unknown User:/dev/null:/dev/null
> smmsp:*:25:25:Sendmail User:/private/etc/mail:/dev/null
> www:*:70:70:World Wide Web Server:/Library/WebServer:/dev/null
> mysql:*:74:74:MySQL Server:/dev/null:/dev/null
> sshd:*:75:75:sshd Privilege separation:/var/empty:/dev/null
> renaud:*:501:20:Renaud Deraison,,,:/Users/renaud:/bin/bash";
> lower\_than\_50 = egrep(pattern:"\[^:\]*:\[^:\]:(\[0-9\]|\[0-5\]\[0-9\]):.*", string:text);
> display(lower\_than\_50);

Running this script in command-line mode results in the following output:

> $ nasl egrep.nasl
> root:*:0:0:System Administrator:/var/root:/bin/tcsh
> daemon:*:1:1:System Services:/var/root:/dev/null
> smmsp:*:25:25:Sendmail User:/private/etc/mail:/dev/null
> $

> ereg_replace(pattern:`<pattern>`, replace:`<replace>`, string:`<string>`);

The ereg_replace() function can be used to replace a pattern in a string with another string. This function supports regular expression back references, which can replace the original string with parts of the matched pattern. The following example uses this function to extract the Server: banner from an HTTP server response:

```NASL
include("http_func.inc");
include("http_keepalive.inc");
reply = http_keepalive_send_recv(data:http_get(item:"/", port:80), port:80);
if ( ! reply ) exit(0);

# Isolate the Server: string from the HTTP reply
server = egrep(pattern:"^Server:", string:reply);
if ( ! server ) exit(0);
server = ereg_replace(pattern:"^Server: (.*)$",
        replace:"The remote server is \1",
        string:server);
display(server, "\n");
```

Running this script in command-line mode results in the following output:

>$ nasl –t 127.0.0.1 ereg_replace.nasl
The remote server is Apache/1.3.29 (Darwin)
$

## String Manipulation
NASL is quite flexible when it comes to working with strings. String operations include addition, subtraction, search, replace, and support for regular expressions. NASL also allows you to use escape characters (such as \n) using the string() function.

### HOW STRINGS ARE DEFINED IN NASL
Strings can be defined using single quotes or double quotes. When using double quotes, a string is taken as is—no interpretation is made on its content—while strings defined with single quotes interpret escape characters. For example:
`A = "foo\n";`
`B = 'foo\n';`

In this example, the variable A is five characters long and is equal to foo\n, while variable B is four characters long and equal to foo, followed by a carriage return. This is the opposite of how strings are handled in languages such as C and Perl, and can be confusing to new plugin developers.

We call an interpreted string (defined with single quotes) a pure string. It is possible to convert a regular string to a pure string using the string() function. In the following example, the variable B is now four characters long and is equal to foo, followed by a carriage return.

`A = "foo\n";`
`B = string(A);`

If you are familiar with C, you might be used to the fact that the zero byte (or NULL byte) marks the end of a string. There’s no such concept in NASL—the interpreter keep tracks of the length of each string internally and does not care about the content. Therefore, the string \0\0\0 is equivalent to three NULL byte characters, and is considered to be three bytes long by the strlen() function.

You may build strings containing binary data using the raw_string() function. This function will accept an unlimited number of arguments, where each argument is the ASCII code of the character you want to use. In the following example, the variable A is equal to the string XXX (ASCII code 88 and 0x58 in hexadecimal).

`A = raw_string(88, 0x58, 88);`

NASL supports string manipulation through the addition (+) and subtraction (–) operators. This is an interesting feature of the NASL language that can save quite a bit of time during plugin development.

The addition operator will concatenate any two strings. The following example sets the variable A to the value foobar, and then variable B to the value *foobarfoobarfoobar*.

`A = "foo" + "bar";`
`B = A + A + A;`

The subtraction operator allows you to remove one string from another. In many cases, this is preferable to a search-and-replace or search-and-extract operation. The following example will set the variable A to the value 1, 2, 3.

`A = "test1, test2, test3";`
`A = A – "test";  # A is now equal to "1, test2, test3"`
`A = A – "test";  # A is now equal to "1, 2, test3"`
`A = A – "test";  # A is now equal to "1, 2, 3"`

### STRING SEARCH AND REPLACE
NASL allows you to easily search for one string and replace it with another, without having to resort to regular expressions. The following example will set the variable A to the value foo1, foo2, foo2.

`A = "test1, test2, test3";`

# Nessus Daemon Requirements to Load a NASL
The Nessus daemon requires several things that a NASL implements before it will load a NASL placed in the plugin directory. These items are required as the Nessus daemon needs to know several things on the test such as its unique ID, name, description, summary, category, family, and copyright notice. While the name, description, summary, family, and copyright can be left as blank, the ID and category have to be properly defined or the test will not be listed by the Nessus daemon as being part of its test list.

The script_id function defines a test’s unique ID. Test IDs are assigned by the Nessus community members, who make sure that no two tests are given the same ID number. The categories of the tests can be any of the following: ACT_INIT,ACT_SCANNER,ACT_SETTINGS,ACT_GATHER_INFO,ACT_ATTACK,ACT_MIXED_ATTACK,ACT_DESTRUCTIVE_ATTACK,ACT_DENIAL,ACT_KILL_HOST,ACT_FLOOD, or ACT_END. Depending on the type of category assigned to the test, Nessus will run it at a specific part of the scan. For example, defining a test as ACT_INIT or ACT_END will restrict the launch of the test to the beginning or end of the scan, respectively.

Once a test has the aforementioned settings, the Nessus daemon will load the test into its test list. The Nessus daemon will launch the test whenever the test’s ID is included in a scan’s plugin list.

# Final Touches
Nessus’ NASL language provides an easy-to-use interface for writing tests. The language is also easy to extend by building wrapper functions that utilize one or more basic functions provided by the NASL interpreter. Once such a wrapper is constructed, many tests can utilize it and gain access to otherwise hard-to-use protocols such as SMB, RPC, and so on. In most cases, NASL plugin writers do not need to hassle with the inner workings of the NASL language or the inner workings of the wrapper functions because they can call very few functions that handle HTTP traffic without having to know how to open a socket, send out data, or parse HTTP traffic.