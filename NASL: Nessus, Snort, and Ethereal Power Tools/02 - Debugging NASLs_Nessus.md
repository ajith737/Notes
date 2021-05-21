# In This Toolbox
There are two methods of debugging newly created or existing Nessus Attack Scripting Languages (NASLs): one is to use the command-line interpreter, and the other is to run it using the Nessus daemon. Each has its shortcomings; for example, running it using the command-line interpreter doesn’t allow to debug any interaction between two tests that might be required, while debugging it using the Nessus daemon requires a longer startup process than simply providing the command-line interpreter with a hostname or IP (Internet Protocol) address and the name of the script to execute.

# How to Debug NASLs Using the Runtime Environment
We will begin with debugging via the NASL command-line interpreter, as this method is the easiest to implement and the easiest to utilize. Debugging a NASL script can be composed of two main components; the easier part is testing the validity of the code and the harder part is testing the validity of the vulnerability test itself.

## Validity of the Code
Testing the validity of the code (that is, ensuring that the code can be understood by the NASL interpreter) can be done by either running the NASL script with the command-line interpreter accompanied by the option -p, which in essence instructs the NASL interpreter to just parse and not execute the code found inside it.

[Swiss Army Knife: NASL Reference Guide](http://michel.arboi.free.fr/nasl2ref/)

The option **-p** only checks to see whether the command syntax is written properly, not whether all the functions are available for execution. For example, suppose you are running the following script:

`port = get_http_port(default:80);`
With the NASL interpreter and the **-p** option set, no errors will be returned. An error should have returned, as the get_http_port() function is not part of the NASL; rather, it is an extension provided by the http_func.inc file. To overcome this problem the NASL interpreter comes with another option called **-L**, or lint, which does more extended testing.

Running the same script as before with the **-L** option set will result in the following error being shown:
`[5148](beyondsecurity_sample1.nasl) Undefined function 'get_http_port'`

The error returned is composed of three components: the number enclosed between the two square brackets is the process number that caused the error; the entry enclosed between the two regular brackets is the name of the script being executed; the third part defines the kind of error that has occurred.

The preceding error can be easily solved by adding the following line:
`include("http_func.inc");`

Just prior to the get_http_port() function call, the **-L** option is not able to spot problems that have occurred within functions; rather, it is only able to detect errors that occur within the main program. For example, the following code will come out error free by using both the **-L** option and the **-p** option:

```NASL
function beyondsecurity(num)
{
 port = get_http_port(default:num);
}

beyondsecurity(num:80);
```

This is due to the fact that no calls to the function itself are being preformed by the error discover algorithm. Therefore, to determine whether your script is written properly or not, the best method is to actually run it against the target. We ran the following code against a test candidate that supports port 80 and Web server under that port number:

> `asl -t 127.0.0.1 beyondsecurity_sample2.nasl`
`[5199](beyondsecurity_sample2.nasl) Undefined function 'get_http_port'`

As you can see, the NASL interpreter has detected the error we expected it to detect. Some errors are nested and are caused by external files we included. Unfortunately, in those cases the error displayed will be the same as what would be displayed if the code used in the include file was inside the NASL file we wrote.

To demonstrate this we will create two files. The first file is an include file called beyondsecurity_sample3.inc that will contain the following code:

```NASL
function beyondsecurity(num)
{
 port = get_http_port(default:num);
}
```

The second file, a NASL file that will be called beyondsecurity_sample3.nasl, will contain the following code:


```NASL
include("beyondsecurity_sample3.inc");

beyondsecurity(num:80);
```

Running the script via the command-line interpreter with a valid hostname will result in the following error being returned:

`[5274](beyondsecurity_sample3.nasl) Undefined function 'get_http_port'`

As you can see, even though the error code should have been displayed in reference to the include file, the NASL language makes no differentiation between the include files and the actual NASL code. This is due to the fact that when an include() directive is present in the NASL code, the entire code present inside the include file is made part of the NASL code and regarded as an integrated part of it.

This can be better seen in action by utilizing the **-T** option. This option tells the NASL interpreter to trace its actions and print them back to either a file or to the standard output. Running the code in the previous example with the trace option set to true will result in the following content being returned by the interpreter:

>`5286]() NASL> [080812b0] <- 1`
`[5286]() NASL> [080812e0] <- 0`
`[5286]() NASL> [08081310] <- 5`
`[5286]() NASL> [08081348] <- 6`
`[5286]() NASL> [08081380] <- 17`
`[5286]() NASL> [080813b8] <- 1`
`[5286]() NASL> [080813f0] <- 0`
`[5286]() NASL> [08081420] <- 2`
`[5286]() NASL> [08081458] <- 1`
`[5286]() NASL> [08081488] <- 2`
`[5286]() NASL> [080814c0] <- 3`
`[5286]() NASL> [080814f8] <- 4`
`[5286]() NASL> [08081530] <- 5`
`[5286]() NASL> [08081568] <- 2201`
`[5286]() NASL> [08081598] <- 1`
`[5286]() NASL> [080815c8] <- 2`
`[5286]() NASL> [080815f8] <- 4`
`[5286]() NASL> [08081628] <- 8`
`[5286]() NASL> [08081658] <- 16`
`[5286]() NASL> [08081688] <- 32`
`[5286]() NASL> [080816b8] <- 32768`
`[5286]() NASL> [080816e8] <- 16384`
`[5286]() NASL> [08081718] <- 8192`
`[5286]() NASL> [08081748] <- 8191`
`[5286]() NASL> [08081778] <- 0`
`[5286]() NASL> [080817a8] <- 3`
`[5286]() NASL> [080817e0] <- 4`
`[5286]() NASL> [08081810] <- 5`
`[5286]() NASL> [08081848] <- 6`
`[5286]() NASL> [08081888] <- 7`
`[5286]() NASL> [080818b8] <- 1`
`[5286]() NASL> [080818f0] <- 2`
`[5286]() NASL> [08081928] <- 8`
`[5286]() NASL> [08081960] <- 9`
`[5286]() NASL> [08081990] <- 10`
`[5286]() NASL> [080819c0] <- 1`
`[5286]() NASL> [08081a20] <- 1`
`[5286]() NASL> [08081a58] <- 0`
`[5286]() NASL> [08081a90] <- "beyondsecurity_sample3.nasl"
NASL:0003> beyondsecurity(...)`
`[5286]() NASL> [08081e68] <- 80`
[`5286](beyondsecurity_sample3.nasl) NASL> Call beyondsecurity(num: 80)
NASL:0003> port=get_http_port(...);
NASL:0003> get_http_port(...)`
`[5286](beyondsecurity_sample3.nasl) Undefined function 'get_http_port'`
`[5286]() NASL> [08081d60] <- undef`
`[5286](beyondsecurity_sample3.nasl) NASL> Return beyondsecurity: FAKE`

The first parts are not relevant at the moment. What is more interesting is the part where we can actually see the script requesting the function beyondsecurity to be called with the value of 80 for its num parameter. Further, we can see the NASL interpreter looking the function get_http_port and not being able to locate it and consequently returning an error.

By adding to the preceding code the include (http_func.inc) directive and running the NASL trace command again, the following output will be returned (the end of the trace was dropped for simplicity):

>`[5316]() NASL> [08091d88] <- 1`
`[5316]() NASL> [08091db8] <- 0`
`[5316]() NASL> [08091de8] <- 5`
`[5316]() NASL> [08091e20] <- 6`
`[5316]() NASL> [08091e58] <- 17`
`[5316]() NASL> [08091e90] <- 1`
`[5316]() NASL> [08091ec8] <- 0`
`[5316]() NASL> [08091ef8] <- 2`
`[5316]() NASL> [08091f30] <- 1`
`[5316]() NASL> [08091f60] <- 2`
`[5316]() NASL> [08091f98] <- 3`
`[5316]() NASL> [08091fd0] <- 4`
`[5316]() NASL> [08092008] <- 5`
`[5316]() NASL> [08092040] <- 2201`
`[5316]() NASL> [08092070] <- 1`
`[5316]() NASL> [080920a0] <- 2`
`[5316]() NASL> [080920d0] <- 4`
`[5316]() NASL> [08092100] <- 8`
`[5316]() NASL> [08092130] <- 16`
`[5316]() NASL> [08092160] <- 32`
`[5316]() NASL> [08092190] <- 32768`
`[5316]() NASL> [080921c0] <- 16384`
`[5316]() NASL> [080921f0] <- 8192`
`[5316]() NASL> [08092220] <- 8191`
`[5316]() NASL> [08092250] <- 0`
`[5316]() NASL> [08092280] <- 3`
`[5316]() NASL> [080922b8] <- 4`
`[5316]() NASL> [080922e8] <- 5`
`[5316]() NASL> [08092320] <- 6`
`[5316]() NASL> [08092360] <- 7`
`[5316]() NASL> [08092390] <- 1`
`[5316]() NASL> [080923c8] <- 2`
`[5316]() NASL> [08092400] <- 8`
`[5316]() NASL> [08092438] <- 9`
`[5316]() NASL> [08092468] <- 10`
`[5316]() NASL> [08092498] <- 1`
`[5316]() NASL> [080924f8] <- 1`
`[5316]() NASL> [08092530] <- 0`
`[5316]() NASL> [08092568] <- "beyondsecurity_sample3.nasl"
NASL:0003> beyondsecurity(...)`
`[5316]() NASL> [08092ff0] <- 80`
`[5316](beyondsecurity_sample3.nasl) NASL> Call beyondsecurity(num: 80)
NASL:0005> port=get_http_port(...);
NASL:0005> get_http_port(...)`
`[5316](beyondsecurity_sample3.nasl) NASL> [08092ff0] -> 80
[5316]() NASL> [080932f0] <- 80`
`[5316](beyondsecurity_sample3.nasl) NASL> Call get_http_port(default: 80)`

Again, the get_http_port function was called, but this time it was located and successfully launched. As pointed out before, there is no reference to get_http_port being part of the http_func.inc file, nor whether the beyondsecurity function is even part of the beyondsecurity_sample3.inc file.

As there is no information about which include file is causing the error, we have to resort to a more basic method of debugging—printing each step we take and determining which one has caused the problem by enclosing it between two printed steps. This kind of debugging method is very basic and very tiresome, as it requires you to either have some clue to where the problem might be stemmed from or to add a lot of redundant code until the culprit is found. To generalize the method you would need to add display() function calls every few lines and before every possible call to an external function. In the end, you would achieve something similar to the following:

>step 1
step 2
step 3
step 3.1
step 3.2
step 3.3
step 3.1
step 3.2
step 3.3
`[3517](beyondsecurity_sample4.nasl) Undefined function 'get_http_port'`
step 4
step 5
done

All steps are a few lines apart, and a few steps are repeated, as they are inside some form of loop. The output in the preceding example tells us that somewhere between our step 3.3 and step 4 a call to the get_http_port, directly or indirectly via an include file, has been made.

## Validity of the Vulnerability Test
Once we have our NASL script up and running and error-free, we can move to a more important part of the debugging stage—determining whether the script you have just written does actually determine the existence or nonexistence of the vulnerability.

There are a few methods you can use to debug your NASL script once the code has been confirmed to be free of coding mistakes: you can print out any variable you desire via the display function or, as an alternative, you can dump the contents of binary data via the dump function provided by the dump.inc file.

In both cases the shortcoming of the two functions is that unless you were the one generating the packet, both functions cannot display what was sent to the host being tested. Such is in the case of SMB, RPC, and others where the infrastructure of Nessus’ include files provides the support for the aforementioned protocols.

In the previous two cases, SMB and RPC, your only alternative to Nessus’ debugging routines is to do either of the following:

1. Add extensive debugging code to the include files being utilized.

2. Use a sniffer and capture the outgoing and incoming traffic.

As it is no easy feat to add debugging routines to the infrastructure used by the Nessus daemon, the more viable option would be to use a packet sniffer. To demonstrate how a sniffer would provide better debugging results, we will run a simple NASL script that tests the existence of a file inclusion vulnerability:

```NASL
include("http_func.inc");
include("http_keepalive.inc");


debug = 1;


if (debug)

{
 display("First part stats here\n");
}


port = get_http_port(default:80);
if (debug)
{
 display("port: ", port, "\n");
}


if(!get_port_state(port))exit(0);


if (debug)
{
 display("First part ends here\n");
}


function check(loc)
{
 if (debug)
 {
  display("Second part starts here\n");
 }
 req = http_get (item: string(loc, "/inserter.cgi?/etc/passwd"), port: port);
 if (debug)
 {
  display("Second part ends here\n");
 }


 if (debug)
 {
  display("req: ", req, "\n");
 }


 if (debug)
 {
  display("Third part starts here\n");
 }
 r = http_keepalive_send_recv(port:port, data:req);
 if (debug)
 {
  display("Third part ends here\n");
 }


 if (debug)
 {
  display("r: ", r, "\n");
 }


 if( r == NULL )exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
 {
  security_warning(port);
  exit(0);
 }
}


foreach dir (make_list(cgi_dirs()))
{
 if (debug)
 {
  display("dir: ", dir, "\n");
 }
 check(loc:dir);
}
```

Once launched against a vulnerable site, the code in the previous example would return the following results (we are launching it by using the NASL command-line interpreter):

>$ nasl -t www.example.com inserter_file_inclusion.nasl
** WARNING : packet forgery will not work
** as NASL is not running as root
First part begins here
[17697] plug_set_key:internal_send(0)['3 Services/www/80/working=1;
']: Socket operation on non-socket
First part ends here
port: 80
dir: /cgi-bin
Second part starts here
Second part ends here
req: GET /cgi-bin/inserter.cgi?/etc/passwd HTTP/1.1
Connection: Close
Host: www.example.com
Pragma: no-cache
User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)
Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*
Accept-Language: en
Accept-Charset: iso-8859-1,*,utf-8


>Third part starts here
[17697] plug_set_key:internal_send(0)['1 www/80/keepalive=yes;
']: Socket operation on non-socket
Third part ends here
res: HTTP/1.1 200 OK
Date: Thu, 28 Apr 2005 09:26:22 GMT
Server: Apache/1.3.35 (Unix) PHP/4.3.3 mod_ssl/2.8.15 OpenSSL/0.9.7b FrontPage/4.0.4.3
Keep-Alive: timeout=15, max=100
Connection: Keep-Alive
Transfer-Encoding: chunked
Content-Type: text/html


>`<meta></meta>document.writeln('root:x:0:0:root:/root:/bin/bash');`
document.writeln('bin:x:1:1:bin:/bin:');
document.writeln('daemon:x:2:2:daemon:/sbin:');
document.writeln('adm:x:3:4:adm:/var/adm:');
document.writeln('lp:x:4:7:lp:/var/spool/lpd:');
document.writeln('sync:x:5:0:sync:/sbin:/bin/sync');
document.writeln('shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown');
document.writeln('halt:x:7:0:halt:/sbin:/sbin/halt');
document.writeln('mail:x:8:12:mail:/var/spool/mail:');
document.writeln('news:x:9:13:news:/var/spool/news:');
document.writeln('uucp:x:10:14:uucp:/var/spool/uucp:');
document.writeln('operator:x:11:0:operator:/root:');
document.writeln('games:x:12:100:games:/usr/games:');
document.writeln('gopher:x:13:30:gopher:/usr/lib/gopher-data:');
document.writeln('ftp:x:14:50:FTP User:/var/ftp:');
document.writeln('nobody:x:99:99:Nobody:/:');



>Success


***
**Master Craftsman...: Ethereal’s Follow TCP Stream**

In most cases incoming and outgoing HTTP (Hypertext Transfer Protocol) traffic gets divided into several packets, in which case debugging the data being transferred inside such packets cannot be easily read. To workaround such cases Ethereal has the ability to reconstruct the TCP (Transmission Control Protocol) session and display it in a single window. To enable Ethereal’s Follow TCP stream option, all that is required is to capture the relevant packets and right-click on any of the TCP packets in question and select the Follow TCP stream option.
***

By running Ethereal in the background and capturing packets, we would notice the following traffic being generated, some of which will be generated because this is the first time this host is being contacted:

```
GET / HTTP/1.1
Host: www.example.com
(Traffic Capture 1)
```

This is followed by the following traffic:

```
GET / HTTP/1.1
Connection: Keep-Alive
Host: www.example.com
Pragma: no-cache
User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)
(Traffic Capture 2)
```
Finally, the following traffic will be generated:

```
GET /cgi-bin/inserter.cgi?/etc/passwd HTTP/1.1
Connection: Keep-Alive
Host: www.example.com
Pragma: no-cache
User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)
Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*
Accept-Language: en
Accept-Charset: iso-8859-1,*,utf-8
(Traffic Capture 3)
```

As you might have noticed, there is a lot of traffic being generated behind the scenes. Furthermore, if we compare the traffic capture 3 with the data returned by NASL interpreter for the parameter req, we see that one specifies the HTTP connection header setting as Close, while the latter specifies it as Keep-Alive; therefore, something had to not only do this but also determine whether the remote server even supports a keep-alive state.

To understand a bit more about how a single traffic transfer became three distinguishable data transfers, we need to drill deeper into the Nessus inner workings. We will start with what appears to be a very simple function call, calling of the get_http_port(default:80) function. This function is responsible for initiating any HTTP traffic being done through the http_func.inc and http_keepalive.inc and not directly to the HTTP socket.

Once the function starts it will try determine whether the port being tested has been previously marked as Services/www, meaning that it supports WWW services. If so, it will return the appropriate port number:

```NASL
port = get_kb_item("Services/www");
if ( port ) return port;
```

If this fails, it will try to determine whether the port provided is marked as broken; that is, not responding, not returning HTTP headers, and so on. If the port is broken the function and the script will exit:


```NASL
p = get_kb_item("Services/www/" + default + "/broken");
if ( p ) exit(0);
```

If this fails and the function continues, the function will try to determine whether the port provided is marked as working. Working ports are those ports that can be connected to and that respond to the most basic HTTP traffic. If the port has been flagged as working, the function will return with the provided port number as its result:

```NASL
p = get_kb_item("Services/www/" + default + "/working");
if ( p ) return default;
```

If the previous test has not failed, the function will continue to open a socket against the provided port number; if it fails to do so, it will report the specified port number as broken:

```NASL
soc = http_open_socket(default);
if ( ! soc )
{
 set_kb_item(name:"Services/www/" + default + "/broken", value:1);
 exit(0);
}
```

Once the socket has been opened successfully, we notice that the function constructs an HTTP request, sends it to the socket, and waits for a response:

```
send(socket:soc, data:'GET / HTTP/1.1\r\nHost: ' + get_host_name() + '\r\n\r\n');
r = recv_line(socket:soc, length:4096);
close(soc);
```

As you might recall, we have seen this packet in our Ethereal capture; this sort of traffic is generated for any HTTP port being accessed for the first time, and subsequent requests to this port by the get_http_port function will not go through this, as the port will be marked either being broken or working. The following code will try to determine whether the provided port number is in fact broken by testing whether a response has not been received, that it doesn’t look like HTTP traffic, or that it returns an “HTTP Forbidden” response:

```NASL
if ( !r || "HTTP" >!< r || ( ereg(pattern:"^HTTP.* 403 ", string:r) && (now - then >= 5)
) )
{
 set_kb_item(name:"Services/www/" + default + "/broken", value:1);
 exit(0);
}
```

If the function hasn’t exited, the port has to be a valid one. It is marked as working, and the function returns the port number provided to it as the response:

```NASL
set_kb_item(name:"Services/www/" + default + "/working", value:1);
return default;
```

From the code in the previous example, we have determined one of the traffic patterns captured using the Ethereal sniffer. We are still missing one traffic pattern. We know that the last piece of traffic was requested by us; the second traffic pattern we have captured.

The debugging code has captured the attempt by the NASL interpreter to write the value of keepalive=yes to the knowledge base. Consequently, our best hunch would be that the function http_keepalive_send_recv is the one responsible for generating our mystery traffic.

The function http_keepalive_send_recv is defined inside the http_keepalive.inc file. We will go into greater detail on this function in Chapter 5, but briefly, support for the keep-alive infrastructure has been called up for the first time. The value of __ka_enabled has not yet been set to any value but –1, which tells the keep-alive infrastructure it has no knowledge of whether the keep-alive mechanism is supported by the remote host.

Therefore, once the http_keepalive_send_recv is called, the http_keepalive_enabled function is called:

```NASL
if(__ka_enabled == -1) __ka_enabled = http_keepalive_enabled(port:port);
```

As mentioned before, the role of the http_keepalive_enabled function is to determine whether the remote Web server supports keep-alive traffic by sending a Keep-Alive request to the server:

```
req = string("GET / HTTP/1.1\r\n",
"Connection: Keep-Alive\r\n",
"Host: ", get_host_name(), "\r\n",
"Pragma: no-cache\r\n",
"User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)\r\n\r\n");

soc = http_open_socket(port);
if(!soc)return -2;
send(socket:soc, data:req);
r = http_recv(socket:soc);
```

By processing the response returned by the server, the function can determine whether the remote host supports keep-alive communication. There are two main types of keep-alive implementations. In the case of Apache-like servers the response will contain a keep-alive header line. In the case of IIS-like servers the response does not contain the keep-alive header. We can therefore determine that the remote server supports the keep-alive function by sending the previous request without reopening the previously opened socket and determining whether a response has been returned. Only IIS implementations would respond to the second request.

[Swiss Army Knife...: HTTP Keep-Alive](http://www.faqs.org/rfcs/rfc2068.html)

The following code implements this concept:

```NASL
# Apache-Like implementation
if(egrep(pattern:"^Keep-Alive:.*", string:r))
{
 http_close_socket(soc);
 set_kb_item(name:string("www/", port, "/keepalive"), value:"yes");
 enable_keepalive(port:port);
 return(1);
}
else
{
 # IIS-Like Implementation
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if(strlen(r))
 {
  set_kb_item(name:string("www/", port, "/keepalive"), value:"yes");
  enable_keepalive(port:port);
  return(1);
 }
}
```

***
**Master Craftsman...: Improving the HTTP Keep-Alive Detection Mechanism**

The keep-alive detection mechanism is unable to detect IIS Web servers that support the keep-alive mechanism, but close the socket connected that connected to it unless the authentication mechanism has been satisfied, such as in the case where NTLM (NT LAN Manager) authentication has been enabled on the remote IIS server.
***

# How to Debug NASLs Using the Nessus Daemon Environment
In some cases it is impossible to use the NASL interpreter to debug the scripts. This is especially true in those cases where a complex system of test dependencies is in place. In these cases the only option to debug the NASL is to generate debugging code that will be later gathered from Nessus daemon’s debug log.

The log file to which the Nessus daemon writes is configured in the nessusd.conf file. By pointing the value of logfile to a file you desire, you can instruct the Nessus daemon where to create the log file. In most cases when Nessus is stored under the /usr/local/ directory the log file is stored under the /usr/local/var/nessus/logs/ directory.

The content of the Nessus daemon log file is called nessusd.dump. It contains all the output returned by the different tests, including errors and display function calls. Unlike when you use the NASL interpreter and immediately see the debug commands you have used, the log files do not list which NASL script produced the content you are seeing. The only exception to this is that when errors are listed, they are accompanied by the process id number, the filename, and the error that has occurred.

# Final Touches
You have learned two ways of debugging your newly written or existing NASLs. Further, you have seen that there is more than one approach where external tools such as packet sniffers are utilized to determine the type of traffic traversing the medium between the Nessus daemon and the tested host. You have also seen a glimpse of the way Nessus communicates with a remote Web server and how it detects Web servers that support keep-alive.