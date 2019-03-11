![alt text](https://i.imgur.com/ck96pzh.png)
# AnchorWatch - A rogue device detection script for Windows with email alerts

# Features

AnchorWatch is a simple script that scans the subnet every X minutes and sends an email alert for each unknown device discovery.

Email contains the following information:

1. MAC Address
2. Hostname
3. IP Address
4. OS Name
5. OUI Vendor Name
6. Last Seen Timestamp

# Installation

AnchorWatch is a powershell script that depends on `nmap` - a network scanning utility - for scanning the subnet.
AnchorWatch will send an email notification each time an unknown device is detected on the network. 
An example of email notification from AnchorWatch:

![alt text](https://i.imgur.com/maS8aHw.jpg)

## Dependency

AnchorWatch has no dependency other than nmap. Download nmap for windows here: https://nmap.org/download.html

## Configuration

Edit ./anchorWatch.ps1 and add the follwing details in corresponding sections:

```
SMTP Hostname           Domain Name of SMTP Server
SMTP Username
SMTP Password
Email Address From      Sender@email.com
Email Address to        recipient@mailaddress.org
```

Additionally, you'd need to add network range in `trustDevices.ps1` also. 

# Scanning

```
./anchorWatch.ps1
```

Running `anchorWatch.ps1` will start AnchorWatch in default blacklisting mode.

Default mode blacklists all the devices by default. You'd need to whitelist all the devices manually by adding the Corresponding MAC to a text file named `known_hosts.txt`

`known_hosts.txt` data format:

```
<MAC Address> <Host name>
```
## Automatic Device Whitelisting

To speedup the whitelisting process, you can alternatively run the following command:
```
./trustDevices.ps1
```

`./trustDevices.ps1` scans the whole subnet(s) and creates a list of discovered devices under known_hosts.txt in a tabular form.
Net admins can then verify each device manually and manage their whitelist using known_hosts.txt

# Fix Powershell ExecutionPolicy Error

To change the execution policy for the computer, for particular users, or for particular sessions, use the Set-ExecutionPolicy cmdlet, as follows.

1. Start Windows PowerShell with the "Run as Administrator" option. (For more information, see Starting Windows PowerShell.) Only members of the Administrators group on the computer can change the execution policy.

2. Run the Set-ExecutionPolicy cmdlet.

As an Administrator, you can set the execution policy by typing this into your PowerShell window:

```
Set-ExecutionPolicy RemoteSigned
```

# About

AnchorWatch is a work of Freelance by Hardeep Singh. Originally created in 2015 for a fellow redittor who asked for a free alternative for Rogue Device Detection tool for Windows machine. 
At the time there were no cheap or free alternative available, especially for Windows domain. Hence, AnchorWatch came to life.

Hardeep Singh is the founder of https://rootsh3ll.com and primarily teaches Wireless Network Security. You can reach him on harry [at] rootsh3ll.com

Follow on Twitter: https://twitter.com/rootsh3ll

(Slight rework by github.com/cap44)