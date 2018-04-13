# inqServices
<pre>
    _             _____                 _                       __  
   (_)___  ____ _/ ___/___  ______   __(_)_______  _____  _____/ /_ 
  / / __ \/ __ `/\__ \/ _ \/ ___/ | / / / ___/ _ \/ ___/ / ___/ __ \
 / / / / / /_/ /___/ /  __/ /   | |/ / / /__/  __(__  ) / /  / /_/ /
/_/_/ /_/\__, //____/\___/_/    |___/_/\___/\___/____(_)_/  /_.___/ 
           /_/                                                      
</pre>

Overview
--------

Inquest is a script current in development which is intended to act as a wrapper for various other tools included within Kali Linux.  It will streamline the enumeration process helping you on your way to popping mad shellz.

This sub script (inqServices.rb) will eventually form the basis for Inquest's enumeration functions; however, this scripts current intention is to reliably and consistently perform nmap scans of varying intensites to discover open services and exploitable vulnerabilities.  This script is currently limited to scanning hosts, and cannot scan subnets.  This will be a future development if I can figure out a clean way of managing the scans.  Perfectly fine for hackthebox, OSCP laps and CTFs... not so useful for pentesting yet.

Basic threading is implemented to run scans for each host in parallel, and the entire function is wrapped so multiple hosts (upto 10 currently), may be scanned at any one given time.  Increasing the threads > 2 is not really reccomended for any hosts accessed over the internet or via a VPN.

Specific details
----------------

For reference, the following scans are performed for each host:

    Initial TCP Discovery:
        nmap -v -sS -F <host>

    UDP Discovery:
        nmap -v -sU -sV --version-all <host>
        
    All TCP Ports Discovery:
        nmap -v -sS -p - <host>

    Initial TCP Comprehensive:
        nmap -v -sS -A --version-all -p [discovered ports] --script=default,discovery,safe,vuln <host>

    All TCP Ports Comprehensive:
        nmap -v -sS -A --version-all -p [discovered ports] --script=default,discovery,safe,vuln <host>

Installation
------------

    apt-get install nmap
    git clone https://github.com/BradBeacham/inqServices.git
    gem install nmap-parser
    gem install highline -v 1.7.8

Usage
-----

    Usage: inqServices.rb
        -d, --output-dir <FILE>          Specify the directory to save all output
        -i <HOST>                        Specify individual host to perform enumeration against
        -l, --input-list <FILE>          File containing one host per line to read from (NO SUBNETS!!!!)
        -t, --threads [1-10]             Specify the number of concurrent scans to perform
            --no-colour                  Removes colourisation from the ourput
        -h, --help                       Display this screen

