# astban
An asterisk tool for blocking brute force attacks

# Description
This is a perl script that uses Net::Pcap to sniff on the network. The script runs as a daemon and looks for traffic going OUT of the LAN.
It filters SIP responses and will automatically invoke iptables to block hosts to which it sees asterisk sending more than 10 (configurable)
responses higher or equal than 400 to a remote host. Only responses sent for REGISTER and INVITE are filtered.

# Usage
Edit the script to change the configuration.

Variable | Description | Example
------------ | ------------- | -------------
$to | Email address where to send notifications | "pat\@localhost"
$pbxPort | UDP port Asterisk is listening on | 5060
$device | Net device | "eth0"
$exemptNet | Network that is exempt from being banned. Whatever destination that starts with this (string-wise) will be exempt  | "192.168.1"
$maxfailcount | Minimum number of failures before banning | 10

# Website
http://www.dumaisnet.ca/index.php?article=35794ced17be93fdb1a28f73f754512c

