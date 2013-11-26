#smonitor

##About

A python daemon for monitoring devices connected to a switch and sending
results to a zabbix server.

The daemon gets a list of MAC addresses of devices on each port of
a switch over the SNMP protocol. If it's possible the daemon will scan 
available local networks with the nmap network scanner to enrich the MAC
cache of the switch and to create a mapping derived MAC addresses to IPs.
Moreover it tries to map known IP addresses to fully qualified domain
names (FQDN). Lastly all gathered data are processed and sent to a zabbix 
server.

The smonitor sends logs to syslog service using the facility daemon.

See available settings and its description in the file Settings.py.sample.

##Requirements
 - Infrastucture: zabbix server
 - Python modules: daemon, syslog
 - Shell commands: ifconfig, snmpwalk, nmap, zabbix\_sender
 - Rights: it's enough common user rights for daemon running, but you have to allow execution of the nmap command by the sudo utility without password prompt

##Tested on devices
 - HP Procurve 2520, 1700
 - D-Link DES-3028, DES-2108
 - Asus GigaX 2008EX
 - 3com 3CDSG8

It doesn't support Cisco switches yet.
