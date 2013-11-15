#smonitor

##About

A python daemon for monitoring devices connected to a switch and sending results to a zabbix server.

The daemon gets a list of MAC addresses of devices on each port of a switch over the SNMP protocol. If it's possible the daemon will scan available local networks with the nmap network scanner to enrich the MAC cache of the switch and to create a mapping derived MAC addresses to IPs. Moreover it tries to map known IP addresses to fully qualified domain names (FQDN). Lastly all gathered data are processed and sent to a zabbix server.

The smonitor sends log messages to syslog service using the facility daemon.

See available settings of the program and its description in the file Settings.py.sample

##Requirements
 - Infrastucture: zabbix server
 - Python modules: daemon, syslog
 - Shell commands: ifconfig, snmpwalk, nmap, zabbix_sender
 - Rights: it's enough common user rights for daemon running, but you have to allow execution of the nmap command by the sudo utility without password prompt

The application is tested with HP Procurve 2520, HP Procurve 1700 and D-Link DES-3028 under Ubuntu Server 12.04 system. It doesn't support Cisco switches now.
