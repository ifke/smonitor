# Sample settings file of the smonitor daemon
# Here the python syntax is used. Strings values are eclosed in quotes
# or apostrophes, intergers - not. The switches parameter is a list of
# dictionaries.

switches = [
    {
        'name': 'procurve2520.forb.local',
        'ip': '172.17.5.221',
        'nports': 28,
    },
]
zabbix_server = '127.0.0.1'
community = 'private'
mac2ip_enable = 1
ip2fqdn_enable = 1
show_all_addresses = 1

send2zabbix_interval = 60

loglevel = 7

default_number_of_ports = 48
max_hosts_on_port = 7

ifconfig_cmd = '/sbin/ifconfig'
sudo_cmd = '/usr/bin/sudo'
nmap_cmd = '/usr/bin/nmap'
zabbix_sender_cmd = '/usr/bin/zabbix_sender'
snmpwalk_cmd = '/usr/bin/snmpwalk'

pidfile = '/var/run/smonitor/smonitor.pid'

mac_oid = '.1.3.6.1.2.1.17.4.3.1.1'
port_oid = '.1.3.6.1.2.1.17.4.3.1.2'
