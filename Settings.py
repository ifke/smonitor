# Sample settings file of the smonitor daemon
# Here the python syntax is used. Strings values are eclosed in quotes
# or apostrophes, intergers - not. The switches parameter is a list of
# dictionaries.

switches = [
    {
        'name': 'switch1.example.local',
        'ip': '192.168.0.254',
        'nports': 28,
    },
    {
        'name': 'switch2.example.local',
        'ip': '192.168.0.253',
        'nports': 24,
    },
]
zabbix_server = '127.0.0.1'
community = 'public'
mac2ip_enable = 1
ip2fqdn_enable = 1

send2zabbix_interval = 90

loglevel = 5
