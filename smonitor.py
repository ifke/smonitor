#!/usr/bin/python
# -*- coding: utf-8 -*-


from __future__ import print_function
import sys
import daemon
from daemon.pidlockfile import PIDLockFile
import tempfile
import time
import re
from syslog import *


import Settings
from Command import Command, CommandError
from Switch import Switch
from AddressDict import AddressDict, normalize_mac, IncorrectMac, Mac


# templates of parameters of used programs
ZABBIX_PARAMS = '--zabbix-server {zabbix_server} --input-file {filename} -vv'
SNMPWALK_PARAMS = '-c {community} -v 2c -Onq -Cc -t 3 {ip} {oid_prefix}'
NMAP_PARAMS = '-sP -sn --exclude {address} -n {address}/{mask}'
# the names of log levels
MSG_NAMES = ['EMERGE', 'ALERT', 'CRITICAL', 'ERROR', 'WARNING', 'NOTICE',
             'INFO', 'DEBUG']
# default settings of smonitor
DEFAULT_SETTINGS = {
    'zabbix_server': '127.0.0.1',
    'community': 'public',
    'mac2ip_enable': 1,
    'addresses_file': '',
    'vendors_file': 'oui.txt',
    'arpscan_only': None,
    'ip2fqdn_enable': 1,
    'show_all_addresses': 1,
    'send2zabbix_interval': 900,
    'loglevel': LOG_WARNING,
    'default_number_of_ports': 48,
    'max_hosts_on_port': 7,
    'ifconfig_cmd': '/sbin/ifconfig',
    'sudo_cmd': '/usr/bin/sudo',
    'nmap_cmd': '/usr/bin/nmap',
    'zabbix_sender_cmd': '/usr/bin/zabbix_sender',
    'snmpwalk_cmd': '/usr/bin/snmpwalk',
    'mac_oid': '.1.3.6.1.2.1.17.4.3.1.1',
    'port_oid': '.1.3.6.1.2.1.17.4.3.1.2',
    'pidfile': '/var/run/smonitor/smonitor.pid',
}

# Regular expressions to parse output of conrrespinding commands
IP = r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})'
MAC = r'(?P<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})'
IFCONFIG_RE = re.compile(r"""(?P<name>\w+)\s+link\s+encap:Ethernet\s+
                             hwaddr\s+{1}\s+inet\s+addr:{0}\s+Bcast:[.0-9]+\s+
                             mask:(?P<mask>[.0-9]+)""".format(IP, MAC),
                         re.I | re.X)

NMAP_RE = re.compile(r'{0}[^\n]*\n[^\n]+\n[^:]+:\s*{1}'.format(IP, MAC),
                     re.I | re.X)


def prepare2log(msg, loglevel, **kargs):
    """
    Prepare message to be send to syslog
    """
    if kargs:
        msg = msg.format(**kargs)
    # replace new line character with triple space
    msg = msg.replace('\n', '   ')
    # remove ascii symbols with code less 32 (syslog doesn't like them)
    msg = ''.join([c for c in msg if ord(c) >= 32])
    # add the name of log level to begin of the message
    return ': '.join((MSG_NAMES[loglevel], msg))


def send2log(msg, loglevel=LOG_INFO, **kargs):
    """
    Send the message msg to syslog
    """
    msg = prepare2log(msg, loglevel, **kargs)
    # carefully send a message to syslog
    try:
        syslog(loglevel, msg)
    except Exception:
        pass


def send2console(msg, loglevel=LOG_INFO, **kargs):
    """
    Print log message to console
    """
    msg = prepare2log(msg, loglevel, **kargs)
    print(msg)


def check_int(value, default, name):
    """
    Check integer parameter of the Settings.py file
    """
    if isinstance(value, str):
        send2log('Convert string "{value}" to integer', **locals())
        try:
            value = int(value)
        except ValueError:
            send2log('Convertation is failed', LOG_ERR, **locals())
            send2log('Set {name} to default {default}',
                     LOG_WARNING, **locals())
            value = default
    if value < 0:
        send2log('{name} must be positive', LOG_ERR, **locals())
        send2log('Set {name} to default {default}', LOG_WARNING, **locals())
        value = default
    return value
        


def check_settings():
    """
    Check a set of variables imported from Settings.py

    If a setting parameter is omitted the function will set it to
    default value. Default values are defined in the DEFAULT_SETTINGS
    list. Besides it verifies list of dictionaries of switch parameters
    and removes incorrect elements.
    """
    send2log('Check the settings')
    settings = dir(Settings)
    # verification of settings variables
    for key, value in DEFAULT_SETTINGS.items():
        if key not in settings:
            setattr(Settings, key, value)
            send2log('No {key} in settings. Set it to default value {value}',
                     **locals())
            continue
        v = Settings.__dict__[key]
        if isinstance(value, int):
            v = check_int(v, value, key)
            setattr(Settings, key, v)
        send2log('The parameter {key} is {v}', **locals())
    # if several interfaces are set, split them into list
    arpscan_only = Settings.arpscan_only
    if arpscan_only is not None and ' ' in arpscan_only:
        setattr(Settings, arpscan_only, arpscan_only.split())
    # selection of correct defined switches
    correct_switches = []
    for n, switch in enumerate(Settings.switches, 1):
        # check necessary parameters of switch
        if 'name' not in switch or 'ip' not in switch:
            what = 'name' if 'name' not in switch else 'ip address'
            send2log('No {what} for switch number {n}. It is ignored', LOG_ERR,
                     **locals())
            continue
        # the name will require for log message
        name = switch['name']
        switch['community'] = switch.get('community', Settings.community)
        default = Settings.default_number_of_ports
        nports = switch.get('nports', default)
        switch['nports'] = check_int(nports, default, 'the number of ports')
        # if we come here, the switch parameters are correct
        correct_switches.append(switch)
    if not correct_switches:
        send2log('No switches to monitor', LOG_CRIT)
        exit(1)
    # keep in Settings.switches list only correct switches
    setattr(Settings, 'switches', correct_switches)


def show_mapping(mapping):
    """
    Return string containing mapping data in the format of this program
    """
    if isinstance(mapping, dict):
        data_list = mapping.items()
    elif isinstance(mapping, (tuple, list)):
        data_list = mapping
    else:
        return ''
    res = []
    for key, value in data_list:
        if isinstance(value, (tuple, list)):
            # stick all elements of tuple or list
            value = ', '.join(value)
            # enclose the result string in brackets
            value = ''.join(('(', value, ')'))
        res.append('->'.join((str(key), str(value))))
    return '; '.join(res)


def get_vendors_list(ouifile):
    """
    Return the mac prefixes to vendors mapping as a dict

    Data are read from the ouifile file downloaded from
    http://standards.ieee.org/develop/regauth/oui/oui.txt
    """
    if not ouifile:
        return None
    res = {}
    send2log('Open file {ouifile} containing vendors list', **locals())
    try:
        with open(ouifile, 'r') as fh:
            for line in fh:
                line = line.strip()
                words = line.split()
                # we need lines of format {prefix}  (hex)   {vendor}
                if len(words) < 3 or words[1] != '(hex)':
                    continue
                try:
                    prefix = normalize_mac(words[0], prefix=True)
                except IncorrectMac:
                    continue
                vendor = ' '.join(words[2:]).title()
                res[prefix] = vendor
        send2log('Data have been read from {ouifile}', **locals())
    except IOError:
        send2log('Can\'t open/read file {ouifile}', LOG_ERR, **locals())
        res = None
    return res


def get_interfaces(ifconfig_cmd):
    """
    Get properties of local network interfaces of the host

    It selects the interfaces with configured ip address and
    save its name, ip and mac addresses, netmask. The parameter
    only_interfaces restrists a set of discovered interfaces.
    """
    cmd_string = ifconfig_cmd.show()
    send2log('Execute command {cmd_string}', LOG_DEBUG, **locals())
    returncode, output = ifconfig_cmd()
    if returncode != 0:
        send2log('Command {cmd_string}: {output}', LOG_ERR, **locals())
        return None

    res = {}
    interface_info = IFCONFIG_RE.findall(output)
    ifaces = ', '.join([iface[0] for iface in interface_info])
    send2log('Found interfaces: {ifaces}', LOG_DEBUG, **locals())
    for name, mac, ip, mask in interface_info:
        # exception is impossible due to regular expression
        mac = normalize_mac(mac)
        # convert netmask from dotted to integer format
        mask = sum([bin(int(x)).count('1') for x in mask.split('.')])
        res[name] = (mac, ip, str(mask))

    return res


def get_arpscan_interfaces(interfaces):
    """
    Return allowed interfaces to scan via arp protocol
    """
    if Settings.arpscan_only is not None:
        res = []
        for iface in interfaces:
            if iface in Settings.arpscan_only:
                res.append(iface)
            else:
                send2log('{iface} is not allowed to scan', **locals())
    else:
        res = interfaces
    return res


def get_addresses_from_file(filename):
    """
    Read from file the mac-to-ip mapping and return it as a dict
    """
    res = {}
    send2log('Open addresses file {filename}', **locals())
    try:
        with open(filename, 'r') as fh:
            for line in fh:
                # remove comment if it exists
                if '#' in line:
                    line = line.split('#', 1)[0]
                line = line.strip()
                if not line:
                    continue
                addr = line.split()
                if len(addr) == 1:
                    res[addr[0]] = None
                elif len(addr) == 2:
                    res[addr[0]] = addr[1]
                elif len(addr) == 3:
                    res[addr[0]] = (addr[1], addr[2])
        send2log('Data have been read from {filename}', **locals())
        res_str = show_mapping(res)
        send2log('Result mapping: {res_str}', LOG_DEBUG, **locals())
    except IOError:
        send2log('Can\'t open file {filename}', LOG_ERR, **locals())
    return res


def arpscan(nmap_cmd, interfaces):
    """
    Scan subnets of local interfaces and return a dict of macs and ips
    """
    res = {}
    for name, addr in interfaces.items():
        cmd_string = nmap_cmd.show(address=addr[1], mask=addr[2])
        send2log('Execute command {cmd_string}', LOG_DEBUG, **locals())
        returncode, output = nmap_cmd(address=addr[1], mask=addr[2])
        if returncode == 0:
            mapping = dict((mac, ip) for ip, mac in NMAP_RE.findall(output))
            mapping_str = show_mapping(mapping)
            send2log('Result mapping: {mapping_str}', LOG_DEBUG, **locals())
            res.update(mapping)
        else:
            send2log('Command {cmd_string}: {output}', LOG_ERR, **locals())
    return res


def send2zabbix(switches, addr_dict, cmd, zabbix_server):
    """
    Send info to zabbix server

    The function generates temp file of format defined in the
    zabbix_line_tmpl and sends it to sender with the zabbix_sender
    command
    """
    zabbix_line_tmpl = '{name} hosts_on_port[{port}] {value}'
    # create a temporary file to write sending data
    with tempfile.NamedTemporaryFile(prefix='smonitor-') as fh:
        send2log('Create temporary file {fh.name} for zabbix data',
                 LOG_DEBUG, **locals())
        send2log('Content of the file:', LOG_DEBUG)
        for switch in switches:
            name = switch.name
            for port, mac_list in enumerate(switch):
                # null port defines mac address of the switch
                if port == 0:
                    continue
                # no device on port
                if not mac_list:
                    value = 'none'
                # too many devices on port
                elif 0 < Settings.max_hosts_on_port < len(mac_list):
                    value = 'another switch'
                else:
                    value = addr_dict.show(mac_list,
                                           Settings.show_all_addresses)
                line = zabbix_line_tmpl.format(**locals())
                send2log(line, LOG_DEBUG)
                print(line, file=fh)
        # write data to the disk before zabbix_sender execution
        fh.flush()
        send2log('Send data to zabbix server {zabbix_server}', **locals())
        cmd_string = cmd.show(zabbix_server=zabbix_server, filename=fh.name)
        send2log('Execute command {cmd_string}', LOG_DEBUG, **locals())
        returncode, output = cmd(zabbix_server=zabbix_server, filename=fh.name)
        level = LOG_DEBUG if returncode == 0 else LOG_ERR
        send2log('Output of zabbix sender: {output}', level, **locals())


def initialize_command(cmd_path, parameters='', use_sudo=False, sudo_path='',
                       required=True):
    """
    Retrun Command object for the command and parameters string
    """
    level = LOG_CRIT if required else LOG_ERR
    if parameters:
        send2log('Initialize {cmd_path} with parameters {parameters}',
                 LOG_DEBUG, **locals())
    else:
        send2log('Initialize {cmd_path} without parameters',
                 LOG_DEBUG, **locals())
    try:
        cmd = Command(cmd_path, parameters, use_sudo, sudo_path)
    except CommandError as err:
        cmd = None
        send2log(str(err), level)
        if required:
            exit(1)
    return cmd


def initialize_switches(snmpwalk_cmd):
    """
    Create Switch objects for each record in the list Settings.switches
    """
    switches = []
    for s in Settings.switches:
        name = s['name']
        ip = s['ip']
        nports = s['nports']
        community = s['community']
        send2log('Initialize switch {name}', **locals())
        send2log('Parameters: ip={ip}, community={community}, nports={nports}',
                 LOG_DEBUG, **locals())
        switch = Switch(name, ip, community, nports)
        switches.append(switch)
    return switches


def snmpwalk(snmpwalk_cmd, community, ip, oid_prefix):
    """
    Run the snmpwalk command and return its result

    The result is a output of the command where each line is split
    into pairs (key, value). The key is an oid without the specified
    oid_prefix. The value corresponds that oid.
    """
    res = []
    cmd_string = snmpwalk_cmd.show(community=community, ip=ip,
                                   oid_prefix=oid_prefix)
    send2log('Execute command {cmd_string}', LOG_DEBUG, **locals())
    rc, output = snmpwalk_cmd(community=community, ip=ip,
                              oid_prefix=oid_prefix)
    if rc == 0:
        for line in output.splitlines():
            if not line.strip():
                continue
            key, value = line.split(' ', 1)
            key = key.strip()
            key = key[len(oid_prefix)+1:]
            value = value.strip('" ')
            res.append((key, value))
        res_str = show_mapping(res)
        send2log('Result mapping: {res_str}', LOG_DEBUG, **locals())
    else:
        send2log('snmpwalk output: {output}', LOG_ERR, **locals())
    return res


def update_switch(switch, snmpwalk_cmd):
    """
    Update port data of the switch object using the snmp requests
    """
    oid2port = {}
    mapping = snmpwalk(snmpwalk_cmd, switch.community, switch.ip,
                       Settings.port_oid)
    for oid, value in mapping:
        try:
            port = int(value)
        except ValueError:
            continue
        oid2port[oid] = port
    oid2mac = {}
    mapping = snmpwalk(snmpwalk_cmd, switch.community, switch.ip,
                       Settings.mac_oid)
    for oid, mac in mapping:
        try:
            mac = normalize_mac(mac)
        except IncorrectMac:
            continue
        oid2mac[oid] = mac
    switch.update(oid2port, oid2mac)


def update_data(addr_dict, switches, nmap_cmd, interfaces, snmpwalk_cmd):
    """
    Update data in switches and addressdict objects
    """
    # arp scanning always is before requests to switches
    if Settings.addresses_file:
        addr_dict.import_from(get_addresses_from_file,
                              Settings.addresses_file)
    if interfaces and nmap_cmd is not None and Settings.mac2ip_enable:
        addr_dict.import_from(arpscan, nmap_cmd, interfaces)
    for switch in switches:
        send2log('Update data of switch {switch.name}', **locals())
        update_switch(switch, snmpwalk_cmd)
        send2log('Switch data: {switch}', LOG_DEBUG, **locals())
        for mac_list in switch:
            addr_dict.import_from(mac_list)
    if Settings.ip2fqdn_enable:
        send2log('Resolve ip addresses to domain names')
        map(Mac.resolve, addr_dict.values())


def main_process():
    """
    The main function of the program
    """
    # initialize necessary commands
    zabbix_sender_cmd = initialize_command(Settings.zabbix_sender_cmd,
                                           ZABBIX_PARAMS, required=True)
    snmpwalk_cmd = initialize_command(Settings.snmpwalk_cmd, SNMPWALK_PARAMS,
                                      required=True)
    ifconfig_cmd = initialize_command(Settings.ifconfig_cmd, required=False)
    nmap_cmd = initialize_command(Settings.nmap_cmd, NMAP_PARAMS,
                                  use_sudo=True, sudo_path=Settings.sudo_cmd,
                                  required=False)
    switches = initialize_switches(snmpwalk_cmd)

    vendors = get_vendors_list(Settings.vendors_file)
    addr_dict = AddressDict(vendors)

    if ifconfig_cmd is not None:
        interfaces = get_interfaces(ifconfig_cmd)
        if interfaces:
            for iface in interfaces.values():
                addr_dict.add(mac=iface[0], ip=iface[1])
        arpscan_only = get_arpscan_interfaces(interfaces)
    update_data(addr_dict, switches, nmap_cmd, arpscan_only, snmpwalk_cmd)
    send2zabbix(switches, addr_dict, zabbix_sender_cmd, Settings.zabbix_server)

    timer = time.time()
    send2log('Set the timer to {timer}', LOG_DEBUG, **locals())
    while True:
        current_time = time.time()

        if (current_time - timer) > Settings.send2zabbix_interval:
            update_data(addr_dict, switches, nmap_cmd, interfaces,
                        snmpwalk_cmd)
            send2zabbix(switches, addr_dict, zabbix_sender_cmd,
                        Settings.zabbix_server)
            send2log('Increase timer value from {timer} to {current_time}',
                     LOG_DEBUG, **locals())
            timer = current_time
        time.sleep(10)


if len(sys.argv) > 1 and sys.argv[1] == '--debug':
    # in debug mode the program doesn't daemonize and prints all log
    # messages on console
    send2log = send2console
    check_settings()
    main_process()
else:
    # normal progrm start
    # initialize the log system
    openlog(ident='smonitor', logoption=LOG_PID, facility=LOG_DAEMON)
    if 'loglevel' not in dir(Settings):
        setlogmask(LOG_UPTO(DEFAULT_SETTINGS['loglevel']))
    elif Settings.loglevel < 0 or Settings.loglevel > 7:
        setlogmask(LOG_UPTO(DEFAULT_SETTINGS['loglevel']))
        send2log('Log level should be from 0 to 7', LOG_WARNING)
    else:
        setlogmask(LOG_UPTO(Settings.loglevel))

    # check settings imported from Settings.py
    check_settings()

    # start the daemon process
    with daemon.DaemonContext(pidfile=PIDLockFile(Settings.pidfile)):
        send2log('Start daemon', LOG_NOTICE)
        try:
            main_process()
        finally:
            send2log('Stop daemon', LOG_NOTICE)
            closelog()
