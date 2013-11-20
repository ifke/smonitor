#!/usr/bin/python
# -*- coding: utf-8 -*-


from __future__ import print_function
import sys
import daemon
from daemon.pidlockfile import PIDLockFile
import tempfile
import time
from syslog import *


import Settings
from Command import Command, CommandError
from Switch import Switch, SwitchError
from Mac2ip import Mac2ip
from AddressDict import AddressDict, normalize_mac, IncorrectMac
from Ip2fqdn import Ip2fqdn


# templates of parameters of used programs
ZABBIX_PARAMS = '--zabbix-server {zabbix_server} --input-file {filename} -vv'
SNMPWALK_PARAMS = '-c {community} -v 2c -Onq -Cc -t 3 {ip} {oid_prefix}'
NMAP_PARAMS = '-sP -sn -n {address}/{mask}'
# the names of log levels
MSG_NAMES = ['EMERGE', 'ALERT', 'CRITICAL', 'ERROR', 'WARNING', 'NOTICE',
             'INFO', 'DEBUG']
# default settings of smonitor
DEFAULT_SETTINGS = {
    'zabbix_server': '127.0.0.1',
    'community': 'public',
    'mac2ip_enable': 1,
    'mac2ip_file': '',
    'arpscan_interfaces': [],
    'ip2fqdn_enable': 1,
    'show_all_addresses': 0,
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
    'switches': [],
}


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
        else:
            value = Settings.__dict__[key]
            send2log('The parameter {key} is {value}', **locals())
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
        # check optional parameters
        default_community = Settings.community
        if 'community' not in switch:
            send2log('Community is not defined for switch {name}', **locals())
            send2log('It will be use default value {default_community}',
                     **locals())
            switch['community'] = default_community
        default_number_of_ports = Settings.default_number_of_ports
        if 'nports' not in switch:
            send2log('The number of ports is not defined for switch {name}',
                     **locals())
            send2log('It will be use default value {default_number_of_ports}',
                     **locals())
            switch['nports'] = default_number_of_ports
        elif isinstance(switch['nports'], str):
            nports = switch['nports']
            send2log('The number of ports is defined as a string "{nports}"',
                     LOG_WARNING, **locals())
            send2log('Try to convert it to an integer value', LOG_WARNING)
            try:
                switch['nports'] = int(nports)
            except ValueError:
                send2log('Converting is unsuccessful', LOG_WARNING)
                send2log('The parameter is set to {default_number_of_ports}',
                         LOG_WARNING, **locals())
                switch['nports'] = default_number_of_ports
        # if we come here, the switch parameters are correct
        correct_switches.append(switch)
    # keep in Settings.switches list only correct switches
    setattr(Settings, 'switches', correct_switches)


def get_vendors_list(ouifile):
    """
    Return the mac prefixes to vendors mapping as a dict

    Data are read from the ouifile file downloaded from
    http://standards.ieee.org/develop/regauth/oui/oui.txt
    """
    result = {}
    send2log('Open file {filename} containing vendors list', **locals())
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
                result[prefix] = vendor
        send2log('Close file {filename}', **locals())
    except IOError:
        send2log('Can\'t open/read file {filename}', LOG_ERR, **locals())
        result = None
    return result


def get_port_value(mac_list, mac2ip, ip2fqdn, show_all_addresses=False):
    """
    Return string value for the list of mac addresses

    This value will be send to zabbix server.
    """
    # no device on port
    if not mac_list:
        return 'none'
    # too many devices on port
    elif 0 < Settings.max_hosts_on_port < len(mac_list):
        return 'another switch'
    # split hosts depending on a type of address we can get
    fqdns, ips, macs = ([], [], [])
    # try to convert every mac address in the list into ip address
    # and then into full qualified domain name
    for mac in mac_list:
        if mac2ip is not None and mac in mac2ip:
            ip = mac2ip[mac]
            if ip2fqdn is not None and ip in ip2fqdn:
                fqdn = ip2fqdn[ip]
                if show_all_addresses:
                    record = '{fqdn} ({ip} {mac})'.format(**locals())
                else:
                    record = fqdn
                fqdns.append(record)
            else:
                if show_all_addresses:
                    record = '{ip} ({mac})'.format(**locals())
                else:
                    record = ip
                ips.append(record)
        else:
            macs.append(mac)

    return ', '.join(sorted(fqdns) + sorted(ips) + sorted(macs))


def send2zabbix(switches, mac2ip, ip2fqdn, cmd, zabbix_server):
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
                value = get_port_value(mac_list, mac2ip, ip2fqdn,
                                       Settings.show_all_addresses)
                line = zabbix_line_tmpl.format(**locals())
                send2log(line, LOG_DEBUG)
                print(line, file=fh)
        # write data to the disk before zabbix_sender execution
        fh.flush()
        send2log('Send data to zabbix server {zabbix_server}', **locals())
        cmd_string = cmd.show(zabbix_server=zabbix_server, filename=fh.name)
        send2log('The command is {cmd_string}', LOG_DEBUG, **locals())
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


def get_addresses_from_file(filename):
    """
    Read from file the mac-to-ip mapping and return it as a dict
    """
    result = {}
    send2log('Open file {filename}', **locals())
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
                    result[addr[0]] = None
                elif len(addr) == 2:
                    result[addr[0]] = addr[1]
                elif len(addr) == 3:
                    result[addr[0]] = (addr[1], addr[2])
        send2log('Close file {filename}', **locals())
        send2log('Read from file: {result}', LOG_DEBUG, **locals())
    except IOError:
        send2log('Can\'t open file {filename}', LOG_ERR, **locals())
    return result


def initialize_mac2ip(ifconfig_cmd, nmap_cmd):
    """
    Create Mac2ip object for the mac-to-ip mapping
    """
    if Settings.mac2ip_enable:
        send2log('Initialize the mac-to-ip mapping')
        if Settings.mac2ip_file:
            initial_mapping = get_mac2ip_from_file(Settings.mac2ip_file)
        else:
            initial_mapping = {}

        if Settings.arpscan_interfaces == 'all':
            Settings.arpscan_interfaces = []

        mapping = Mac2ip(ifconfig_cmd, nmap_cmd,
                         only_interfaces=Settings.arpscan_interfaces,
                         initial_mapping=initial_mapping)
        ifs = str(mapping.scanning_interfaces())
        send2log('Found interfaces for arp scannig: {ifs}', **locals())
        send2log('The mapping is {mapping}', LOG_DEBUG, **locals())
    else:
        send2log('The mac-to-ip mapping is disabled')
        mapping = None
    return mapping


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
        send2log('Initialize switch named {name}', **locals())
        send2log('Parameters: ip={ip}, community={community}, nports={nports}',
                 LOG_DEBUG, **locals())
        try:
            switch = Switch(name, ip, community, nports, snmpwalk_cmd,
                            Settings.port_oid, Settings.mac_oid)
            switches.append(switch)
        except SwitchError as err:
            send2log('Switch error: {err}', LOG_ERR, **locals())
            continue
        send2log('The mapping of switch {name} ({ip}) is {switch}',
                 LOG_DEBUG, **locals())
    if not switches:
        send2log('No switch to monitor', LOG_CRIT)
        exit(5)
    return switches


def initialize_ip2fqdn(ip_list):
    """
    Create the Ip2fqdn object for the ip-to-fqdn mapping
    """
    if Settings.ip2fqdn_enable:
        send2log('Initialize the ip-to-fqdn mapping')
        mapping = Ip2fqdn(ip_list) if Settings.ip2fqdn_enable else None
        send2log('The mapping is {mapping}'.format(**locals()), LOG_DEBUG)
    else:
        send2log('The ip-to-fqdn mapping is disabled')
        mapping = None
    return mapping


def update_mappings(switches, mac2ip, ip2fqdn):
    """
    Update all used mappings
    """
    if mac2ip is not None:
        send2log('Update the mac-to-ip mapping')
        errors = mac2ip.update()
        for err in errors:
            send2log(err, LOG_ERR)
        send2log('The mac-to-ip mapping is {mac2ip}', LOG_DEBUG, **locals())

    for switch in switches:
        send2log('Update the port-to-mac mapping of switch {switch.name}',
                 **locals())
        try:
            switch.update()
            send2log('The mapping is {switch}', LOG_DEBUG, **locals())
        except SwitchError as err:
            send2log('Switch snmp error: {err}', LOG_ERR, **locals())

    if ip2fqdn is not None:
        send2log('Update the ip-to-fqdn mapping')
        ip2fqdn.update(mac2ip.values())
        send2log('The ip-to-fqdn mapping is {ip2fqdn}', LOG_DEBUG, **locals())


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

    # initialize mappings and switches
    # arp scanning always is before requests to switches
    if ifconfig_cmd is None or nmap_cmd is None:
        send2log('Force disable mac-to-ip and ip-to-fqdn mappings', LOG_ERR)
        mac2ip = None
    else:
        mac2ip = initialize_mac2ip(ifconfig_cmd, nmap_cmd)
    switches = initialize_switches(snmpwalk_cmd)
    if mac2ip is not None:
        ip2fqdn = initialize_ip2fqdn(mac2ip.values())
    else:
        ip2fqdn = None
    send2zabbix(switches, mac2ip, ip2fqdn, zabbix_sender_cmd,
                Settings.zabbix_server)

    timer = time.time()
    send2log('Set the timer to {timer}', LOG_DEBUG, **locals())
    while True:
        current_time = time.time()

        if (current_time - timer) > Settings.send2zabbix_interval:
            update_mappings(switches, mac2ip, ip2fqdn)
            send2zabbix(switches, mac2ip, ip2fqdn, zabbix_sender_cmd,
                        Settings.zabbix_server)
            send2log('Set the timer from {timer} to {current_time}',
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
