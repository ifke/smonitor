# -*- coding: utf-8 -*-


from __future__ import print_function
import re


# Regular expressions to parse output of conrrespinding commands
IFCONFIG_RE = re.compile(r"""(?P<ifname>\w+)\s+link\s+encap:Ethernet\s+
                             hwaddr\s+(?P<ifmac>[:0-9a-f]+)\s+inet\s+
                             addr:(?P<ifip>[.0-9]+)\s+Bcast:[.0-9]+\s+
                             mask:(?P<mask>[.0-9]+)""",
                         re.I | re.X)
NMAP_RE = re.compile(r"""(?P<ip>(?:\d{1,3}\.){3}\d{1,3})[^:]+:\s+
                         (?P<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})""",
                     re.I | re.X)


def normalize_mac(mac):
    """
    Return mac address in standard form

    Standard form assumes all letters in address are lowercase and
    colons separate each byte of address
    """
    result = mac.lower()
    if len(result) == 12:
        # no separators in mac address
        result = ':'.join([result[i:i+2] for i in range(0, 12, 2)]) 
    else:
        result = result.replace(' ', ':')
        result = result.replace('-', ':')
    return result


class Mac2ip(dict):
    """
    The object stores the mac-to-ip mapping

    It is used as a common dictionary: keys are mac addresses of
    hosts, values - their ip addresses. The mapping is constructed by
    the nmap command which scans network interfaces of local host.
    A list of interfaces is taken from output of the ifconfig
    command. You can restrict the list by the only_interfaces parameter.
    """
    def __init__(self, ifconfig_cmd, nmap_cmd, only_interfaces=[],
                 initial_mapping={}):
        super(Mac2ip, self).__init__()
        self.ifconfig_cmd = ifconfig_cmd
        self.nmap_cmd = nmap_cmd
        self.initial_mapping = initial_mapping
        self.interface_discover(only_interfaces)
        self.update()

    def __repr__(self):
        pairs_generator = ('->'.join(pair) for pair in self.items())
        return ' '.join(pairs_generator)

    def interface_discover(self, only_interfaces):
        """
        Get a list of local network interfaces of the host

        It selects the interfaces with configured ip address and
        save its name, ip and mac addresses, netmask. The parameter
        only_interfaces restrists a set of discovered interfaces.
        """
        result = []
        returncode, output = self.ifconfig_cmd()
        if returncode != 0:
            msg = 'Can\'t run ifconfig: {output}'.format(**locals())
            raise InterfaceDiscoverError(msg)

        interface_info = IFCONFIG_RE.findall(output)
        self.interfaces = []
        for name, mac, ip, mask in interface_info:
            if only_interfaces and name not in only_interfaces:
                continue
            result.append(name)
            mac = normalize_mac(mac)
            self[mac] = ip
            # convert netmask from dotted to integer format
            mask = sum([bin(int(x)).count('1') for x in mask.split('.')])
            self.interfaces.append((name, mac, ip, str(mask)))

    def scanning_interfaces(self):
        """
        Return a string of names of network interfaces used for arp scan
        """
        if self.interfaces:
            return ', '.join([iface[0] for iface in self.interfaces])
        else:
            return 'none'

    def update(self):
        """
        Update the mac-to-ip mapping with the nmap command

        The function do arp scanning of each known network interfaces.
        It returns a list of errors that appear during scanning.
        """
        self.clear()
        for mac, ip in self.initial_mapping.items():
            self[mac] = ip
        errors = []
        for name, mac, ip, mask in self.interfaces:
            self[mac] = ip
            returncode, output = self.nmap_cmd(address=ip, mask=mask)
            if returncode != 0:
                msg = 'The nmap error on {name}: {output}'
                errors.append(msg.format(**locals()))
                continue
            for host_ip, host_mac in NMAP_RE.findall(output):
                host_mac = normalize_mac(host_mac)
                self[host_mac] = host_ip
        return errors
