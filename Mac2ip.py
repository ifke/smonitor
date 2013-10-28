# -*- coding: utf-8 -*-


from __future__ import print_function
import re


# Regular expressions to parse output of conrrespinding commands
IFCONFIG_RE = re.compile(r'(?P<ifname>\w+)\s+Link encap:Ethernet\s+HWaddr\s+(?P<ifmac>[:0-9a-f]+)\s+inet addr:(?P<ifip>[.0-9]+)', re.I)
ARPSCAN_RE = re.compile(r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})', re.I)


class InterfaceDiscoverError(Exception):
    """
    Excetion for network interface discovering
    """
    pass


class Mac2ip(dict):
    """
    The object stores the mac-to-ip mapping

    It is used as a common dictionary: keys are the mac addresses of hosts, values - their ip addresses.
    The mapping is constructed by the arp-scan command which scans local network interfaces of the system.
    A list of network interfaces is taken from output of the ifconfig command.
    You can restrict the list by means of the only_interfaces parameter.
    """
    def __init__(self, ifconfig_cmd, arpscan_cmd, only_interfaces = []):
        super(Mac2ip, self).__init__()
        self.ifconfig_cmd = ifconfig_cmd
        self.arpscan_cmd = arpscan_cmd
        self.interface_discover(only_interfaces)
        self.update()

    def __repr__(self):
        pairs_generator = ('->'.join(pair) for pair in self.items())
        return ' '.join(pairs_generator)

    def interface_discover(self, only_interfaces):
        """
        Get a list of local network interfaces of the host

        It's selected the interfaces with configured ip address.
        Corresponding mac and ip addresses of each interfaces is stored in the mapping
        Parameter only_interfaces restrists a set of discovered interfaces
        """
        result = []
        returncode, output = self.ifconfig_cmd()
        if returncode != 0:
            raise InterfaceDiscoverError('Can\'t run ifconfig: {output}'.format(**locals()))
    
        interface_info = IFCONFIG_RE.findall(output)
        if only_interfaces:
            interface_info = [iface for iface in interface_info if iface[0] in only_interfaces]
        for ifname, mac, ip in interface_info:
            result.append(ifname)
            mac = mac.lower()
            self[mac] = ip
        self.interfaces = interface_info
        if not interface_info:
            raise InterfaceDiscoverError('No valid interfaces for arp scanning')
            

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
        Update the mac-to-ip mapping with the arp-scan command

        The function do arp scanning of each known network interfaces.
        It returns a list of errors that appear during scanning.
        """
        self.clear()
        errors = []
        for interface, iface_mac, iface_ip in self.interfaces:
            self[iface_mac] = iface_ip
            returncode, output = self.arpscan_cmd(interface=interface)
            if returncode != 0:
                errors.append('Arp scan error on {interface}: {output}'.format(**locals()))
                continue
            for ip, mac in ARPSCAN_RE.findall(output):
                mac = mac.lower()
                self[mac] = ip
        return errors
