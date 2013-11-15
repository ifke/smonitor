# -*- coding: utf-8 -*-


from __future__ import print_function


class SwitchError(Exception):
    """
    Excetion for switch communication
    """
    pass


class Switch(list):
    """
    Store a mapping of ports to sets of mac addresses connected hosts
    """
    def __init__(self, name, ip, community, nports, snmpwalk_cmd,
                 port_oid, mac_oid):
        super(Switch, self).__init__([set() for i in range(nports+1)])
        self.name = name
        self.ip = ip                # IP address of switch
        self.community = community
        self.snmpwalk_cmd = snmpwalk_cmd
        self.port_oid = port_oid
        self.mac_oid = mac_oid
        self.nports = nports
        self.oid2port = {}
        self.oid2mac = {}
        self.update_oid2port()
        self.update_oid2mac()
        self.update()
        # next(iter(set(...)), '') is a trick to get random element
        # of the set
        # there is the only element in self[0] - mac of the switch
        # the blank string helps to avoid exception in case of empty set
        self.mac = next(iter(self[0]), '')

    def snmpwalk(self, oid_prefix):
        """
        Run the snmpwalk command and return its result
        
        The result is a output of the command where each line is split
        into pairs (key, value). The key is an oid without the specified
        oid_prefix. The value corresponds that oid.
        """
        returncode, output = self.snmpwalk_cmd(community=self.community,
                                               ip=self.ip,
                                               oid_prefix=oid_prefix)
        if returncode != 0:
            raise SwitchError(output) 

        result = []
        for line in output.split('\n'):
            if not line.strip():
                continue
            key, value = line.split(' ', 1)
            key = key.strip()
            key = key[len(oid_prefix)+1:]
            value = value.strip()
            result.append((key, value))
        return result

    def __repr__(self):
        """
        Return the port-to-mac mapping in compact format
        """
        port_list = []
        for port, mac_set in enumerate(self[1:], 1):
            if mac_set:
                mac_list = ' '.join(mac_set)  
                port_list.append('{port} -> {mac_list}'.format(**locals()))
        return ', '.join(port_list)

    def update_oid2port(self):    
        """
        Update the mapping of OID sufficies to port numbers
        """
        self.oid2port.clear()
        for oid, value in self.snmpwalk(self.port_oid):
            try:
                port = int(value)
            except ValueError:
                continue
            self.oid2port[oid] = port

    def update_oid2mac(self):    
        """
        Update the mapping of OID sufficies to sets of mac addresses
        """
        self.oid2mac.clear()
        for oid, value in self.snmpwalk(self.mac_oid):
            mac = value.strip('" ')
            mac = mac.replace(' ', ':')
            mac = mac.lower()
            if mac != '00:00:00:00:00:00':
                self.oid2mac[oid] = mac

    def update(self):
        """
        Rebuild the port-to-mac mapping
        """
        self.update_oid2port()
        self.update_oid2mac()
        map(set.clear, self)
        for oid, port in self.oid2port.items():
            if oid in self.oid2mac and 0 <= port <= self.nports:
                mac = self.oid2mac[oid]
                self[port].add(mac)
