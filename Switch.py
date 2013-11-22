# -*- coding: utf-8 -*-


from __future__ import print_function


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
        self.nports = nports

    def __repr__(self):
        """
        Return the port-to-mac mapping in compact format
        """
        port_list = []
        for port, mac_set in enumerate(self[1:], 1):
            if mac_set:
                mac_list = ' '.join(mac_set)
                port_list.append('{port} -> {mac_list}'.format(**locals()))
        return '; '.join(port_list)

    def update(self, oid2port, oid2mac):
        """
        Rebuild the port-to-mac mapping
        """
        map(set.clear, self)
        for oid, port in oid2port.items():
            if oid in oid2mac and 0 <= port <= self.nports:
                mac = oid2mac[oid]
                self[port].add(mac)
        # next(iter(set(...)), '') is a trick to get random element
        # of the set
        # there is the only element in self[0] - mac of the switch
        # the blank string helps to avoid exception in case of empty set
        self.mac = next(iter(self[0]), '')
