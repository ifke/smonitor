# -*- coding: utf-8 -*-


from __future__ import print_function
import socket


class IncorrectMac(Exception):
    """
    Raise it when the incorrect mac address is found
    """
    pass


def normalize_mac(mac, prefix=False):
    """
    Return mac address or mac prefix in standard form

    Standard form assumes all letters in address are lowercase and
    colons separate each byte of address
    """
    res = mac.lower()
    length, short_length, nbytes = (8, 6, 3) if prefix else (17, 12, 6)
    if len(res) == short_length:
        # there is no separators in mac address
        res = ':'.join([res[i:i+2] for i in range(0, len(res), 2)])
    elif len(res) == length:
        # replace other types of separators
        res = res.replace(' ', ':')
        res = res.replace('-', ':')
    else:
        err = 'incorrect length of mac address {mac}'
        raise IncorrectMac(err.format(**locals()))

    # Validation of format of the res
    try:
        check = [x for x in res.split(':') if 0 <= int(x, 16) <= 255]
        if len(check) != nbytes:
            raise ValueError
    except ValueError:
        err = 'incorrect format of mac address {mac}'
        raise IncorrectMac(err.format(**locals()))

    return res


class Mac(object):
    """
    Store all information about a mac address
    """
    def __init__(self, mac, ip=None, name=None, vendors=None):
        super(Mac, self).__init__()
        # mac must already be in normalized form 
        self.mac = mac
        self.ip = ip
        self.__name = name
        self.fqdn = None
        if vendors:
            self.vendor = vendors.get(mac[:8], 'Unknown')
        else:
            self.vendor = None

    def __repr__(self):
        return self.show()

    @property
    def name(self):
        return self.__name or self.fqdn

    @name.setter
    def name(self, name):
        self.__name = name

    def show(self, all_addresses=True):
        """
        Show object data in human-readable format
        """
        if all_addresses:
            if self.vendor:
                mac_info = ', '.join((self.mac, self.vendor))
            else:
                mac_info = self.mac
            name = self.name
            ip = self.ip
            if self.name:
                return '{name} ({ip}, {mac_info})'.format(**locals())
            elif self.ip:
                return '{ip} ({mac_info})'.format(**locals())

        if self.vendor:
            mac_info = ''.join((self.mac, ' (', self.vendor, ')'))
        else:
            mac_info = self.mac
        return self.name or self.ip or mac_info


class AddressDict(dict):
    """
    Store mix of mac addresses and network hosts
    """
    def __init__(self, vendors=None):
        super(AddressDict, self).__init__()
        self.vendors = vendors
    
    def __repr__(self):
        return '; '.join([str(addr) for addr in self.values()])

    def contains(self, mac):
        """
        Consider any string as mac and check it containing in the macs list

        If the parameter is incorrect, there is no exception and the
        function returns False.
        """
        try:
            return normalize_mac(mac) in self
        except IncorrectMac:
            return False

    def update_address(self, mac, ip=None, name=None):
        """
        Update exist address record if it's necessary

        exit_code is a bit mask:
        exit_code & 1 == 1 if new object has been created
        (here it's always null)
        exit_code & 2 == 1 if ip address is updated
        exit_code & 4 == 1 if name is updated
        """
        exit_code = 0
        if ip is not None and ip != self[mac].ip:
            self[mac].ip = ip
            exit_code |= 2
        if name is not None and name != self[mac].name:
            self[mac].name = name
            exit_code |= 4
        return exit_code

    def add(self, mac, ip=None, name=None):
        """
        Add mac address into the macs

        The function returns the same bit mask as in update_address.
        Return value equaling one is possible here
        """
        # more likelihood at first
        if mac in self:
            return self.update_address(mac, ip, name)
        original_mac = mac
        mac = normalize_mac(mac)
        if mac != original_mac and mac in self:
            return self.update_address(mac, ip, name)
        try:
            self[mac] = Mac(mac, ip, name, self.vendors)
        except IncorrectMac:
            return -1
        return 1

    def update(self, addr_dict, only_add_new=False):
        """
        Update addresses from a dictionary

        The keys of the dictionary are mac addresses, the values contain
        ip address or a pair of ip and hostname.
        """
        for mac, addr in addr_dict.items():
            if only_add_new and self.contains(mac):
                continue
            if addr is None or isinstance(addr, str):
                self.add(mac, ip=addr)
            elif isinstance(addr, (tuple, list)):
                if len(addr) == 1:
                    self.add(mac, ip=addr[0])
                else:
                    self.add(mac, ip=addr[0], name=addr[1])

    def resolve_ips(self):
        """
        Try to resolve ip addresses to fqdns
        """
        for addr in {self[x] for x in self if self[x].ip}:
            try:
                addr.fqdn = socket.gethostbyaddr(addr.ip)[0]
            except socket.herror:
                pass
