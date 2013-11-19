# -*- coding: utf-8 -*-


from __future__ import print_function


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
    def __init__(self, mac, ip=None, hostname=None, vendors=None):
        # mac must already be in normalized form 
        super(Mac, self).__init__()
        self.mac = mac
        self.ip = ip
        self.hostname = hostname
        if vendors:
            self.vendor = vendors.get(mac[:8], 'Unknown')
        else:
            self.vendor = None

    def __repr__(self):
        output = [self.mac]
        if self.vendor:
            output.extend(['(', self.vendor, ')'])
        if self.ip:
            output.extend(['->', self.ip])
        if self.hostname:
            output.extend(['->', self.hostname])
        return ''.join(output)


class AddressDict(dict):
    """
    Store mix of mac addresses and network hosts
    """
    def __init__(self, vendors=None):
        super(AddressDict, self).__init__()
        self.vendors = vendors
    
    def __repr__(self):
        return '; '.join([str(mac) for mac in self.values()])

    def update_address(self, mac, ip=None, hostname=None):
        """
        Update exist address record if it's necessary

        exit_code is a bit mask:
        exit_code & 1 == 1 if new object has been created
        (here it's always null)
        exit_code & 2 == 1 if ip address is updated
        exit_code & 4 == 1 if hostname is updated
        """
        exit_code = 0
        if ip is not None and ip != self[mac].ip:
            self[mac].ip = ip
            exit_code |= 2
        if hostname is not None and hostname != self[mac].hostname:
            self[mac].hostname = hostname
            exit_code |= 4
        return exit_code

    def add(self, mac, ip=None, hostname=None):
        """
        Add mac address into the macs

        The function returns the same bit mask as in update_address.
        Return value equaling one is possible here
        """
        # more likelihood at first
        if mac in self:
            return self.update_address(mac, ip, hostname)
        original_mac = mac
        mac = normalize_mac(mac)
        if mac != original_mac and mac in self:
            return self.update_address(mac, ip, hostname)
        self[mac] = Mac(mac, ip, hostname, self.vendors)
        return 1
