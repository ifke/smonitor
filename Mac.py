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
    def __init__(self, mac, ip=None, vendors=None):
        super(Mac, self).__init__()
        self.mac = normalize_mac(mac)
        self.ip = ip
        if vendors:
            self.vendor = vendors.get(self.mac[:8], 'Unknown')
        else:
            self.vendor = None

    def __repr__(self):
        return self.mac
