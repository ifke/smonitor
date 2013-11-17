# -*- coding: utf-8 -*-


from __future__ import print_function


class IncorrectMac(Exception):
    """
    Raise it when the incorrect mac address is found
    """
    pass


def normalize_mac(mac):
    """
    Return mac address in standard form

    Standard form assumes all letters in address are lowercase and
    colons separate each byte of address
    """
    result = mac.lower()
    if len(result) == 12:
        # there is no separators in mac address
        result = ':'.join([result[i:i+2] for i in range(0, 12, 2)])
    elif len(result) == 17:
        # replace other types of separators
        result = result.replace(' ', ':')
        result = result.replace('-', ':')
    else:
        err = 'incorrect length of mac address {mac}'
        raise IncorrectMac(err.format(**locals()))

    # Validation of format of the result
    try:
        check = [x for x in result.split(':') if 0 <= int(x, 16) <= 255]
        if len(check) != 6:
            raise ValueError
    except ValueError:
        err = 'incorrect format of mac address {mac}'
        raise IncorrectMac(err.format(**locals()))

    return result


class Mac(object):
    """
    Store all information about a mac address
    """
    def __init__(self, mac, ip=None, vendors=None):
        super(Mac, self).__init__()
        self.mac = normalize_mac(mac)
        self.ip = ip
        self.vendor = vendors(mac[:8], None) if vendors else None

    def __repr__(self):
        return self.mac
