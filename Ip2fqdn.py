# -*- coding: utf-8 -*-


from __future__ import print_function
import socket


class Ip2fqdn(dict):
    """
    The object stores the ip-to-fqdn mapping
    """
    def __init__(self, ip_list):
        super(Ip2fqdn, self).__init__()
        self.update(ip_list)

    def __repr__(self):
        pairs_generator = ('->'.join(pair) for pair in self.items())
        return ' '.join(pairs_generator)

    def update(self, ip_list):
        self.clear()
        for ip in ip_list:
            try:
                fqdn = socket.gethostbyaddr(ip)[0]
                self[ip] = fqdn
            except socket.herror:
                pass
