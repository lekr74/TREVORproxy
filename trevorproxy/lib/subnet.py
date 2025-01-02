import logging
import ipaddress
import threading
from .errors import *
import subprocess as sp
from .cyclic import ipgen
from .util import autodetect_address_pool, autodetect_interface, sudo_run

log = logging.getLogger("trevorproxy.interface")


class SubnetProxy:
    def __init__(self, subnets=None, interface=None, version=6, pool_netmask=16, socks_username=None, socks_password=None):
        self.lock = threading.Lock()
        self.socks_username = socks_username
        self.socks_password = socks_password
        self.subnets = subnets or [] # Handle empty subnet list

        # ... (rest of the __init__ method remains the same, except subnet is now a list) ...

        self.ipgens = [ipgen(subnet) for subnet in self.subnets] # Create generators for each subnet

    def start(self):
        for subnet in self.subnets:
            cmd = [
                "ip",
                "route",
                "add",
                "local",
                str(subnet),
                "dev",
                str(self.interface),
            ]
            sudo_run(cmd)

    def stop(self):
        for subnet in self.subnets: # Iterate through subnets to remove routes
            cmd = [
                "ip",
                "route",
                "del",
                "local",
                str(subnet),
                "dev",
                str(self.interface),
            ]
            sudo_run(cmd)
