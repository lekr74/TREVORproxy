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

        pool_netmask = pool_netmask if version == 6 else 128 - pool_netmask

        # if no subnet is requested
        if not self.subnets:
            log.info(f"No subnet specified, detecting IPv{version} interfaces.")
            self.subnets = autodetect_address_pool(version=version)
            if not self.subnets:
                raise SubnetProxyError("Failed to detect any IPv6 subnets")
            log.debug(f"Successfully detected subnets: {self.subnets}")
        else:
            # Convert single subnet string to a list for consistency
            self.subnets = [ipaddress.ip_network(subnet, strict=False) for subnet in self.subnets]

        # if no interface is requested
        self.interface = interface
        if self.interface is None:
            log.info(f"No interface specified, detecting.")
            self.interface = autodetect_interface(version=version)
            if not self.interface:
                raise SubnetProxyError("Failed to detect interface")
            log.debug(f"Successfully detected interface: {self.interface}")

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
