
import ipaddress
import os
from toolkitTCU.network_module.core.config import REPORT_FOLDER
import re
import socket

def validate_target(target):
    try:
        if "-" in target:
            start_ip, end_ip = target.split("-")
            ipaddress.ip_address(start_ip.strip())
            ipaddress.ip_address(end_ip.strip())
            return True

        ipaddress.ip_network(
            target,
            strict=False
        )
        return True
    except ValueError:
        return False

def expand_ip_range(target):
    if "-" in target:
        start_ip, end_ip = target.split("-")
        start = ipaddress.ip_address(
            start_ip.strip()
        )
        end = ipaddress.ip_address(
            end_ip.strip()
        )
        ips = []

        for ip_int in range(
            int(start),
            int(end) + 1
        ):
            ips.append(str(
                ipaddress.ip_address(ip_int)
            ))
        return " ".join(ips)
    return target

def create_report_folder():
    if not os.path.exists(REPORT_FOLDER):
        os.makedirs(REPORT_FOLDER)

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def reverse_dns_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(
            ip
        ).is_private
    except ValueError:
        return False

def is_valid_domain(domain):
    if "." not in domain:
        return False
    pattern = (
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    return re.match(
        pattern,
        domain
    ) is not None
