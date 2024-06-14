#!/usr/local/bin/python
#-*- coding: utf-8 -*-

VERSION: str = '0.0.1'
"""
bigip-cookie-decoder - Extracts the internal IP address and port coded into a BIGip WAF cookie
Copyright © 2024 Daniel Hoffman (Aka. Z)
GitHub: Zeta-0x00

@Author Daniel Hofman (Aka. Z)
@License: GPL v3
@version {}
""".format(VERSION)

import sys
from termcolor import colored
from typing import Callable


if len(sys.argv) != 2:
    print(f"[{colored('X','red')}] Error:\n\t{colored('Required just 1 argument (The BIGipServerpool)','red')}\nUsage:\t",colored(f'python {sys.argv[0]} \'Set-Cookie: BIGipServerpool_z_domain=557539594.40570.0000; path=/; Httponly; Secure; SameSite=lax\'', 'yellow'))
    sys.exit(1)


def print_boxed(title: str, content: str) -> None:
    """Print the content in a fancy box
    Args:
        title: str
        content: f-str (splited by \\n)
    Details:
        Draw a fancy Box with the title in cyan and magenta borders
    """
    longest_line = max(len(line) for line in content.split('\n'))
    print(f"{colored('┌─', 'magenta')} {colored(title.ljust(longest_line + 2),'cyan')}" )
    print(colored(f"├─{'─' * (longest_line + 2)}─┐",'magenta'))
    for line in content.split('\n'):
        print(f"{colored('│', 'magenta')} {line.center(longest_line + 2)} {colored('│', 'magenta')}")
    print(colored(f"└─{'─' * (longest_line + 2)}─┘", 'magenta'))


def parse_Cookie(cookie:str)->tuple[int, int]:
    """Parse cookie
    Args:
        cookie: str
    Details:
        The Cookie format is \'Set-Cookie: BIGipServerpool_z_domain=i557539594.40570.0000; path=/; Httponly; Secure; SameSite=lax\'
        Parse scaping the \'Set-Cookie Prefix\' the equal symbol, semicolon, etc.
        Only Remains the real value where the cookie in decimal representation exists
    """
    cookie_value: str
    bigip_cookie: str
    ip: int
    port: int
    _, cookie_value = cookie.split(':')
    bigip_cookie = cookie_value.split(';')[0].strip()
    print_boxed("BIGipServerpool cookie value:", f"{bigip_cookie}")
    ip, port, _ = (int(part) for part in bigip_cookie.split('=')[1].split('.'))
    print_boxed("Decimal values:",f"IP: {ip}\nPort: {port}")
    return (ip, port)


def convert_ip(hex_ip: str) -> str:
    """Convert IP Hex to IPv4
    Args:
        hex_ip: str
    Details:
        Convert the Hexadecimal value of IP Address to IPv4 format
    """
    ip_bytes: str
    ip_parts: str
    ip_address: str
    ip_bytes = [hex_ip[i:i+2] for i in range(2, len(hex_ip), 2)]
    ip_parts = [int(byte, 16) for byte in reversed(ip_bytes)]
    ip_address = '.'.join(map(str, ip_parts))
    return ip_address


"""Convert Port Hex to real Decimal port (Lambda Function)
Args:
    hex_port: str
Details:
    Parse the bytes hex format to decimal format human readable
"""
convert_port: Callable[str, int] = lambda hex_port: int(hex_port[4:6] + hex_port[2:4], 16)


"""Decimal to Hex cookie value (Lambda Function)
Args:
    val: int
Details:
    Get a int value and return a f-string of the hex value
"""
DecimalToHex_cookie_value: Callable[int, str] = lambda value: f"{value:#x}"


def main(cookie: str) -> None:
    """Main Function
    Args:
        cookie: str
    Details:
        cookie is a full set cookie.
        assert cookie is a BIGipServerpool cookie
        send value to parsers and call the print_boxed
    """
    try:
        assert "bigipserverpool" in cookie.lower() and ";" in cookie and "set-cookie:" in cookie.lower(), "La cookie 'BIGipServerpool' no es válida o está incompleta."
    except AssertionError as e:
        print(colored(str(e), 'red'))
        sys.exit(1)
    ip_int, port_int = parse_Cookie(cookie)
    print_boxed(f"Hexadecimal (Little Endian):", f"IP: {(hex_ip:=DecimalToHex_cookie_value(ip_int))}\nPort: {(hex_port:=DecimalToHex_cookie_value(port_int))}")
    ip_address: str = convert_ip(hex_ip)
    port: int = convert_port(hex_port)
    print_boxed("IP Address:", f"{ip_address}")
    print_boxed("Port:", f"{port}")



if __name__ == "__main__":
    main(sys.argv[1].strip())
