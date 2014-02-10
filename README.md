# TSPS

TSPS stands for Tiny and Stealth Ports Scanner.

## Tiny

The scanner fits in one C file, the code is clear and maintainable.

## Stealth

The default scanning technique is known as SYN scanning, which is also
known as «stealth scanning».

## Technical details

* tested on archlinux 64b, compiled with gcc 4.8.2 and clang 3.4
* requires superuser privileges (it sends packets through a raw socket)
* IPv4 only

``
Usage: ./tsps [-h | OPTIONS ] <target address>
Available options:
	-v: enable verbose mode (default: disabled)
		-m <method>: scan method (default: SYN)
		-f: enable services fingerprinting (default: disabled)
		-d: disable random delay between ports (default: enabled)
		-n <number>: amount of ports to be scanned (default: 2014)
		-i <iface>: interface to use (default will be automatically detected)
``
