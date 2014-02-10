# TSPS

TSPS stands for Tiny and Stealth Ports Scanner.

## Tiny

* the code fits in one C file, is clear and maintainable.
* no dependency

## Stealth

* SYN scanning enabled by default (also known as «stealth scanning»)
* waits randomly before scanning the next port in the queue (between 500ms and 3s), to avoid detection
* scan ports in a random order, also to avoid detection

# Technical details

* tested on archlinux 64b, compiled with gcc 4.8.2 and clang 3.4
* requires superuser privileges (it sends packets through a raw socket)
* IPv4 only

## Usage

``Usage: ./tsps [-h | OPTIONS ] <target address>``

* Available options:
	* ``-v: enable verbose mode (default: disabled)``
	* ``-m <method>: scan method (default: SYN)``
	* ``-f: enable services fingerprinting (default: disabled)``
	* ``-d: disable random delay between ports (default: enabled)``
	* ``-n <number>: amount of ports to be scanned (default: 2014)``
	* ``-i <iface>: interface to use (default will be automatically detected)``
