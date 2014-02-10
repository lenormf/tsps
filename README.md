# TSPS

TSPS stands for Tiny and Stealth Ports Scanner.

## Tiny

Download tsps.c to your file system, give it to your favorite C compiler and you're done.

* The code fits in one C file, is clear and maintainable.
* No dependency

## Stealth

Unless you want it to, _TSPS_ will try to stay under the radar when scanning a host.

* SYN scanning enabled by default (also known as «stealth scanning»)
* Waits randomly before scanning the next port in the queue (between 500ms and 3s), to avoid detection
* Scans ports in a random order, also to avoid detection

# Technical details

* Tested on archlinux 64b, compiled with gcc 4.8.2 and clang 3.4
* Requires superuser privileges (it sends packets through a raw socket)
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

## Examples

* Stealth scan with random ports order, random delay between the ports being scanned (system ports)
	* ``# ./tsps -v scanme.nmap.org``
* Stealth scan with random ports order, no delay between the ports being scanned, and service fingerprinting enabled
	* ``# ./tsps -v -d -f scanme.nmap.org``
* Stealth scan with random ports order, service fingerprinting on a special interface, but only system ports
	* ``# ./tsps -v -n 1024 -f -i vboxnet0 scanme.nmap.org``
