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
