#!/usr/bin/env python3

# Modules in standard library
import argparse
import sys
import os
from platform import python_version


# Modules in custom library
from lib.Core import *


Core.banner()


def start():
    parser = argparse.ArgumentParser(
        description='discoveryScan is a python tool used to enumerate web applications\n'
                    ' within a provided domain or list of domains using both passive and active recon techniques.',
        epilog='Example:\n\n'
               'python discoveryScan.py -d "google.com, yahoo.com" -P 80,443\n'
               'python discoveryScan.py -d "google.com -o output.txt\n'
               'python discoveryScan.py -i domains.txt -e ALL\n\n',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-d', '--domains', help='Domain name(s) which will be enumerated.\n'
                                                '-d target.tld,sub.target.tld,sub.sub.target.tld', required=False)
    parser.add_argument('-i', '--Import', help='Specify a text file of domains to import', required=False)
    parser.add_argument('-P', '--Ports', help='Ports to scan 80,443,8080,8443', required=False)
    parser.add_argument('-o', '--output', help='Save the results to a text file', required=False)
    parser.add_argument('-e', '--engines', help='''passive-dns, search-engines, certificates, threat-intel, 
                                                    brute-force, dns, zone-transfer, port-scanner, all''')
    args = parser.parse_args()

    target_domains = []

    if args.Import is not None:

        if os.path.exists(args.Import):
            with open(args.Import) as input_file:
                lines = input_file.readlines()
                for l in lines:
                    target_domains.append(l.strip())
        else:
            print("\033[93m[!] No file exists at '" + str(args.Import) + "'. Quitting.\n\n \033[0m")
            sys.exit(1)

    elif args.domains is not None:
        target_domains = args.domains.replace(' ', '')
        target_domains = target_domains.split(',')

    else:
        print('\033[93m[!] Make sure you specify a domain or input file, quitting.\n\n \033[0m')
        parser.print_usage()
        sys.exit(1)

    print("%s[-] Number of target domains to enumerate: %s%s%s%s" % (color["yellow"], color["white"], color["red"], len(target_domains), color["white"]))


def interactive():
    if python_version()[0:3] < '3':
        print('\033[93m[!] Make sure you have Python 3+ installed, quitting.\n\n \033[0m')
        sys.exit(1)
    try:
        start()
    except KeyboardInterrupt:
        print('\n\n\033[93m[!] ctrl+c detected from user, quitting.\n\n \033[0m')
    except Exception:
        import traceback

        print(traceback.print_exc())


if __name__ == '__main__':
    interactive()
