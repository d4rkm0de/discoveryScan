#!/usr/bin/env python3

# Modules in standard library
import argparse
import sys
import os
import json
from platform import python_version
from engines import certificates


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
    
    if ('certificates' in args.engines) or args.engines == "all":
        print(color["light gray"], "[*]", color["dark gray"], "Running certificates... ", color["white"])

        # Call Crt-Sh Module
        crtsh_search = certificates.Crtsh(target_domains)
        crtsh_search.run()
        crtsh_results = crtsh_search.results

        print(color["blue"], "[certificates]", color["cyan"], "[crt-sh]", color["white"], "Total number of domains from crt-sh submodule: ",
              color["red"], (str(len(crtsh_results))), color["white"])

        # Call Entrust Module
        entrustct_search = certificates.Entrust(target_domains)
        entrustct_search.run()
        entrustct_results = entrustct_search.results

        print(color["blue"], "[certificates]", color["cyan"], "[Entrust]", color["white"], "Total number of domains from Entrust submodule: ",
              color["red"], (str(len(entrustct_results))), color["white"])

        # Call GoogleCT Module
        googlect_search = certificates.GoogleCT(target_domains)
        googlect_search.run()
        googlect_results = (googlect_search.results)

        print(color["blue"], "[certificates]", color["cyan"], "[googleCT]", color["white"], "Total number of domains from GoogleCT submodule: ",
              color["red"], (str(len(googlect_results))), color["white"])

        certificates_results = Core.combine(crtsh_results, entrustct_results)
        certificates_results = Core.combine(certificates_results, googlect_results)

        ################### TESTING BLOCK BELOW ###################

        path = 'certificates_results.json'
        with open(path, 'w') as outfile:
            json.dump(certificates_results, outfile)
        print("\r\nTEST certificates_results JSON Object saved at: " + path)

        print(certificates_results)
        ################### TESTING BLOCK ABOVE ###################
    

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
