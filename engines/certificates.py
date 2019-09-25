import threading
import logging
import requests
import json
from lib.Core import *
import re


class Entrust:

    def __init__(self, domains):
        self.domains = domains
        self.threads = 20
        self.lock = threading.BoundedSemaphore(value=self.threads)
        self.engine = 'ctEngine'
        self.module = 'Entrust'
        self.host = "ctsearch.entrust.com"
        self.protocol = "https://"
        self.uri = '/api/v1/certificates?fields=validTo,validFrom,sn,issuerDN,thumbprint,san,' \
                   'subjectCNReversed&includeExpired=False&exactMatch=false&limit=5000&domain='

        self.results = {}

    def ctsearch(self, domain):

        # Acquire thread lock
        self.lock.acquire()
        try:

            # Initiate network request for current domain
            url = self.protocol + self.host + self.uri + domain
            ua = Core.get_user_agent()
            params = {'User-Agent': ua}
            r = requests.get(url, headers=params)
            # Was network request OK?
            subdomains = []
            if r.ok:

                content = r.content.decode('UTF-8')
                # Was there any results from search?
                if content != '':
                    data = json.loads(content)
                    # cert_count = len(data)
                    # print(cDK, str(cert_count) + " certificates retrieved from Entrust CT Search for " + domain, cW)

                    if data:

                        for d in data:

                            if "subjectO" in list(d.keys()):
                                org = d['subjectO']
                            else:
                                org = ''

                            if "san" in list(d.keys()):
                                for sand in d['san']:
                                    if str(domain) in str(sand['valueReversed'][::-1]):
                                        subdomains.append({
                                            "Subdomain": sand['valueReversed'][::-1],
                                            "Thumbprint": d['thumbprint'],
                                            "Issuer": re.compile('o=(.+?),').findall(d['issuerDN'])[0],
                                            "Issuer CN": re.compile('cn=(.+?),').findall(d['issuerDN'])[0],
                                            "Serial": d["sn"],
                                            'Org': org,
                                            "ValidFrom": d["validFrom"],
                                            "ValidTo": d["validTo"],
                                            "Link": 'https://www.entrust.com/ct-search-result/?id=' + d[
                                                'thumbprint']
                                        })
                            else:
                                subdomains.append({
                                    "Subdomain": d['subjectCNReversed'][::-1],
                                    "Thumbprint": d['thumbprint'],
                                    "Issuer": re.compile('o=(.+?),').findall(d['issuerDN'])[0],
                                    "Issuer CN": re.compile('cn=(.+?),').findall(d['issuerDN'])[0],
                                    "Serial": d["sn"],
                                    'Org': org,
                                    "ValidFrom": d["validFrom"],
                                    "ValidTo": d["validTo"],
                                    "Link": 'https://www.entrust.com/ct-search-result/?id=' + d['thumbprint']
                                })

                        if len(subdomains) != 0:
                            # Loop through unique matches and add to total array of matches in threaded batch
                            print(color["blue"], "[certificates]", color["cyan"], "[Entrust]", color["dark gray"],
                                  "Number of subdomains discovered from: ", color["white"], domain, color["red"],
                                  str(len(subdomains)), color["white"])

                            self.results[domain] = {
                                self.engine + '-' + self.module: {
                                    "Domain": domain,
                                    "Subdomains": subdomains
                                }
                            }

                # End if variable has data

                else:
                    print("No hits found in Entrust CT Search")

                # End If/Else search found any hits

            else:
                print("Network request was NOT OK")

            # End If/Else network request OK

        except Exception as e:
            print(e)
            print('really bad stuff')
            pass

        # End Try/Except block

        # Release thread lock
        self.lock.release()

    # End ct_search function

    def run(self):

        threads = []
        for domain in self.domains:
            worker = threading.Thread(target=self.ctsearch(domain))
            threads.append(worker)

        for t in threads:
            t.start()

        for w in threads:
            w.join()

        return self.results


class Crtsh:
    def __init__(self, domains):
        self.domains = domains
        self.threads = 20
        self.lock = threading.BoundedSemaphore(value=self.threads)
        self.engine = 'ctEngine'
        self.module = 'crt-sh'
        self.host = "crt.sh"
        self.protocol = "https://"
        self.uri = '/?output=json&q=%25.'
        self.results = {}

    def ctsearch(self, domain):

        # Acquire thread lock
        self.lock.acquire()

        try:

            # Initiate network request for current domain
            url = self.protocol + self.host + self.uri + domain
            ua = Core.get_user_agent()
            params = {'User-Agent': ua}
            r = requests.get(url, headers=params)

            if r.ok:
                logging.debug("request was OK")

                if r.content != '[]'.encode('UTF-8'):
                    subdomains = []
                    logging.debug("Looks like we have results")
                    content = r.content.decode('UTF-8')
                    data = json.loads(content)

                    for d in data:
                        subdomains.append(d['name_value'])

                    if len(set(subdomains)) > 0:
                        # Loop through unique matches and add to total array of matches in threaded batch
                        print(color["blue"], "[certificates]", color["cyan"], "[crt-sh]", color["dark gray"],
                              "Number of subdomains discovered from: ", color["white"], domain, color["red"],
                              str(len(set(subdomains))), color["white"])
                        for sub in set(subdomains):
                            self.results[domain] = {
                                self.engine + ' - ' + self.module: {
                                    "Subdomain": sub
                                }
                            }

                else:
                    logging.debug("no certificates found for search")

            else:
                logging.debug("request was not OK")

        except Exception as e:
            logging.debug(e)
            pass

        # Release thread lock
        self.lock.release()

    def run(self):
        threads = []
        for domain in self.domains:
            worker = threading.Thread(target=self.ctsearch(domain))
            threads.append(worker)

        for t in threads:
            t.start()

        for w in threads:
            w.join()

        return self.results


class GoogleCT:
    # https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=true&include_subdomains=true&domain=

    def __init__(self, domains):
        self.domains = domains
        self.threads = 20
        self.lock = threading.BoundedSemaphore(value=self.threads)
        self.engine = 'ctEngine'
        self.module = 'GoogleCT'
        self.host = "www.google.com"
        self.protocol = "https://"
        self.uri = '/transparencyreport/api/v3/httpsreport/ct/certsearch?' \
                   'include_expired=true&include_subdomains=true&domain='
        self.results = {}

    def ctsearch(self, domain):

        # Acquire thread lock
        self.lock.acquire()

        try:
            # Initiate network request for current domain
            url = self.protocol + self.host + self.uri + domain
            ua = Core.get_user_agent()
            params = {'User-Agent': ua}
            r = requests.get(url, headers=params)

            if r.ok:
                logging.debug("request was OK")
                content = r.content.decode('UTF-8')
                data = json.loads(content.split('\n', 2)[2])
                data = data[0][1]

                if data != '[]':
                    subdomains = []
                    logging.debug("Looks like we have results")

                    for d in data:
                        subdomains.append(d[1])

                    if len(set(subdomains)) > 0:
                        # Loop through unique matches and add to total array of matches in threaded batch
                        print(color["blue"], "[certificates]", color["cyan"], "[GoogleCT]", color["dark gray"],
                              "Number of subdomains discovered from: ", color["white"], domain, color["red"],
                              str(len(set(subdomains))), color["white"])
                        for sub in set(subdomains):
                            self.results[domain] = {
                                self.engine + ' - ' + self.module: {
                                    "Subdomain": sub
                                }
                            }

                else:
                    logging.debug("no certificates found for search")

            else:
                logging.debug("request was not OK")

        except Exception as e:
            logging.debug(e)
            pass

        # Release thread lock
        self.lock.release()

    def run(self):

        threads = []
        for domain in self.domains:
            worker = threading.Thread(target=self.ctsearch(domain))
            threads.append(worker)

        for t in threads:
            t.start()

        for w in threads:
            w.join()

        return self.results
