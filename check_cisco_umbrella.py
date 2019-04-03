#!/usr/bin/env python
"""
check_cisco_umbrella - plugin for fetching blocked threats
from the Cisco Umbrella API (Reporting API - Security Activity Report)

Author: Henrik Janzon <hjanzon@op5.com>
"""
try:
    import argparse
    import sys
    import time
    import json
    import nagiosplugin
    import requests
except ImportError as missing:
    print("Error - could not import all required Python modules: {} \nDependency installation with pip:\n pip install -r requirements.txt".format(missing))
    sys.exit(3)


class CheckCiscoUmbrella(nagiosplugin.Resource):
    """ Collect data and process result """
    def __init__(self, org, key, sec, time):
        self.org = org
        self.key = key
        self.sec = sec
        self.time = time

    def fetch_blocks(self):
        verifysll = True
        headers = {'content-type': 'application/json', 'accept': 'application/json'}
        params = {
            'start': round(time.time()) - self.time,
        }
        r = requests.get("https://reports.api.umbrella.com/v1/organizations/{}/security-activity".format(self.org), params=params, auth=(self.key, self.sec), verify=(verifysll), headers=(headers))
        # print(json.dumps(r.json(), indent=2))
        return r.json()

    def total_blocks(self, result):
        total_blocks = len(result["requests"])
        # print(total_blocks)
        return total_blocks

    def blocks_per_seccategory(self, result):
        categories = {
            "Command and Control": 0,
            "Cryptomining": 0,
            "DNS Tunneling VPN": 0,
            "Dynamic DNS": 0,
            "Malware": 0,
            "Newly Seen Domains": 0,
            "Phishing": 0,
            "Potentially Harmful": 0,
            "Unauthorized IP Tunnel Access": 0
        }
        for block in result["requests"]:
            # print(block["originId"])
            for cat in block["categories"]:
                if cat in categories:
                    categories[cat] += 1
                    # print(cat)
        return categories

    def probe(self):

        # Fetch data
        result = self.fetch_blocks()

        # Get totalt number of blocks
        total_blocks = self.total_blocks(result)

        # Get total number of blocks per category
        blocks_per_secategory = self.blocks_per_seccategory(result)
        return [nagiosplugin.Metric('total', total_blocks, context='total'),
                nagiosplugin.Metric('command and control', blocks_per_secategory["Command and Control"], context='default'),
                nagiosplugin.Metric('cryptomining', blocks_per_secategory["Cryptomining"], context='default'),
                nagiosplugin.Metric('dns tunneling vpn', blocks_per_secategory["DNS Tunneling VPN"], context='default'),
                nagiosplugin.Metric('dynamic dns', blocks_per_secategory["Dynamic DNS"], context='default'),
                nagiosplugin.Metric('malware', blocks_per_secategory["Malware"], context='default'),
                nagiosplugin.Metric('newly seen domains', blocks_per_secategory["Newly Seen Domains"], context='default'),
                nagiosplugin.Metric('phishing', blocks_per_secategory["Phishing"], context='default'),
                nagiosplugin.Metric('potentially harmful', blocks_per_secategory["Potentially Harmful"], context='default'),
                nagiosplugin.Metric('unauthorized ip tunnel access', blocks_per_secategory["Unauthorized IP Tunnel Access"], context='default')]


def parse_args():
    """ Define and Parse arguments """
    desc = "check_cisco_umbrella"
    epi = "API doc: https://docs.umbrella.com/umbrella-api/docs/security-activity-report"
    argp = argparse.ArgumentParser(description=desc, epilog=epi)
    argp._optionals.title = "Options"
    argp.add_argument('-o', '--org', required=True, dest='org', type=str, help='Organisation ID')
    argp.add_argument('-k', '--key', required=True, dest='key', type=str, help='API Key')
    argp.add_argument('-s', '--secret', required=True, dest='sec', type=str, help='API Key Secret')
    argp.add_argument('-T', '--time', required=False, default=300, dest='time', type=int, help='How many seconds back to begin the query (start_time), default 300s')
    argp.add_argument('-w', '--warning', metavar='RANGE', default='')
    argp.add_argument('-c', '--critical', metavar='RANGE', default='')
    argp.add_argument('-v', '--verbose', action='count', default=0, help='verbose')
    argp.add_argument('-V', '--version', action='version', version='%(prog)s 1.0')
    argp.add_argument('-t', '--timeout', default=30, help='timeout')
    return argp.parse_args()


def main():
    args = parse_args()
    check = nagiosplugin.Check(CheckCiscoUmbrella(args.org, args.key, args.sec, args.time), nagiosplugin.ScalarContext('total', args.warning, args.critical, fmt_metric='{value} threat(s) blocked'))
    check.main(args.verbose, args.timeout)

if __name__ == '__main__':
    main()