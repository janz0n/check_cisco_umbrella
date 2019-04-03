# check_cisco_umbrella
Nagios/Naemon/OP5 Plugin for fetching blocked threats from Cisco Umbrella API (Reporting API - Security Activity Report)
API doc: https://docs.umbrella.com/umbrella-api/docs/security-activity-report

## Installation
pip install -r requirements.txt

## Usage
```
usage: check_cisco_umbrella.py [-h] -o ORG -k KEY -s SEC [-T TIME] [-w RANGE]
                               [-c RANGE] [-v] [-V] [-t TIMEOUT]

check_cisco_umbrella

Options:
  -h, --help            show this help message and exit
  -o ORG, --org ORG     Organisation ID
  -k KEY, --key KEY     API Key
  -s SEC, --secret SEC  API Key Secret
  -T TIME, --time TIME  How many seconds back to begin the query (start_time),
                        default 300s
  -w RANGE, --warning RANGE
  -c RANGE, --critical RANGE
  -v, --verbose         verbose
  -V, --version         show program's version number and exit
  -t TIMEOUT, --timeout TIMEOUT
                        timeout

```
