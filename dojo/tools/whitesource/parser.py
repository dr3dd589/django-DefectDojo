import hashlib
from urlparse import urlparse
import re
import json
from dojo.models import Endpoint, Finding

__author__ = 'dr3dd589'



class WhitesourceJSONParser(object):
    def __init__(self, file, test):
        self.dupes = dict()
        self.items = ()
        if file is None:
            return
        
        content = json.load(file)
        if "vulnerabilities" in content:
            tree_node = content['vulnerabilities']
            for node in tree_node:
                title = node['name'] + " | " + node['project']
                severity = node['severity'].lower().capitalize()
                description = node['description']
                if "CVE" in node['type']:
                    cve = node['name']
                else:
                    cve = None
                
                dupe_key = hashlib.md5(description + title).hexdigest()

                if dupe_key in self.dupes:
                    finding = self.dupes[dupe_key]
                    if finding.description:
                        finding.description = finding.description
                    self.dupes[dupe_key] = finding
                else:
                    self.dupes[dupe_key] = True

                    finding = Finding(title=title,
                                    test=test,
                                    active=False,
                                    verified=False,
                                    description=description,
                                    severity=severity,
                                    cve=cve,
                                    numerical_severity=Finding.get_numerical_severity(
                                        severity),
                                    # mitigation=mitigation,
                                    # impact=impact,
                                    # references=references,
                                    dynamic_finding=True)
                    self.dupes[dupe_key] = finding

            self.items = self.dupes.values()


