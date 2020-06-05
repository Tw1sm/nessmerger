#!/usr/bin/env python3
######################################################
# Holds the classes the Nessus XML will be mapped to
######################################################

class Report:
    name = ''
    target = ''
    hosts = []


    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.hosts = []


    def addHost(self, host):
        self.hosts.append(host)


class Host:
    name = ''
    os = ''
    startTimestamp = ''
    endTimestamp = ''
    cveCount = ''
    hostRdns = ''
    reportItems = []


    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.reportItems = []


    def addItem(self, item):
        self.reportItems.append(item)


class ReportItem:
    pluginId = ''
    pluginName = ''
    pluginFamily = ''
    pluginType = ''
    pluginPublicationDate = ''
    pluginModificationDate = ''
    vulnPublicationDate = ''
    patchPublicationDate = ''
    cve = ''
    cvss3BaseScore = ''
    cvss3TemporalScore = ''
    cvss3TemporalVector =''
    cvss3Vector = ''
    cvssBasescore = ''
    cvssScoreSource = ''
    cvssVector = ''
    cvssScoreRationale = ''
    cwe = ''
    port = ''
    serviceName = ''
    protocol = ''
    severity = ''
    description = ''
    riskFactor = ''
    synopsis = ''
    pluginOutput = ''
    seeAlso = ''
    solution = ''
    scriptVersion = ''


    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
