#!/usr/bin/env python3
####################################################################
# This script takes a folder as input and merges all .nessus files
# from the folder into one report, formatted as an Excel .xlsx file
#
# Intended for use with Nessus' "Basic Network Scan"
####################################################################
import xml.etree.ElementTree as et
from src.models import Report, Host, ReportItem
from datetime import datetime
import xlsxwriter
import os
import toolz
import argparse


class Customization:
    logo_file = 'src/logo.png'
    companyName = 'Schneider Downs'
    accentColor = '1E32E3' # used for header color etc
    accentFontColor = 'FFFFFF' # used for font color in cells with accentColor background


# global lists
reports = []
rawReportItems = []


def getReportItems(host, newHost):
    reportItems = host.findall('ReportItem')
    for item in reportItems:
        # pull all attributes
        pluginId = item.attrib['pluginID']
        pluginName = item.attrib['pluginName']
        pluginFamily = item.attrib['pluginFamily']
        pluginType = item.find('plugin_type').text
        pluginPublicationDate = item.find('plugin_publication_date').text
        port = item.attrib['port']
        serviceName = item.attrib['svc_name']
        protocol = item.attrib['protocol']
        severity = item.attrib['severity']
        description = item.find('description').text
        riskFactor = item.find('risk_factor').text

        # attributes below may not exist on all report items
        try:
            vulnPublicationDate = item.find('vuln_publication_date').text
        except:
            vulnPublicationDate = ''

        try:
            pluginModificationDate = item.find('plugin_modification_date').text
        except:
            pluginModificationDate = ''

        try:
            patchPublicationDate = item.find('patch_publication_date').text
        except:
            patchPublicationDate = ''

        try:
            cve = item.find('cve').text
        except:
            cve = ''

        try:
            cvss3BaseScore = item.find('cvss3_base_score').text
        except:
            cvss3BaseScore = ''

        try:
            cvssBasescore = item.find('cvss_base_score').text
        except:
            cvssBasescore = ''

        try:
            cvssScoreSource = item.find('cvss_score_source').text
        except:
            cvssScoreSource = ''

        try:
            cvssScoreRationale = item.find('cvss_score_rationale').text
        except:
            cvssScoreRationale = ''

        try:
            cvss3TemporalScore = item.find('cvss3_temporal_vector').text
        except:
            cvss3TemporalScore = ''

        try:
            cvss3TemporalVector = item.find('cvss3_temporal_vector').text
        except:
            cvss3TemporalVector = ''

        try:
            cvss3Vector = item.find('cvss3_vector').text
        except:
            cvss3Vector = ''

        try:
            cvssVector = item.find('cvss_vector').text
        except:
            cvssVector = ''

        try:
            cwe = item.find('cwe').text
        except:
            cwe = ''

        try:
            synopsis = item.find('synopsis').text
        except:
            synopsis = ''

        try:
            pluginOutput = item.find('plugin_output').text
        except:
            pluginOutput = ''

        try:
            seeAlso = item.find('see_also').text
        except:
            seeAlso = ''

        try:
            solution = item.find('solution').text
        except:
            solution = ''

        try:
            scriptVersion = item.find('script_version').text
        except:
            scriptVersion = ''

        # add to host's list of report items
        newReportItem = ReportItem(pluginId=pluginId, pluginName=pluginName, pluginFamily=pluginFamily, pluginType=pluginType, \
            pluginPublicationDate=pluginPublicationDate, vulnPublicationDate=vulnPublicationDate, cve=cve, cvss3BaseScore=cvss3BaseScore, \
            cvss3TemporalScore=cvss3TemporalScore, cvss3TemporalVector=cvss3TemporalVector, cvss3Vector=cvss3Vector, \
            cvssBasescore=cvssBasescore, cvssScoreSource=cvssScoreSource, cvssVector=cvssVector, \
            cwe=cwe, port=port, serviceName=serviceName, protocol=protocol, severity=severity, description=description, \
            riskFactor=riskFactor, synopsis=synopsis, pluginOutput=pluginOutput, seeAlso=seeAlso, solution=solution, \
            scriptVersion=scriptVersion, pluginModificationDate=pluginModificationDate, patchPublicationDate=patchPublicationDate
        )
        newHost.addItem(newReportItem)
        rawReportItems.append(newReportItem)


def getHosts(root):
    # get the top level <Report> tag
    rootReport = root.find('Report')

    # add to reports list
    reportName = rootReport.attrib['name']
    pref = root.find('.//*[name="TARGET"]')
    reportTarget = pref.find('value').text
    newReport = Report(name=reportName, target=reportTarget)
    reports.append(newReport)

    # get all hosts in the report
    hosts = rootReport.findall('ReportHost')

    print(f'[*] Parsing report: {reportName} (Hosts: {len(hosts)})')

    for host in hosts:
        name = host.attrib['name']
        #print(f'\t[+] Parsing data for host: {name}')

        os = host.find('.//tag[@name="os"]').text
        startTimestamp = host.find('.//tag[@name="HOST_START_TIMESTAMP"]').text
        endTimestamp = host.find('.//tag[@name="HOST_END_TIMESTAMP"]').text
        try:
            cveCount = host.find('.//tag[@name="patch-summary-total-cves"]').text
        except:
            cveCount = 0
        hostRdns = host.find('.//tag[@name="host-rdns"]').text

        # add host to report's host list
        newHost = Host(name=name, os=os, startTimestamp=startTimestamp, endTimestamp=endTimestamp, \
            cveCount=cveCount, hostRdns=hostRdns
        )
        newReport.addHost(newHost)

        # get all vuln data related to the current host
        getReportItems(host, newHost)


def addSeveritySheet(workbook, name, vulns):
    sheet = workbook.add_worksheet(name)
    unique = list(toolz.unique(vulns, key=lambda vuln: vuln.pluginId))

    sheet.set_column(0, 0, 12)
    sheet.set_column(1, 1, 45)
    sheet.set_column(3, 4, 16)
    sheet.set_column(5, 5, 20)
    sheet.set_column(6, 8, 65)
    sheet.set_column(9, 9, 33)
    sheet.set_column(12, 15, 23)

    sheet.add_table(
        f'A1:P{len(unique) + 1}',
        {
            'columns': [
                {'header': 'Plugin ID'},
                {'header': 'Plugin Name'},
                {'header': 'Count'},
                {'header': 'Plugin Family'},
                {'header': 'Plugin Type'},
                {'header': 'CVE'},
                {'header': 'Solution'},
                {'header': 'Description'},
                {'header': 'Synopsis'},
                {'header': 'CVSS Vector'},
                {'header': 'CVSS Base Score'},
                {'header': 'CVSS Temportal Score'},
                {'header': 'Plugin Publicaton Date'},
                {'header': 'Plugin Modification Date'},
                {'header': 'Patch Publication Date'},
                {'header': 'Vuln Publication Date'},
            ]
        }
    )

    row = 2
    for item in unique:
        count = len([x for x in vulns if x.pluginId == item.pluginId])
        sheet.write_row(
            f'A{row}',
            [
                int(item.pluginId),
                item.pluginName,
                count,
                item.pluginFamily,
                item.pluginType,
                item.cve,
                item.solution,
                item.description,
                item.synopsis,
                item.cvssVector,
                item.cvssBasescore,
                item.cvss3TemporalScore,
                item.pluginPublicationDate,
                item.pluginModificationDate,
                item.patchPublicationDate,
                item.vulnPublicationDate
            ]
        )
        row += 1


def writeXlsx(reports, directory):
    print('\n[*] Creating report...')
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    fname = os.path.join(directory, f'Nessus-Report-{timestamp}.xlsx')

    # calc stats
    criticals   = [x for x in rawReportItems if x.severity == '4']
    highs       = [x for x in rawReportItems if x.severity == '3']
    mediums     = [x for x in rawReportItems if x.severity == '2']
    lows        = [x for x in rawReportItems if x.severity == '1']
    infos       = [x for x in rawReportItems if x.severity == '0']

    totalHosts = 0
    for report in reports: totalHosts += len(report.hosts)


    workbook = xlsxwriter.Workbook(fname)

    # Define formats
    header = workbook.add_format({
        'bold': True,
        'bg_color': Customization.accentColor,
        'font_color': Customization.accentFontColor,
    })

    # Home worksheet
    homesheet = workbook.add_worksheet('Home')
    homesheet.insert_image('A1', Customization.logo_file)
    homesheet.set_column(0,0,55)
    homesheet.write('A10', f'{Customization.companyName} Scanning Summary', header)
    homesheet.write('A11', 'Total Scans')
    homesheet.write('A12', 'Hosts Scanned')
    homesheet.write('A14', 'Count of Critical Vulnerabilities')
    homesheet.write('A15', 'Count of High Vulnerabilities')
    homesheet.write('A16', 'Count of Medium Vulnerabilities')
    homesheet.write('A17', 'Count of Low Vulnerabilities')

    homesheet.write_blank('B10', '', header)
    homesheet.write('B11', len(reports))
    homesheet.write('B12', totalHosts)
    homesheet.write('B14', len(criticals))
    homesheet.write('B15', len(highs))
    homesheet.write('B16', len(mediums))
    homesheet.write('B17', len(lows))

    # ScanTargets sheet
    targetsSheet = workbook.add_worksheet('ScanTargets')
    targetsSheet.set_column(0, 0, 35)
    targetsSheet.set_column(1, 1, 20)

    row = 2
    for report in reports:
        targets = report.target.split(',')
        for target in targets:
            targetsSheet.write_row(
                f'A{row}',
                [
                    report.name,
                    target
                ]
            )
            row += 1

    targetsSheet.add_table(
        f'A1:B{row - 1}',
        {
            'columns': [
                {'header': 'Scan'},
                {'header': 'Target'},
            ]
        }
    )

    # Vulns by Host sheet
    byHostSheet = workbook.add_worksheet('Vulns by Host')
    byHostSheet.set_column(0, 0, 35)
    byHostSheet.set_column(1, 2, 20)
    byHostSheet.set_column(3, 3, 45)
    byHostSheet.set_column(4, 4, 10)
    byHostSheet.set_column(5, 8, 55)
    byHostSheet.set_column(9, 9, 20)
    byHostSheet.set_column(10, 14, 10)

    byHostSheet.add_table(
        f'A1:O{len(rawReportItems) + 1}',
        {
            'columns': [
                {'header': 'Scan Name'},
                {'header': 'Host'},
                {'header': 'Operating System'},
                {'header': 'Plugin Name'},
                {'header': 'Risk'},
                {'header': 'Solution'},
                {'header': 'Synopsis'},
                {'header': 'Description'},
                {'header': 'Plugin Output'},
                {'header': 'Service Name'},
                {'header': 'Protocol'},
                {'header': 'Port'},
                {'header': 'CVSS Vector'},
                {'header': 'CVSS Base Score'},
                {'header': 'CVSS Temportal Score'},
            ]
        }
    )

    row = 2
    for report in reports:
        for host in report.hosts:
            for item in host.reportItems:
                byHostSheet.write_row(
                    f'A{row}',
                    [
                        report.name,
                        host.name,
                        host.os,
                        item.pluginName,
                        item.riskFactor,
                        item.solution,
                        item.synopsis,
                        item.description,
                        item.pluginOutput,
                        item.serviceName,
                        item.protocol,
                        int(item.port),
                        item.cvssVector,
                        item.cvssBasescore,
                        item.cvss3TemporalScore
                    ]
                )
                row += 1

    addSeveritySheet(workbook, 'Critical', criticals)
    addSeveritySheet(workbook, 'High', highs)
    addSeveritySheet(workbook, 'Medium', mediums)
    addSeveritySheet(workbook, 'Low', lows)
    addSeveritySheet(workbook, 'Informational', infos)

    workbook.close()
    print(f'\n[*] Report written to {fname}')


def getargs():
    parser = argparse.ArgumentParser(description="Merge all .nessus files within a folder into one Excel .xlsx report", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(type=str, dest="directory", help="Folder containing .nessus files")
    args = parser.parse_args()
    return args


def main():
    args = getargs()
    if not os.path.isdir(args.directory):
        print('[!] Cannot find specified directory')
        exit()

    # find all .nessus files in the directory
    nessusFiles = [os.path.join(args.directory, file) for file in os.listdir(args.directory) if file.endswith('.nessus')]

    if len(nessusFiles) == 0:
        print('[!] No .nessus files found!')
        exit()
    else:
         print(f'[*] Found {len(nessusFiles)} nessus files!')

    for file in nessusFiles:
        try:
            tree = et.parse(file)
            root = tree.getroot()
        except:
            print(f"\n[!] Error reading from {file}")
            Input('[ Press enter to skip to the next file ]')

        getHosts(root)

    writeXlsx(reports, args.directory)


if __name__ == '__main__':
    main()
  
 
