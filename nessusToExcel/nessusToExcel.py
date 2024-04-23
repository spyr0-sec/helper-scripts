#!/usr/bin/python3
import os, re, argparse, shutil, time, textwrap, json
from xml.etree.ElementTree import ParseError
import nessus_file_reader as nfr
import pandas as pd

# CHANGELOG
# v0.1 - 26/01/2022 - Merged all modules into one file and created wrapper
# v0.2 - 27/01/2022 - Tidied up a bit, added single plugin logic and removed dir argument as xlsxwriter does not support append
# v0.3 - 15/03/2022 - Added unencrypted protocols function. Refactored columns to Hostname / IP / Info to assist with reporter import
# v0.4 - 15/03/2022 - Added CIS compliance extraction function. Added quiet parameter due to inputs now required
# v0.5 - 15/03/2022 - Added HTTP Audit & Default HTTP functions
# v0.6 - 23/03/2022 - Added all issues worksheet
# v0.7 - 30/03/2022 - Added more unsupported OS. Added impact column to remidiations workbook.
#                   - Added logic to seek WMI / Hostnames is Nessus has failed to obtain FQDN, added noresolve flag as comes at a performance hit
#                   - Added LastUpdated module which pulls each Windows latest effective update level. Added exploitability column to unquoted paths
# v0.8 - 01/04/2022 - Added SSH Weak Algorithms Module
# v0.9 - 11/04/2022 - Created dedicated excel functions to create workbook,worksheet,table and add data
# Credit @nop-sec   - Created host dictionary to limit repeat host looks
#                   - Moved the initial parse of XML root to main() rather than per issue to decrease loading of file.
# v1.0 - 08/06/2022 - Added more unsupported OSes. Added databases, open ports and Linux patching modules. Made unquoted paths insensitive matching.
# v1.1 - 29/06/2022 - Fixed invalid module error. Refactored winpatches module. Changed default Excel filename to match input nessus.
#                   - Removed WinRM ports from HTTP output. Better handling if output file is already open. Added keyword search module.
#                   - Added more database end of life dates
# v1.2 - 25/07/2022 - Improved hostname resolvers. Fixed nix patching string matching. Added Debian EoL dates. Refactored compliance to cover all
#                   - Added outdated third party software module 
# v1.3 - 04/08/2022 - 'check Audit Trail' case fix. Added full MS patch audit to lastupdated module. Refactored nixpatches to pick up all RPM checks.
#                   - Added severity column to outdated software and patch modules.
# v1.4 - 08/08/2022 - Added better error handling for incorrect nessus_file_reader package. Added Linux support for all installed software.
#                   - Removed remediations module as now info is captured from outdated third party module. Removed io dependancy.
# v1.5 - 11/05/2023 - Several bug fixes inclduing unix compliance file handing and updated nfr dependancies.
# Credit @lapolis
# v1.6 - 22/01/2024 - Converted to use Pandas.
#                   - Improved output.
#                   - Automatically remove doubles.
#                   - Custom aggregation of results for 'Outdated Software' (more to come)
#                   - Automatically text wrap.
# Credit @lapolis
# v1.7 - 06/03/2024 - Added TLS module
# Credit @lapolis
# v1.8 - 22/03/2024 - Added Table Style customisation
#                   - Added TLS list of issues in a txt file

# STANDARDS
# Columns order - Hostname / IP Address / Other (Except for hosts which will be in reporter format of IP / Hostname / OS)
# Columns width - Hostname = 40 / IP Address = 15 / Operating System = 40 / Protocol = 10 / Port = 6 / Other = variable
# Long Date format - 01 January 1970 - 31 December 2049

# Globals hosts dictionary to lookup host information by report_host
Hosts = {}
root = ""
# this is needed for custom sorting
severity_hierarchy = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}

# load additional configs
script_dir = os.path.dirname(__file__)
config_file = os.path.join(script_dir, './additional_config.json')
try:
    with open(config_file, 'r') as rf:
        additional_config = json.load(rf)
except:
    additional_config = None

# Functions
def extractAll():
    extractHosts()
    extractIssues()
    extractCompliance()
    extractDatabases()
    extractDefaultHTTP()
    extractHTTPServers()
    extractLastUpdated()
    extractMSPatches()
    extractLinuxPatches()
    extractOpenPorts()
    extractInstalledSoftware()
    extractOutdatedSoftware()
    extractUnencryptedProtocols()
    extractUnquotedServicePaths()
    extractUnsupportedOperatingSystems()
    extractWeakServicePermissions()
    extractWeakSSHAlgorithms()
    extractWeakRDP()
    extractWeakSMB()
    extractCredPatch()
    extractTLSWeaknesses()

# Extract system information
def extractHosts():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['IP Address',
               'Hostname',
               'Operating System']
    column_widths = [15, 40, 60]
    df = pd.DataFrame(columns=columns)

    with open("Host Information.txt", "w") as txt_file:

        for report_host in nfr.scan.report_hosts(root):
            report_ip = nfr.host.resolved_ip(report_host)
            report_host_os = nfr.host.detected_os(report_host)
            report_fqdn = Hosts[report_ip]

            if (report_host_os is None or report_host_os.count('\n') > 0):
                report_host_os = None

            # Write to txt
            print(f'{report_ip} {report_fqdn} {report_host_os}', file=txt_file)

            # Write to Excel worksheet
            row = [report_ip,
                   report_fqdn,
                   report_host_os]
            df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    txt_file.close()

    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        df = df.sort_values(by='IP Address')
        WriteDataFrame(df, 'Host Information', column_widths)

    toc = time.perf_counter()
    if args.verbose:
            print(f'DEBUG - Completed Host Information. {len(df)} rows took {toc - tic:0.4f} seconds')

# Extract all non-informational issues
def extractIssues():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Protocol',
               'Port',
               'Risk',
               'Issue']
               # 'Reporter Issue - 30']
    # Any reason to keep that?? ^^ - why was it there?
    column_widths = [40, 15, 10, 6, 8, 100, 30]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        report_ip = nfr.host.resolved_ip(report_host)
        report_fqdn = Hosts[report_ip]

        report_items_per_host = nfr.host.report_items(report_host)
        for report_item in report_items_per_host:

            risk_factor = nfr.plugin.report_item_value(report_item, 'risk_factor')

            if risk_factor != "None":
                issue_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                issue_port = nfr.plugin.report_item_value(report_item, 'port')
                issue_description = nfr.plugin.report_item_value(report_item, 'plugin_name')

                # Write to Excel worksheet
                row = [report_fqdn,
                       report_ip,
                       issue_protocol,
                       issue_port,
                       risk_factor,
                       issue_description]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        df = df.sort_values(by='IP Address')
        WriteDataFrame(df, 'All Issues', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Issues. {len(df)} rows took {toc - tic:0.4f} seconds')

# Extract and format CIS Compliance results
def extractCompliance():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'CIS Benchmark ID',
               'Result',
               'Description',
               'Assessed Host value',
               'CIS Policy value']
    # Any reason to keep that?? ^^ - why was it there?
    column_widths = [40, 15, 17, 8, 120, 55, 55]
    df = pd.DataFrame(columns=columns)

    # Will need to assess each plugin for its family
    for report_host in nfr.scan.report_hosts(root):
        all_plugins = nfr.host.report_items(report_host)

        for plugin in all_plugins:
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]
            plugin_family = nfr.plugin.report_item_value(plugin, 'pluginFamily')

            if plugin_family == "Policy Compliance":
                compliance_host_value = nfr.plugin.report_item_value(plugin, 'compliance-actual-value')
                compliance_policy_value = nfr.plugin.report_item_value(plugin, 'compliance-policy-value')
                compliance_desc = nfr.plugin.report_item_value(plugin, 'compliance-check-name')
                compliance_result = nfr.plugin.report_item_value(plugin, 'compliance-result')

                try:
                    compliance_id,compliance_name = compliance_desc.split(' ',1)
                except Exception as e:
                    compliance_name = compliance_desc
                    compliance_id = None
                    if args.verbose:
                        print(f'DEBUG - If this is not a Unix machine something is wrong! (compliance-check-name) -> {e}')

                # Write to Excel worksheet
                row = [report_fqdn,
                       report_ip,
                       compliance_id,
                       compliance_result,
                       compliance_name,
                       compliance_host_value,
                       compliance_policy_value]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    if not args.noclean:
        df = df.drop_duplicates()

    if not df.empty:
        # df = df.sort_values(by='IP Address')
        WriteDataFrame(df, 'Compliance', column_widths, style='compliance')

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Compliance. {len(df)} rows took {toc - tic:0.4f} seconds')

# Provide database asset audit and include end of life dates.
# TODO: This module is taking significantly longer than the rest - could reduce code within if statements
def extractDatabases():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Protocol',
               'Port',
               'Database Type',
               'Version',
               'MSSQL Instance Name',
               'End of Life Date']
    column_widths = [40, 15, 10, 6, 20, 63, 34, 16]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        unauth_mssql_plugin = nfr.plugin.plugin_outputs(root, report_host, '10144')
        auth_mssql_plugin = nfr.plugin.plugin_outputs(root, report_host, '11217')
        mysql_plugin = nfr.plugin.plugin_outputs(root, report_host, '10719')
        postgres_plugin = nfr.plugin.plugin_outputs(root, report_host, '26024')
        oracle_plugin = nfr.plugin.plugin_outputs(root, report_host, '22073')
        mongo_plugin = nfr.plugin.plugin_outputs(root, report_host, '65914')

        # Reinit variables each loop
        mssql_version = ["",""]; mssql_instance = ["",""]; mysql_version = ["",""]
        mssql_eol = ""; mysql_eol = ""; mongo_eol = ""

        # Microsoft SQL Server
        if not (re.match('[Cc]heck Audit Trail', unauth_mssql_plugin)) or not (re.match('[Cc]heck Audit Trail', auth_mssql_plugin)):
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            report_items_per_host = nfr.host.report_items(report_host)
            for report_item in report_items_per_host:
                lines = None

                plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))

                if plugin_id == 10144:
                    lines = unauth_mssql_plugin.splitlines()
                    mssql_port = nfr.plugin.report_item_value(report_item, 'port')
                if plugin_id == 11217:
                    lines = auth_mssql_plugin.splitlines()
                    mssql_port = '1433'

                if lines is not None:
                    for line in lines:
                        if ('Version' in line) and ('Recommended' not in line):
                            mssql_version = line.split(':', 1)

                            sql_2005 = re.match(r'9[.]0[.]', mssql_version[-1].strip())
                            sql_2008 = re.match(r'10[.][5|0][0|.]', mssql_version[-1].strip())
                            sql_2012 = re.match(r'11[.]0[.]', mssql_version[-1].strip())

                            if sql_2005: mssql_eol = "12 April 2016"
                            if sql_2008: mssql_eol = "09 July 2019"
                            if sql_2012: mssql_eol = "12 July 2022"

                        if 'Instance' in line:
                            mssql_instance = line.split(':', 1)

                    mssql_protocol = nfr.plugin.report_item_value(report_item, 'protocol')

                    # Write to Excel worksheet
                    row = [report_fqdn,
                           report_ip,
                           mssql_protocol,
                           mssql_port,
                           "Microsoft SQL Server",
                           mssql_version[-1].strip(),
                           mssql_instance[-1].strip(),
                           mssql_eol]
                    df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

        # MySQL 
        if not re.match('[Cc]heck Audit Trail', mysql_plugin):
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            report_items_per_host = nfr.host.report_items(report_host)
            for report_item in report_items_per_host:

                plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
                if plugin_id == 10719:
                    lines = mysql_plugin.splitlines()
                    for line in lines:
                        if 'Version' in line:
                            mysql_version = line.split(':', 1)

                            mysql_five_zero = re.match(r'5[.]0[.]', mysql_version[-1].strip())
                            mysql_five_one = re.match(r'5[.]1[.]', mysql_version[-1].strip())
                            mysql_five_five = re.match(r'5[.]5[.]', mysql_version[-1].strip())
                            mysql_five_six = re.match(r'5[.]6[.]', mysql_version[-1].strip())

                            if mysql_five_zero: mysql_eol = "09 January 2012"
                            if mysql_five_one: mysql_eol  = "31 December 2013"
                            if mysql_five_five: mysql_eol = "03 December 2018"
                            if mysql_five_six: mysql_eol  = "05 February 2021"

                    mysql_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                    mysql_port = nfr.plugin.report_item_value(report_item, 'port')

                    # Write to Excel worksheet
                    row = [report_fqdn,
                           report_ip,
                           mysql_protocol,
                           mysql_port,
                           "MySQL",
                           mysql_version[-1].strip(),
                           "",
                           mysql_eol]
                    df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

        # PostgreSQL - Doesn't present any info from an unauth perspective
        if not re.match('[Cc]heck Audit Trail', postgres_plugin):
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            report_items_per_host = nfr.host.report_items(report_host)
            for report_item in report_items_per_host:

                plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
                if plugin_id == 26024:

                    postgres_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                    postgres_port = nfr.plugin.report_item_value(report_item, 'port')

                    # Write to Excel worksheet
                    row = [report_fqdn,
                           report_ip,
                           postgres_protocol,
                           postgres_port,
                           "PostgreSQL",
                           "", "", ""]
                    df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

        # Oracle
        if not re.match('[Cc]heck Audit Trail', oracle_plugin):
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            report_items_per_host = nfr.host.report_items(report_host)
            for report_item in report_items_per_host:

                plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
                if plugin_id == 22073:

                    lines = oracle_plugin.splitlines()
                    oracle_version = None
                    for line in lines:
                        if 'Version' in line:
                            oracle_version = line.split()[-1].strip()

                    oracle_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                    oracle_port = nfr.plugin.report_item_value(report_item, 'port')

                    # Write to Excel worksheet
                    row = [report_fqdn,
                           report_ip,
                           oracle_protocol,
                           oracle_port,
                           "Oracle Database",
                           oracle_version,
                           "",""]
                    df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

        # MongoDB
        if not re.match('[Cc]heck Audit Trail', mongo_plugin):
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            report_items_per_host = nfr.host.report_items(report_host)
            for report_item in report_items_per_host:

                plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
                if plugin_id == 65914:

                    lines = mongo_plugin.splitlines()
                    for line in lines:
                        if 'Version' in line:
                            mongo_version = line.split(':', 1)

                            mongo_one = re.match(r"^1[.][1-9][.]", mongo_version[-1].strip())
                            mongo_two = re.match(r"^2[.][1-9][.]", mongo_version[-1].strip())
                            mongo_three = re.match(r"^3[.][1-9][.]", mongo_version[-1].strip())

                            if mongo_one: mongo_eol = "01 September 2012"
                            if mongo_two: mongo_eol  = "01 October 2016"
                            if mongo_three: mongo_eol = "30 April 2021"

                    mongo_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                    mongo_port = nfr.plugin.report_item_value(report_item, 'port')

                    # Write to Excel worksheet
                    row = [report_fqdn,
                           report_ip,
                           mongo_protocol,
                           mongo_port,
                           "MongoDB",
                           mongo_version[-1].strip(),
                           "",
                           mongo_eol]
                    df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing and cleaning the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, 'Databases', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Database Audit. {len(df)} rows took {toc - tic:0.4f} seconds')

# Extract all Default HTTP instances
def extractDefaultHTTP():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Protocol',
               'Port',
               'HTTP Content']
    column_widths = [40, 15, 10, 6, 60]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        plugin_11422 = nfr.plugin.plugin_outputs(root, report_host, '11422')

        if not re.match('[Cc]heck Audit Trail', plugin_11422):
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            lines = plugin_11422.splitlines()

        report_items_per_host = nfr.host.report_items(report_host)
        for report_item in report_items_per_host:

            plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
            if plugin_id == 11422:
                http_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                http_port = nfr.plugin.report_item_value(report_item, 'port')

                # Write to Excel worksheet
                row = [report_fqdn,
                       report_ip,
                       http_protocol,
                       http_port,
                       lines[1]]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, 'Default HTTP Servers', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Default HTTP Servers. {len(df)} rows took {toc - tic:0.4f} seconds')

# Extract all HTTP(S) servers and their headers
def extractHTTPServers():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Protocol',
               'Port',
               'HTTP Server']
    column_widths = [40, 15, 10, 6, 60]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        plugin_10107 = nfr.plugin.plugin_outputs(root, report_host, '10107')

        if not re.match('[Cc]heck Audit Trail', plugin_10107):
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            lines = plugin_10107.splitlines()

        report_items_per_host = nfr.host.report_items(report_host)
        for report_item in report_items_per_host:

            plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
            if plugin_id == 10107:
                http_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                http_port = nfr.plugin.report_item_value(report_item, 'port')

                # Write to Excel worksheet if not WinRM / SCCM HTTP ports
                if (http_port != "5985") and (http_port != "8005")  and (http_port != "47001"):
                    row = [report_fqdn,
                           report_ip,
                           http_protocol,
                           http_port,
                           lines[2]]
                    df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, 'HTTP Servers', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed HTTP Servers. {len(df)} rows took {toc - tic:0.4f} seconds')

# Windows security patch audit
def extractLastUpdated():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Latest Effective Update Level',
               'Patch',
               'Installed on']
    column_widths = [40, 15, 28, 28, 28]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        # Microsoft Security Rollup Enumeration
        plugin_93962 = nfr.plugin.plugin_outputs(root, report_host, '93962')

        if not re.match('[Cc]heck Audit Trail', plugin_93962):
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            lines = plugin_93962.splitlines()
            update_level = ""
            for line in lines:
                if 'Latest effective update level : ' in line:
                    update_level = line.replace(' Latest effective update level : ','')

            # Write to Excel worksheet
            row = [report_fqdn,
                   report_ip,
                   update_level.replace('_','/'),
                   None,
                   None]
            df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

        # SMB Quick Fix Engineering patch output
        plugin_62042 = nfr.plugin.plugin_outputs(root, report_host, '62042')

        if not re.match('[Cc]heck Audit Trail', plugin_62042):
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            lines = plugin_62042.splitlines()
            for line in lines:
                if 'Installed on:' in line:
                    patch_date = line.split(',', 1)
                    patch = patch_date[0]
                    date = patch_date[-1].split()

                    # Write to Excel worksheet
                    row = [report_fqdn,
                           report_ip,
                           None,
                           patch,
                           date[-1]]
                    df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, 'Security Update Level', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Security Patch Levels. {len(df)} rows took {toc - tic:0.4f} seconds')

# Extract all missing Windows security patches
def extractMSPatches():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Severity',
               'Missing Security Patch',
               'Exploit Available',
               'CVE',
               'Additional Information']
    column_widths = [40, 15, 10, 110, 17, 14, 180]
    df = pd.DataFrame(columns=columns)

    # Will need to assess each plugin for its family
    for report_host in nfr.scan.report_hosts(root):
        all_plugins = nfr.host.report_items(report_host)

        for plugin in all_plugins:
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]
            plugin_id = nfr.plugin.report_item_value(plugin, 'pluginID')
            plugin_name = nfr.plugin.report_item_value(plugin, 'pluginName')
            plugin_family = nfr.plugin.report_item_value(plugin, 'pluginFamily')
            risk_factor = nfr.plugin.report_item_value(plugin, 'risk_factor')
            exploitability_ease = nfr.plugin.report_item_value(plugin, 'exploitability_ease')
            cve_list = nfr.plugin.report_item_values(plugin, 'cve')

            exploit_exists_debugging = False
            exploit_exists = False
            if exploitability_ease == 'No known exploits are available':
                exploit_exists = False
            elif exploitability_ease == 'Exploits are available':
                exploit_exists = True
            else:
                # leaving this one here for potential debugging
                exploit_exists_debugging = True

            if cve_list:
                cve_text = '\n'.join([cve for cve in cve_list if cve])
            else:
                cve_text = None

            if (plugin_family == "Windows : Microsoft Bulletins") and (plugin_name != "Microsoft Windows Summary of Missing Patches") and (plugin_name != "Microsoft Patch Bulletin Feasibility Check"):
                output = nfr.plugin.plugin_output(root, report_host, plugin_id)
                row = [report_fqdn,
                       report_ip,
                       risk_factor,
                       plugin_name,
                       exploit_exists,
                       cve_text,
                       output.strip()]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

                # leaving this one here for potential debugging
                if exploit_exists_debugging:
                    print(f'ERROR - Unknown exploitability for Missing Microsoft Patch - Plugin: {plugin_name} - Host: {report_ip}')

            elif (plugin_family == "Windows") and (plugin_name.startswith('Security Updates for ')):
                output = nfr.plugin.plugin_output(root, report_host, plugin_id)
                row = [report_fqdn,
                       report_ip,
                       risk_factor,
                       plugin_name,
                       exploit_exists,
                       cve_text,
                       output.strip()]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

                # leaving this one here for potential debugging
                if exploit_exists_debugging:
                    print(f'ERROR - Unknown exploitability for Missing Microsoft Patch - Plugin: {plugin_name} - Host: {report_ip}')

    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, 'Missing Microsoft Patches', column_widths, style='severity', txtwrap=['CVE', 'Additional Information'])
        # print("INFO - Please text wrap column F and G within the Missing Microsoft Patches worksheet. Highlight column -> Home -> Wrap Text")

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Microsoft Patches. {len(df)} rows took {toc - tic:0.4f} seconds')

# Extract all missing Linux security patches
def extractLinuxPatches():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Severity',
               'Missing patch',
               'Current Package Version',
               'Latest Package Version',
               'Exploit Available',
               'CVE']
    column_widths = [40, 15, 10, 67, 50, 50, 17, 14]
    df = pd.DataFrame(columns=columns)

    # Local security check family misses outdated MySQL rpms among others query every output for "remote package"
    for report_host in nfr.scan.report_hosts(root):
        all_plugins = nfr.host.report_items(report_host)

        for plugin in all_plugins:
            # Remove all info and MS Patching issues
            risk_factor = nfr.plugin.report_item_value(plugin, 'risk_factor')
            plugin_family = nfr.plugin.report_item_value(plugin, 'pluginFamily')

            if (risk_factor != 'None') and (not plugin_family.startswith('Windows')):
                report_ip = nfr.host.resolved_ip(report_host)
                report_fqdn = Hosts[report_ip]
                plugin_name = nfr.plugin.report_item_value(plugin, 'pluginName')
                plugin_id = int(nfr.plugin.report_item_value(plugin, 'pluginID'))
                plugin_output = nfr.plugin.plugin_outputs(root, report_host, plugin_id)
                exploitability_ease = nfr.plugin.report_item_value(plugin, 'exploitability_ease')
                cve_list = nfr.plugin.report_item_values(plugin, 'cve')

                exploit_exists = False
                exploit_exists_debugging = False
                if exploitability_ease == 'No known exploits are available':
                    exploit_exists = False
                elif exploitability_ease == 'Exploits are available':
                    exploit_exists = True
                else:
                    # leaving this one here for potential debugging
                    exploit_exists_debugging = True

                if cve_list:
                    cve_text = '\n'.join([cve for cve in cve_list if cve])
                else:
                    cve_text = None

                lines = plugin_output.splitlines()
                installed_string = ["Remote package installed", "Remote version", "Installed package"]
                updated_string = ["Fixed package", "Should be"]
                for line in lines:
                    if any(in_str in line for in_str in installed_string):
                        currentver = line.split(":",1)
                    if any(in_str in line for in_str in updated_string):
                        latestver = line.split(":",1)
                        row = [report_fqdn,
                               report_ip,
                               risk_factor,
                               plugin_name,
                               currentver[-1].strip(),
                               latestver[-1].strip(),
                               exploit_exists,
                               cve_text]

                        df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

                        # leaving this one here for potential debugging
                        if exploit_exists_debugging:
                            print(f'ERROR - Unknown exploitability for Missing Microsoft Patch - Plugin: {plugin_name} - Host: {report_ip}')

    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, 'Missing Linux Patches', column_widths, style='severity', txtwrap=['CVE'])
        # print("INFO - Please text wrap column H within the Missing Linux Patches worksheet. Highlight column -> Home -> Wrap Text")

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Linux Patches. {len(df)} rows took {toc - tic:0.4f} seconds')

# Extract all open ports
def extractOpenPorts():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Protocol',
               'Port']
    column_widths = [40, 15, 10, 6]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        report_ip = nfr.host.resolved_ip(report_host)
        report_fqdn = Hosts[report_ip]

        report_items_per_host = nfr.host.report_items(report_host)
        for report_item in report_items_per_host:

            plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))

            # Unauth SYN, TCP & UDP + Auth SSH * Netstat plugin outputs
            if (plugin_id == 11219 or plugin_id == 34277 or plugin_id == 10335 or plugin_id == 14272 or plugin_id == 34220):
                protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                port = nfr.plugin.report_item_value(report_item, 'port')

                if (port != "0"):
                    # Write to Excel worksheet
                    row = [report_fqdn,
                           report_ip,
                           protocol,
                           port]
                    df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, 'Open Ports', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Open Ports. {len(df)} rows took {toc - tic:0.4f} seconds')

# Perform software audit on all Windows machines
def extractInstalledSoftware():
    tic = time.perf_counter()
    skip_this = [' - check Audit Trail',
                 ' - not enabled',
                 'Here is the list',
                 'The following']

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Installed Software']
    column_widths = [40, 15, 100]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        report_ip = nfr.host.resolved_ip(report_host)
        report_fqdn = Hosts[report_ip]

        # Windows (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall HKLM\SOFTWARE\Microsoft\Updates)
        plugin_20811 = nfr.plugin.plugin_output(root, report_host, '20811')

        if not re.match('[Cc]heck Audit Trail', plugin_20811):
            lines = plugin_20811.splitlines()
            for line in lines:
                kb_match = re.match(r"  KB\d[0-9]{5,8}", line)

                if line == '' or any(s in line for s in skip_this) or kb_match:
                    pass
                else:
                    # Write to Excel worksheet
                    row = [report_fqdn,
                           report_ip,
                           line.strip()]
                    df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

        # Linux (rpm -qa etc.)
        plugin_22869 = nfr.plugin.plugin_output(root, report_host, '22869')

        if not re.match('[Cc]heck Audit Trail', plugin_22869):
            lines = plugin_22869.splitlines()
            for line in lines:
                if line == '' or any(s in line for s in skip_this):
                    pass
                else:
                    # Write to Excel worksheet
                    row = [report_fqdn,
                           report_ip,
                           line.strip()]
                    df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, 'Installed Third Party Software', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Installed Third Party Software. {len(df)} rows took {toc - tic:0.4f} seconds')

# Extract all outdated software
def extractOutdatedSoftware():
    tic = time.perf_counter()

    # Column names
    columns = [ 'Hostname',
                'IP Address',
                'Severity',
                'Issue',
                'Exploit Available',
                'CVE',
                'Installed Version',
                'Latest Version',
                'Path',
                'End of Support Date' ]
    column_widths = [40, 15, 10, 100, 17, 14, 70, 55, 100, 20]

    # Creating an empty DataFrame with these columns
    df = pd.DataFrame(columns=columns)

    # No queries to pull out just outdated software plugins. So will go through each one and look for "Installed version"
    for report_host in nfr.scan.report_hosts(root):
        all_plugins = nfr.host.report_items(report_host)

        for plugin in all_plugins:
            # Remove all info and MS Patching issues
            risk_factor = nfr.plugin.report_item_value(plugin, 'risk_factor')
            plugin_family = nfr.plugin.report_item_value(plugin, 'pluginFamily')
            plugin_name = nfr.plugin.report_item_value(plugin, 'pluginName')

            if (risk_factor != 'None') and (plugin_family != 'Windows : Microsoft Bulletins') and not plugin_name.startswith('Security Updates for '):
                report_ip = nfr.host.resolved_ip(report_host)
                report_fqdn = Hosts[report_ip]
                plugin_id = int(nfr.plugin.report_item_value(plugin, 'pluginID'))
                plugin_output = nfr.plugin.plugin_outputs(root, report_host, plugin_id)
                exploitability_ease = nfr.plugin.report_item_value(plugin, 'exploitability_ease')
                cve_list = nfr.plugin.report_item_values(plugin, 'cve')

                if cve_list:
                    cve_text = '\n'.join([cve for cve in cve_list if cve])
                else:
                    cve_text = None

                # resetting all variables
                installed_version = None; latest_version = None; eol_date = None; installed_path = None

                exploit_exists = False
                exploit_exists_debugging = False
                if exploitability_ease == 'No known exploits are available':
                    exploit_exists = False
                elif exploitability_ease == 'Exploits are available':
                    exploit_exists = True
                # this is when a software is EoL (marked in line + 13)
                elif exploitability_ease is None:
                    exploit_exists = False
                else:
                    exploit_exists_debugging = True

                lines = plugin_output.splitlines()
                for idx, line in enumerate(lines):
                    if 'Installed version' in line or 'Channel version' in line or 'Product' in line or 'File Version' in line or 'DLL Version' in line or 'File version' in line:
                        installed_version = line.split(':',1)
                        installed_version = installed_version[-1].strip()
                    if 'Supported version' in line or 'Fixed version' in line or 'Minimum supported version' in line:
                        latest_version = line.split(':',1)
                        latest_version = latest_version[-1].strip()
                    if 'End of support' in line or 'Support ended' in line or 'EOL date' in line:
                        eol_date = line.split(':',1)
                        eol_date = eol_date[-1].strip()
                    if 'Path' in line or 'Filename' in line or 'Install Path' in line or 'URL' in line:
                        installed_path = line.split(':',1)
                        installed_path = installed_path[-1].strip()
                        # When a SW is enumerated remotely (web for instance) there is no Path info
                        installed_path = None if installed_path == '/' else installed_path

                    # Wait until we get to the last line of the plugin output before writing to Excel
                    if (idx == len(lines)-1) and (installed_version or latest_version or eol_date is not None):
                        if exploitability_ease is None and latest_version is None:
                            latest_version = 'End of Life'
                        row = [report_fqdn,
                               report_ip,
                               risk_factor,
                               plugin_name,
                               exploit_exists,
                               cve_text,
                               installed_version,
                               latest_version,
                               installed_path,
                               eol_date]
                        df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

                        # leaving this one here for potential debugging
                        if exploit_exists_debugging:
                            print(f'ERROR - Unknown exploitability for Missing Microsoft Patch - Plugin: {plugin_name} - Host: {report_ip}')

    if not df.empty:

        # Cleaning the table
        if not args.noclean:
            df = df.drop_duplicates()

            # define aggregation functions for each column
            # TODO: define a function for the repeated methods
            aggregations = {
                'Hostname': lambda x: next((i for i in reversed(x.tolist()) if i), None),   # Keep the first non-empty
                'Severity': lambda x: max(x, key=lambda s: severity_hierarchy[s]),          # Keep the highest severity
                'Issue': lambda x: ''.join(i for i in x.unique() if i),                     # Keep unique if not None
                'Exploit Available': lambda x: any(x),                                      # Logic gate OR
                'CVE': lambda x: '\n'.join(i for i in x.unique() if i),                     # Join with \n if not None
                'Latest Version': lambda x: ''.join(i for i in x.unique() if i),            # Keep unique if not None
                'End of Support Date': lambda x: ''.join(i for i in x.unique() if i)        # Keep unique if not None
            }
            df = df.groupby(['IP Address', 'Installed Version', 'Path'], as_index=False).agg(aggregations)
            df = df[columns]

        # Writing the DataFrame
        WriteDataFrame(df, 'Outdated Software', column_widths, style='severity', txtwrap=['CVE'])
        # print("INFO - Please text wrap column F within the Outdated Software worksheet. Highlight column -> Home -> Wrap Text")
        if args.noclean:
            print(f'INFO - Use "Remove Duplicates" on the Outdated Software worksheet if required. Can be found within the Data ribbon in Excel')

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Outdated Software. {len(df)} rows took {toc - tic:0.4f} seconds')

# Identify all unencrypted protcols in use
def extractUnencryptedProtocols():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Protocol',
               'Port',
               'Description']
    column_widths = [40, 15, 10, 6, 50]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        report_ip = nfr.host.resolved_ip(report_host)
        report_fqdn = Hosts[report_ip]

        report_items_per_host = nfr.host.report_items(report_host)
        for report_item in report_items_per_host:

            plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
            if (plugin_id == 10092 or plugin_id == 10281 or plugin_id == 54582 or plugin_id == 11819 or plugin_id == 35296
            or plugin_id == 87733 or plugin_id == 10203 or plugin_id == 10205 or plugin_id == 10061 or plugin_id == 10198
            or plugin_id == 10891 or plugin_id == 65792):
                unencrypted_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                unencrypted_port = nfr.plugin.report_item_value(report_item, 'port')
                unencrypted_description = nfr.plugin.report_item_value(report_item, 'plugin_name')

                # Write to Excel worksheet
                row = [report_fqdn,
                       report_ip,
                       unencrypted_protocol,
                       unencrypted_port,
                       unencrypted_description]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, 'Unencrypted Protocols', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Unencrypted Protocols. {len(df)} rows took {toc - tic:0.4f} seconds')

# Extract all unquoted service paths along with their service name
def extractUnquotedServicePaths():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Service Name',
               'Service Path',
               'Exploitability']
    column_widths = [40, 15, 40, 100, 14]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):

        plugin_63155 = nfr.plugin.plugin_outputs(root, report_host, '63155')
        if not re.findall(r'[Cc]heck [aA]udit [tT]rail', plugin_63155) and 'not enabled' not in plugin_63155:
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            lines = plugin_63155.splitlines()
            for line in lines:
                line.strip()

                if len(line) > 2 and 'Nessus found the following' not in line:
                    service,path = line.split(':',1)
                    # Write to Excel worksheet
                    if "C:\\Program Files".lower() in path.lower():
                        exploitability = 'Low'
                    else:
                        exploitability = 'High'
                    row = [report_fqdn,
                           report_ip,
                           service.strip(),
                           path.strip(),
                           exploitability]
                    df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, 'Unquoted Service Paths', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Unquoted Service Paths. {len(df)} rows took {toc - tic:0.4f} seconds')

# Identify all unsupported operating systems
def extractUnsupportedOperatingSystems():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Operating System',
               'End of Mainstream Support Date',
               'End of Extended Support Date',
               'End of Extended Security Updates (ESU / ESM) Date']
    column_widths = [40, 15, 55, 31, 29, 50]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        report_ip = nfr.host.resolved_ip(report_host)
        report_fqdn = Hosts[report_ip]
        report_host_os = nfr.host.detected_os(report_host)

        # TODO: check if this can land on more than one if
        # if not, convert to elif and a single pd.concat at the end
        if report_host_os is not None and report_host_os.count('\n') == 0:
            # https://docs.microsoft.com/en-gb/lifecycle/products/
            if 'Microsoft Windows 2000' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"30 June 2005","13 July 2010",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Microsoft Windows Server 2003' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"13 July 2010","14 July 2015",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Microsoft Windows Server 2008' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"13 January 2015","14 January 2020","10 January 2023"]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Microsoft Windows Server 2012' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"09 October 2018","10 October 2023","13 October 2026"]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Microsoft Windows XP' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"14 April 2009","08 April 2014",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Microsoft Windows Vista' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"10 April 2012","11 April 2017",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Microsoft Windows 7' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"13 January 2015","14 January 2020","10 January 2023"]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Microsoft Windows 8' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"","12 January 2016",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            # https://endoflife.date/   https://endoflife.software/
            if 'VMware ESXi 5.5' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"19 September 2015","19 September 2020",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'VMware ESXi 6.0' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"12 March 2018","12 March 2022",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Ubuntu 10.04' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"30 April 2015","",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Ubuntu 12.04' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"28 April 2017","",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Ubuntu 14.04' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"02 April 2019","","02 April 2024"]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Ubuntu 16.04' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"02 April 2021","","02 April 2026"]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'CentOS Linux 5' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"31 March 2017","",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'CentOS Linux release 6' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"10 May 2017","30 November 2020",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'CentOS Linux 8' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"31 December 2021","",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Debian 6' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"31 May 2015","29 February 2016",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Debian 7' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"26 April 2016","01 May 2018","31 December 2019"]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Debian 8' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"17 June 2018","30 June 2020","30 June 2022"]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'Debian 9' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"01 January 2020","30 June 2022",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            # https://www.freebsd.org/security/unsupported/
            if 'FreeBSD 9.' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"31 December 2016","",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'FreeBSD 10.' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"31 October 2018","",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
            if 'FreeBSD 11.' in report_host_os:
                row = [report_fqdn,report_ip,report_host_os,"30 September 2021","",""]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, 'Unsupported Operating Systems', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Unsupported Operating Systems. {len(df)} rows took {toc - tic:0.4f} seconds')

# Identify all Windows services with weak permissions
def extractWeakServicePermissions():
    tic = time.perf_counter()
    path = services = dirGroups = writeGroups = ''

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column width
    columns = ['Hostname',
               'IP Address',
               'Service Name',
               'Service Path',
               'User / Group with Write permissions',
               'User / Group with Full Control']
    column_widths = [40, 15, 50, 85, 35, 30]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        report_ip = nfr.host.resolved_ip(report_host)

        plugin_65057 = nfr.plugin.plugin_outputs(root, report_host, '65057')
        if not re.match('[Cc]heck Audit Trail', plugin_65057):
            report_fqdn = Hosts[report_ip]

            items = plugin_65057.split("\n\n")
            for item in items:
                lines = item.splitlines()

                for line in lines:
                    if ',' in line:
                        line=line.replace(',',' &')
                    if 'Path' in line:
                        path=line.replace('Path : ','')
                    if 'Used by services' in line:
                        services=line.replace('Used by services : ','')
                    if 'File write allowed' in line:
                        dirGroups= line.replace('File write allowed for groups : ','')
                    if 'Full control of directory' in line:
                        writeGroups= line.replace('Full control of directory allowed for groups : ','')

                # TODO: this produces empty columns - find out why and fix (migth be done with that if)
                if services and path:
                    # Write to Excel worksheet
                    row = [report_fqdn,
                           report_ip,
                           services,
                           path,
                           dirGroups,
                           writeGroups]
                    df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, 'Insecure Service Permissions', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Weak Service Permissions. {len(df)} rows took {toc - tic:0.4f} seconds')

# Extract all Weak Algorithms and Ciphers being used by SSH services
def extractWeakSSHAlgorithms():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Protocol',
               'Port',
               'Weak Encryption Algorithm',
               'Weak Key Exchange Algorithm',
               'Weak Cipher Block Chaining Cipher',
               'Weak Message Authentication Code Algorithm',
               'Password Authentication Accepted']
    column_widths = [40, 15, 10, 6, 27, 33, 33, 44, 33]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        # Initialize some variables
        enc_algorithms = []; keyex_algorithms = []; cbc_algorithms = []; mac_algorithms = []

        enc_plugin = nfr.plugin.plugin_outputs(root, report_host, '90317')
        keyex_plugin = nfr.plugin.plugin_outputs(root, report_host, '153953')
        cbc_plugin = nfr.plugin.plugin_outputs(root, report_host, '70658')
        mac_plugin = nfr.plugin.plugin_outputs(root, report_host, '71049')
        passwd_plugin = nfr.plugin.plugin_outputs(root, report_host, '149334')
        passwd_accepted = 'No'

        if not (re.match('[Cc]heck Audit Trail', enc_plugin)) or not (re.match('[Cc]heck Audit Trail', keyex_plugin)) or not (re.match('[Cc]heck Audit Trail', cbc_plugin)) or not (re.match('[Cc]heck Audit Trail', mac_plugin) or not (re.match('[Cc]heck Audit Trail', passwd_plugin))):
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            report_items_per_host = nfr.host.report_items(report_host)
            for report_item in report_items_per_host:

                plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
                # check enc, kek, cbc or mac 
                if plugin_id == 90317 or plugin_id == 153953 or plugin_id == 70658 or plugin_id == 71049 or plugin_id == 149334:
                    # Weak encryption ciphers
                    if plugin_id == 90317:

                        enc_output = enc_plugin.splitlines()
                        for enc_algorithm in enc_output:
                            if 'The following weak' not in enc_algorithm and not re.match('[Cc]heck Audit Trail', enc_algorithm) and len(enc_algorithm) != 0:
                                if enc_algorithm.strip() not in enc_algorithms:
                                    enc_algorithms.append(enc_algorithm.strip())

                    # Weak key exchange ciphers
                    if plugin_id == 153953:

                        keyex_output = keyex_plugin.splitlines()
                        for keyex_algorithm in keyex_output:
                            if 'The following weak key exchange' not in keyex_algorithm and not re.match('[Cc]heck Audit Trail', keyex_algorithm) and len(keyex_algorithm) != 0:
                                if keyex_algorithm.strip() not in keyex_algorithms:
                                    keyex_algorithms.append(keyex_algorithm.strip())

                    # Weak CBC ciphers
                    if plugin_id == 70658:

                        cbc_output = cbc_plugin.splitlines()
                        for cbc_algorithm in cbc_output:
                            if 'The following' not in cbc_algorithm and 'are supported :' not in cbc_algorithm and not re.match('[Cc]heck Audit Trail', cbc_algorithm) and len(cbc_algorithm) != 0:
                                if cbc_algorithm.strip() not in cbc_algorithms:
                                    cbc_algorithms.append(cbc_algorithm.strip())

                    # Weak MAC ciphers
                    if plugin_id == 71049:
                        mac_output = mac_plugin.splitlines()

                        for mac_algorithm in mac_output:
                            if 'The following' not in mac_algorithm and 'are supported :' not in mac_algorithm and not re.match('[Cc]heck Audit Trail', mac_algorithm) and len(mac_algorithm) != 0:
                                if mac_algorithm.strip() not in mac_algorithms:
                                    mac_algorithms.append(mac_algorithm.strip())

                    if plugin_id == 149334:
                        passwd_accepted = "Yes"

                    ssh_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                    ssh_port = nfr.plugin.report_item_value(report_item, 'port')

            ipComplete = False
            r = 0
            while ipComplete == False:
                if len(enc_algorithms) > r:
                    enc = enc_algorithms[r]
                else:
                    enc = ""
                if len(keyex_algorithms) > r:
                    kek = keyex_algorithms[r]
                else:
                    kek = ""
                if len(cbc_algorithms) > r:
                    cbc = cbc_algorithms[r]
                else:
                    cbc = ""
                if len(mac_algorithms) > r:
                    mac = mac_algorithms[r]
                else:
                    mac = ""
                if enc == "" and kek == "" and cbc == "" and mac == "":
                    ipComplete = True
                else:
                    row = [report_fqdn,
                           report_ip,
                           ssh_protocol,
                           ssh_port,
                           enc, kek,
                           cbc, mac,
                           passwd_accepted]
                    df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)
                    r += 1

    # Writing the DataFrame
    # TODO: this could also be enhanced with ssh-audit list ?
    # TODO: Aggregate columns E, F, G and H with lambda x: '\n'.join(i for i in x.unique() if i)
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()

            # define aggregation functions for each column
            # TODO: define a function for the repeated methods
            aggregations = {
                'Hostname': lambda x: next((i for i in reversed(x.tolist()) if i), None),                       # Keep the first non-empty
                'Weak Encryption Algorithm': lambda x: '\n'.join(i for i in x.unique() if i),                   # Concat with \n
                'Weak Key Exchange Algorithm': lambda x: '\n'.join(i for i in x.unique() if i),                 # Concat with \n
                'Weak Cipher Block Chaining Cipher': lambda x: '\n'.join(i for i in x.unique() if i),           # Concat with \n
                'Weak Message Authentication Code Algorithm': lambda x: '\n'.join(i for i in x.unique() if i),  # Concat with \n
                'Password Authentication Accepted': lambda x: next((i for i in reversed(x.tolist()) if i), None)# Keep the first non-empty
            }
            df = df.groupby(['IP Address', 'Protocol', 'Port'], as_index=False).agg(aggregations)
            df = df[columns]

        col_to_wrap = ['Weak Encryption Algorithm',
                       'Weak Key Exchange Algorithm',
                       'Weak Cipher Block Chaining Cipher',
                       'Weak Message Authentication Code Algorithm']
        WriteDataFrame(df, 'Weak SSH Algorithms', column_widths, txtwrap=col_to_wrap)
        # print(f'INFO - Please text wrap columns E,F,G,H within the Weak SSH Algorithms worksheet. Highlight column -> Home -> Wrap Text')

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Weak SSH Algorithms and Ciphers. {len(df)} rows took {toc - tic:0.4f} seconds')

def extractWeakRDP():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname', 'IP Address', 'Protocol', 'Port', 'NLA Enabled', 'MITM Weakness',
               'Weak Encryption Level', 'Not FIPS Compliant']
    column_widths = [30, 13, 10, 8, 15, 18, 22, 25]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        # Initialize variables for host
        finding_present = False
        rdp_nla_vuln = rdp_mitm_vuln = rdp_enc_value = rdp_fips_value = "-"
        report_ip = nfr.host.resolved_ip(report_host)
        report_fqdn = Hosts.get(report_ip, "-")

        report_items_per_host = nfr.host.report_items(report_host)
        for report_item in report_items_per_host:
            plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
            rdp_port_candidate = nfr.plugin.report_item_value(report_item, 'port')

            if rdp_port_candidate == "3389":
                # If we are dealing with the RDP port, update the protocol and port once
                rdp_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                rdp_port = rdp_port_candidate

                # Flag to check if at least one finding is present for the host
                if plugin_id in [58453, 18405, 57690, 30218]:
                    finding_present = True

                    if plugin_id == 58453:
                        rdp_nla_plugin = nfr.plugin.plugin_outputs(root, report_host, '58453')
                        if rdp_nla_plugin and not re.match('[Cc]heck Audit Trail', rdp_nla_plugin):
                            rdp_nla_vuln = "No"

                    if plugin_id == 18405:
                        rdp_mitm_plugin = nfr.plugin.plugin_outputs(root, report_host, '18405')
                        if rdp_mitm_plugin and not re.match('[Cc]heck Audit Trail', rdp_mitm_plugin):
                            rdp_mitm_vuln = "Yes"

                    if plugin_id == 57690:
                        rdp_enc_plugin = nfr.plugin.plugin_outputs(root, report_host, '57690')
                        if rdp_enc_plugin and not re.match('[Cc]heck Audit Trail', rdp_enc_plugin):
                            rdp_enc_value = rdp_enc_plugin.splitlines()[-1]

                    if plugin_id == 30218:
                        rdp_fips_plugin = nfr.plugin.plugin_outputs(root, report_host, '30218')
                        if rdp_fips_plugin and not re.match('[Cc]heck Audit Trail', rdp_fips_plugin):
                            rdp_fips_value = rdp_fips_plugin.splitlines()[-1]

        # After processing all report items for the host, add a single row to the DataFrame if finding present
        if finding_present:
            row = [report_fqdn, report_ip, rdp_protocol, rdp_port, rdp_nla_vuln, rdp_mitm_vuln, rdp_enc_value, rdp_fips_value]
            df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing the DataFrame
    if not df.empty:
        df = df.drop_duplicates(subset=['IP Address', 'Port'], keep='last')
        WriteDataFrame(df, 'Weak RDP', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f"DEBUG - Completed RDP. {len(df)} rows took {toc - tic:0.4f} seconds")


def extractWeakSMB():
    tic = time.perf_counter()

    columns = ['Hostname', 'IP Address', 'Protocol', 'Port', 'SMB Signing Enforced', 'SMBv1 Disabled']
    column_widths = [30, 13, 10, 8, 20, 17]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        # Initialize variables for host
        finding_present = False
        smb_signing_vuln = smb_v1_vuln = "Yes"
        report_ip = nfr.host.resolved_ip(report_host)
        report_fqdn = Hosts.get(report_ip, "-")

        report_items_per_host = nfr.host.report_items(report_host)
        for report_item in report_items_per_host:
            plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
            smb_port_candidate = nfr.plugin.report_item_value(report_item, 'port')

            if smb_port_candidate == "445":
                # If we are dealing with SMB, update the protocol and port once
                smb_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                smb_port = smb_port_candidate

                # Flag to check if at least one finding is present for the host
                if plugin_id in [57608, 96982]:
                    finding_present = True

                    if plugin_id == 57608:
                        smb_signing_plugin = nfr.plugin.plugin_outputs(root, report_host, '57608')
                        if smb_signing_plugin and not re.match('[Cc]heck Audit Trail', smb_signing_plugin):
                            smb_signing_vuln = "No"

                    if plugin_id == 96982:
                        smb_v1_plugin = nfr.plugin.plugin_outputs(root, report_host, '96982')
                        if smb_v1_plugin and not re.match('[Cc]heck Audit Trail', smb_v1_plugin):
                            smb_v1_vuln = "No"

        # After processing all report items for the host, add a single row to the DataFrame if finding present
        if finding_present:
            row = [report_fqdn, report_ip, smb_protocol, smb_port, smb_signing_vuln, smb_v1_vuln]
            df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing the DataFrame
    if not df.empty:
        df = df.drop_duplicates(subset=['IP Address', 'Port'], keep='last')
        WriteDataFrame(df, 'Weak SMB', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f"DEBUG - Completed SMB. {len(df)} rows took {toc - tic:0.4f} seconds")

# Extract list of hosts in which Cred Patch was Possible/Successful
def extractCredPatch():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Operating System',
               'Plugin']
    column_widths = [40, 15, 60, 15]
    df = pd.DataFrame(columns=columns)

    for report_host in nfr.scan.report_hosts(root):
        report_items_per_host = nfr.host.report_items(report_host)

        plugin_ids = [int(nfr.plugin.report_item_value(report_item, 'pluginID')) for report_item in report_items_per_host]

        # Apparently there is no single plugin that can tell us this >.>
        unix_cred_patch_plugins = [
            141118,     # Target Credential Status by Authentication Protocol - Valid Credentials Provided
            97993,      # OS Identification and Installed Software Enumeration over SSH v2 (Using New SSH Library)
            152742      # Unix Software Discovery Commands Available
        ]

        # Filtering pluign "WMI Available"
        if 24269 in plugin_ids:
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]
            report_host_os = nfr.host.detected_os(report_host)

            if (report_host_os is None or report_host_os.count('\n') > 0):
                report_host_os = ""

            row = [report_fqdn,
                   report_ip,
                   report_host_os,
                   'WMI Available (Windows CredPatch)']
            df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

        elif bool(set(unix_cred_patch_plugins) & set(plugin_ids)):
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]
            report_host_os = nfr.host.detected_os(report_host)

            if (report_host_os is None or report_host_os.count('\n') > 0):
                report_host_os = ""

            row = [report_fqdn,
                   report_ip,
                   report_host_os,
                   'Authenticated Patch Report Available (Linux CredPatch)']
            df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, 'CredPatch Hosts', column_widths)

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed WMI Available. {len(df)} rows took {toc - tic:0.4f} seconds')


# Extract all TLS issue
def extractTLSWeaknesses():
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Protocol',
               'Port',
               'SSL Certificate Cannot Be Trusted',
               'SSL Certificate Expiry',
               'SSL Self-Signed Certificate',
               'Certificate chain keys less than 2048 bits in lengt',
               'NULL ciphers suites accepte',
               'Anonymous cipher suites accepted',
               'Weak strength ciphers accepted',
               'RC4 cipher suites accepted',
               'Plaintext injection (insecure renegotiation)',
               'Susceptibility to Heartbleed attack (insufficient patching)',
               'Susceptibility to CRIME attack (HTTP compression)',
               'Susceptibility BEAST attack (CBC ciphers)',
               'Change Cipher Spec Injection (insufficient patching)',
               'Susceptibility to SSL POODLE attack (SSL 3.0 enabled)',
               'Susceptibility to TLS POODLE attack (insufficient patching)',
               'Susceptibility to DROWN attack (SSL 2.0 enabled)',
               'Susceptibility to FREAK attack (export grade RSA keys)',
               'OpenSSL Padding Oracle Attack',
               'Susceptibility to SWEET32 attack (supports 64 bit block ciphers)',
               'Susceptibility to LOGJAM attack (weak DH key exchange supported)',
               'Certificate signed with a weak hashing algorithm',
               'Susceptibility to LUCKY13 attack (supports CBC encryption cipher suites)',
               'Protocols with known weaknesses allowed']

    column_widths = [40, 15, 10, 6, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25]
    df = pd.DataFrame(columns=columns)

    # match the plugin ID with the row[] column index to modify
    plugins = {'51192': 4,  # 'SSL Certificate Cannot Be Trusted',
               '15901': 5,  # 'SSL Certificate Expiry',
               '57582': 6,  # 'SSL Self-Signed Certificate',
               '69551': 7,  # 'Certificate chain keys less than 2048 bits in lenght',
               '66848': 8,  # 'NULL ciphers suites accepted',
               '31705': 9,  # 'Anonymous cipher suites accepted',
               '26928': 10,  # 'Weak strength ciphers accepted',
               '65821': 11,  # 'RC4 cipher suites accepted',
               '42880': 12,  # 'Plaintext injection (insecure renegotiation)',
               '73412': 13,  # 'Susceptibility to Heartbleed attack (insufficient patching)',
               '62565': 14,  # 'Susceptibility to CRIME attack (HTTP compression)',
               '58751': 15,  # 'Susceptibility BEAST attack (CBC ciphers)',
               '74326': 16,  # 'Change Cipher Spec Injection (insufficient patching)',
               '78479': 17,  # 'Susceptibility to SSL POODLE attack (SSL 3.0 enabled)',
               '80035': 18,  # 'Susceptibility to TLS POODLE attack (insufficient patching)',
               '89058': 19,  # 'Susceptibility to DROWN attack (SSL 2.0 enabled)',
               '81606': 20,  # 'Susceptibility to FREAK attack (export grade RSA keys)',
               '91572': 21,  # 'OpenSSL Padding Oracle Attack',
               '42873': 22,  # 'Susceptibility to SWEET32 attack (supports 64 bit block ciphers)',
               '94437': 22,  # 'Susceptibility to SWEET32 attack (supports 64 bit block ciphers)',
               '83875': 23,  # 'Susceptibility to LOGJAM attack (weak DH key exchange supported)',
               '95631': 24,  # 'Certificate signed with a weak hashing algorithm',
               '70544': 25,  # 'Susceptibility to LUCKY13 attack (supports CBC encryption cipher suites)',
               '20007': 26,  # 'Protocols with known weaknesses allowed',
               '104743': 26}  # 'Protocols with known weaknesses allowed'

    # this will be used to store all issues
    host_dict = {}
    for report_host in nfr.scan.report_hosts(root):
        report_ip = nfr.host.resolved_ip(report_host)


        report_items_per_host = nfr.host.report_items(report_host)
        for report_item in report_items_per_host:

            plugin_id = str(nfr.plugin.report_item_value(report_item, 'pluginID'))
            if plugin_id in plugins:
                row = [None] * len(columns)
                # mark it as vulnerable
                row[ plugins[plugin_id] ] = 'r'
                report_fqdn = Hosts[report_ip]
                report_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                report_port = nfr.plugin.report_item_value(report_item, 'port')

                # mark all the 0s as not vulnerable
                row = [value if value is not None else 'a' for value in row]

                # add the host info
                row[0] = report_fqdn
                row[1] = report_ip
                row[2] = report_protocol
                row[3] = report_port

                # add the row
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)


    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()

            # congregate all findings
            # define aggregation functions for each column
            # TODO: define a function for the repeated methods
            aggregations = {
                'Hostname': lambda x: next((i for i in reversed(x.tolist()) if i), None),  # Keep the first non-empty
            }
            exclude_columns = ['IP Address', 'Protocol', 'Port', 'Hostname']

            # Apply a default aggregation logic to all other columns
            # This is used to keep the vulnerable mark
            for column in df.columns:
                if column not in exclude_columns:
                    aggregations[column] = lambda x: 'r' if 'r' in x.values else 'a'

            df = df.groupby(['IP Address', 'Protocol', 'Port'], as_index=False).agg(aggregations)
            df = df[columns]

            # drop all columns that has no issues
            df = df.drop(columns=[col for col in df if (df[col] == 'a').all()])

        WriteDataFrame(df, 'TLS Issues', column_widths[:len(df.columns)], style='tls')

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed TLS Issues. {len(df)} rows took {toc - tic:0.4f} seconds')

# Search plugins by keyword to pull out all relevant info
def searchPlugins(keyword):
    tic = time.perf_counter()

    # Create DataFrame. Xlswriter doesn't support autofit so best guess for column widths
    columns = ['Hostname',
               'IP Address',
               'Plugin Name',
               'Plugin Output']
    column_widths = [40, 15, 110, 180]
    df = pd.DataFrame(columns=columns)

    # Enumerate through all plugin names and see if keyword is present
    for report_host in nfr.scan.report_hosts(root):
        all_plugins = nfr.host.report_items(report_host)

        for plugin in all_plugins:
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]
            plugin_id = nfr.plugin.report_item_value(plugin, 'pluginID')
            plugin_name = nfr.plugin.report_item_value(plugin, 'pluginName')

            if keyword.lower() in plugin_name.lower():
                output = nfr.plugin.plugin_output(root, report_host, plugin_id)

                row = [report_fqdn,
                       report_ip,
                       plugin_name,
                       output.strip()]
                df = pd.concat([df, pd.DataFrame([row], columns=columns)], ignore_index=True)

    # Writing the DataFrame
    if not df.empty:
        if not args.noclean:
            df = df.drop_duplicates()
        WriteDataFrame(df, f'{keyword} Search Results', column_widths, txtwrap=['Plugin Output'])
        # print(f'INFO - Please text wrap column D within the {keyword} Search Results worksheet. Highlight column -> Home -> Wrap Text')

    toc = time.perf_counter()
    if args.verbose:
        print(f'DEBUG - Completed Plugin Search. {len(df)} rows took {toc - tic:0.4f} seconds')

#--------------------------------------------------------------------------------
# Common Nessus Functions
def GenerateHostDictionary():
    tic = time.perf_counter()

    for report_host in nfr.scan.report_hosts(root):
        # If Nessus can't resolve the hostname get it from other plugins
        report_fqdn = nfr.host.resolved_fqdn(report_host)

        plugin_10785 = nfr.plugin.plugin_outputs(root, report_host, '10785')
        plugin_55472 = nfr.plugin.plugin_outputs(root, report_host, '55472')

        if report_fqdn is None:
            # First try FQDN from NativeLanManager plugin
            if not re.match('[Cc]heck Audit Trail', plugin_10785):
                lines = plugin_10785.splitlines()
                for line in lines:
                    if 'DNS Computer Name' in line:
                        report_fqdn = line.split(':', 1)
                        report_fqdn = report_fqdn[-1].strip()

        if report_fqdn is None:
            # Then try hostname plugin
            if not re.match('[Cc]heck Audit Trail', plugin_55472):
                lines = plugin_55472.splitlines()
                for line in lines:
                    if 'Hostname' in line:
                        report_fqdn = line.split(':', 1)
                        report_fqdn = report_fqdn[-1].strip()

        if report_fqdn is None:
            # If we still haven't obtained hostname, use placeholder
            report_fqdn = None

        report_ip = nfr.host.resolved_ip(report_host)
        if report_ip not in Hosts or (report_fqdn and not Hosts[report_ip]):
            # Set the key value only if the key does not exist
            # or if report_fqdn is non-empty and Hosts[report_ip] is currently empty
            Hosts[report_ip] = report_fqdn

    toc = time.perf_counter()

    if len(Hosts) < 1:
            print('ERROR - No Hosts Found! Exiting..')
            exit()
    else:
        if args.verbose:
            print(f'DEBUG - Hosts List Generated. {len(Hosts)} rows took {toc - tic:0.4f} seconds')

def CreateExcelWriter(workBookName):
    excel_writer = pd.ExcelWriter(args.out, engine='xlsxwriter')

    if args.verbose:
        print(f'DEBUG - Using Excel output file: {workBookName}')

    return excel_writer

def WriteDataFrame(dataframe, sheet_name, column_widths, style=None, txtwrap=[]):
    # https://xlsxwriter.readthedocs.io/worksheet.html
    ### dataframe.to_excel(excelWriter, sheet_name=sheet_name, index=False, na_rep='N.A')
    dataframe.to_excel(excelWriter, sheet_name=sheet_name, startrow=1, header=False, index=False, na_rep='N.A')

    # Get the xlsxwriter workbook and worksheet objects
    excel_book = excelWriter.book
    # Access the xlsxwriter workbook and worksheet objects
    worksheet = excelWriter.sheets[sheet_name]

    # Get the dimensions of the dataframe and specific columns
    max_row, max_col = dataframe.shape
    result_col_index = dataframe.columns.get_loc('Result') if 'Result' in dataframe.columns else None
    severity_col_index = dataframe.columns.get_loc('Severity') if 'Severity' in dataframe.columns else None
    txtwrap_cols_indices = [dataframe.columns.get_loc(col) for col in txtwrap if col in dataframe.columns]

    # Create a list of column headers, to use in add_table().
    column_settings = [{'header': column} for column in dataframe.columns]

    # Add the Excel table structure. Pandas will add the data.
    worksheet.add_table(0, 0, max_row, max_col - 1, {'columns': column_settings, 'style': None})

    # Set the column widths
    for i, width in enumerate(column_widths):
        worksheet.set_column(i, i, width)

    ### Setting up all styles ###
    # Grabbing default style if specified
    additional_style = False
    if additional_config and 'STYLE' in additional_config:
        try:
            additional_style = True
            style_conf = additional_config['STYLE']

            header_format = excel_book.add_format({
                'bg_color': style_conf['head_bg_color'],
                'font_color': style_conf['head_font_color'],
                'border_color': style_conf['border_color'],
                'border': 1
            })
            rows_format_dict = {
                'bg_color': style_conf['bg_color'],
                'font_color': style_conf['font_color'],
                'border_color': style_conf['border_color'],
                'border': 1
            }
            rows_format = excel_book.add_format(rows_format_dict)

            # Updating the formats starting from the base Style for all various styles - python 3.9+
            txtwrap_format = excel_book.add_format(rows_format_dict | {'text_wrap': True, 'valign': 'top'})
            # Formats for CIS results
            good_format = excel_book.add_format(rows_format_dict | {'bg_color': '#C6EFCE', 'font_color': '#006100'})
            bad_format = excel_book.add_format(rows_format_dict | {'bg_color': '#FFC7CE', 'font_color': '#9C0006'})
            neutral_format = excel_book.add_format(rows_format_dict | {'bg_color': '#FFEB9C', 'font_color': '#9C6500'})
            # Formats for severity
            low_format = excel_book.add_format(rows_format_dict | {'bg_color': '#ffff00'})
            medium_format = excel_book.add_format(rows_format_dict | {'bg_color': '#f79646'})
            high_format = excel_book.add_format(rows_format_dict | {'bg_color': '#ff0000'})
            critical_format = excel_book.add_format(rows_format_dict | {'bg_color': '#954eca'})
            # Formats for TLS issues
            tls_medium_format = excel_book.add_format(rows_format_dict | {'bg_color': '#f79646', 'align': 'center', 'font_name': 'Webdings'})
            tls_good_format = excel_book.add_format(rows_format_dict | {'bg_color': '#92d050', 'align': 'center', 'font_name': 'Webdings'})
            # Format for bool
            bool_format = excel_book.add_format(rows_format_dict | {'align': 'center'})

            # Apply header_format to the header row
            for col_num in range(max_col):
                worksheet.write(0, col_num, dataframe.columns[col_num], header_format)

        except Exception as e:
            additional_style = False
            print(f'ERROR - {e}. Error in additional style supplied. Style won\'t be used')

    else:
        txtwrap_format = excel_book.add_format({'text_wrap': True, 'valign': 'top'})
        # Formats for CIS results
        good_format = excel_book.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100'})
        bad_format = excel_book.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})
        neutral_format = excel_book.add_format({'bg_color': '#FFEB9C', 'font_color': '#9C6500'})
        # Formats for severity
        low_format = excel_book.add_format({'bg_color': '#ffff00'})
        medium_format = excel_book.add_format({'bg_color': '#f79646'})
        high_format = excel_book.add_format({'bg_color': '#ff0000'})
        critical_format = excel_book.add_format({'bg_color': '#954eca'})
        # Formats for TLS issues
        tls_medium_format = excel_book.add_format({'bg_color': '#f79646', 'align': 'center', 'font_name': 'Webdings'})
        tls_good_format = excel_book.add_format({'bg_color': '#92d050', 'align': 'center', 'font_name': 'Webdings'})
        # Format for bool
        bool_format = excel_book.add_format({'align': 'center'})

    # One main loop
    if style or txtwrap or additional_style:
        for row_num in range(max_row):
            for col_num in range(max_col):

                # Default style to use (None if not specified)
                if additional_style:
                    format_to_apply = rows_format
                else:
                    format_to_apply = {}

                cell_value = dataframe.iloc[row_num, col_num]
                # Need to do some manual checking
                if pd.isna(cell_value):
                    cell_value = 'N.A'

                # Apply text wrapping if needed
                if col_num in txtwrap_cols_indices:
                    format_to_apply = txtwrap_format

                # Yes, I don't really want to talk about this next check
                # and how long it took me to find out panda is using numpy.bool_ instead of bool
                if isinstance(cell_value, bool) or pd.api.types.is_bool_dtype(cell_value):
                    format_to_apply = bool_format
                    if cell_value == True:
                        cell_value = 'TRUE'
                    elif cell_value == False:
                        cell_value = 'FALSE'

                # Conditional formatting based on style
                if style == 'compliance' and col_num == result_col_index:
                    if cell_value == 'FAILED':
                        format_to_apply = bad_format
                    elif cell_value == 'PASSED':
                        format_to_apply = good_format
                    elif cell_value == 'WARNING':
                        format_to_apply = neutral_format

                elif style == 'severity' and col_num == severity_col_index:
                    if cell_value == 'Critical':
                        format_to_apply = critical_format
                    elif cell_value == 'High':
                        format_to_apply = high_format
                    elif cell_value == 'Medium':
                        format_to_apply = medium_format
                    elif cell_value == 'Low':
                        format_to_apply = low_format

                elif style == 'tls':
                    # Specific TLS formatting based on cell value
                    if cell_value == 'a':
                        format_to_apply = tls_good_format
                    elif cell_value == 'r':
                        format_to_apply = tls_medium_format

                # Write the cell with the determined format
                worksheet.write(row_num + 1, col_num, cell_value, format_to_apply)

    # TLS additional actions if required
    if style == 'tls' and additional_config and 'TLS' in additional_config:
        if args.verbose:
            print(f'DEBUG - Listing TLS  in text file: {args.out[:-5] + "_TLS_Issues.txt"}')
        with open(args.out[:-5] + '_TLS_Issues.txt', 'a+') as fw:
            for column_title in dataframe:
                if column_title in additional_config["TLS"]:
                    fw.write(f'{column_title}: {additional_config["TLS"][column_title]}\n')

def CloseExcelWriter(writer):
    writer.close()

# -------------------------------------------------------------------------------
# Argparser to handle the usage / argument handling
parser = argparse.ArgumentParser(description='''Extract useful information out of .nessus files into Excel

nessusToExcel.py --verbose --file report.nessus --module unsupported,hosts,software --out companyName
nessusToExcel.py -f client.nessus -q -m hosts,search -k "Log4j"''', formatter_class=argparse.RawTextHelpFormatter)

# Arguments
parser.add_argument('--file', '-f', required=True, help='.nessus file to extract from')
parser.add_argument('--verbose', '-v', action='store_true', help='Increase output verbosity')
parser.add_argument('--out', '-o', required=False, help='Name of resulting Excel workbook. (Does not need extention, default name based on input file)')
parser.add_argument('--quiet', '-q', action='store_true', help='Accept defaults during execution')
parser.add_argument('--keyword', '-k', required=False, help='Extract all information relating to this word')
parser.add_argument('--noclean', '-n', required=False, action='store_true', help='Do not remove duplicates and merge columns in outdatedsoftware')
# parser.add_argument('--nostyle', '-s', required=False, action='store_true', help='Do not apply any style')
parser.add_argument('--module', '-m', type=str, default='all',
help=textwrap.dedent('''Comma seperated list of what data you want to extract:
all              = Default
compliance       = Format CIS Compliance output
databases        = Audit of all identified databases 
defaulthttp      = Web servers with default content
hosts            = Host information (also comes in .txt file)
http             = Identify all HTTP servers and their versions
issues           = Present all non-info issues
lastupdated      = View all Windows host security patch levels
nixpatches       = Missing *nix security patches
outdatedsoftware = Outdated third party software 
ports            = All identified open ports
services         = Insecure Services and their weak permissions
search           = Extract all information based on keyword e.g. "Log4j" (Requires --keyword / -k flag)
software         = Enumerate all installed software
ssh              = Identify all weak SSH algorithms and ciphers in use
rdp              = Identify all weak RDP settings. NLA, weak encryption cipher etc
smb              = Identify all weak SMB settings. Signing not enforced, version 1 enabled etc
unencrypted      = Unencrypted protocols in use. FTP, Telnet etc.
unquoted         = Unquoted service paths and their weak permissions
unsupported      = Unsupported operating systems
winpatches       = Missing Microsoft security patches
credpatch        = Extract all hosts that had a Cred Patch audit done
tls              = Extract TlS issue
'''))

# Keep a timer to keep an eye on performance
tic = time.perf_counter()

args = parser.parse_args()
if args.verbose:
    print(f'DEBUG - Arguments provided: {args}')

# If a valid .nessus file has been provided, create our Excel workbook based on its name
if not args.out:
    args.out = f'{args.file.rsplit(".",1)[0]}.xlsx'
    if args.verbose:
        print(f'DEBUG - No output filename given, new value: {args.out}')
else:
    if not args.out.endswith('.xlsx'):
        args.out = f'{args.out}.xlsx'
        if args.verbose:
            print(f'DEBUG - Output file does not contain extension, new value: {args.out}')
    else:
        if args.verbose:
            print(f'DEBUG - Fully qualified output name given: {args.out}')

# Check if the output files exist and are writable
try:
    if os.path.exists(args.out):
        with open(args.out, 'a') as open_excel:
            if not args.quiet:
                excel_answer = input(f'WARN - {args.out} is about to be overwritten, would you like to continue? [Y/n] ')
                if excel_answer.lower() == 'n' or excel_answer.lower() == 'no':
                    exit(0)
    if os.path.exists("Host Information.txt"):
        with open("Host Information.txt", "a") as open_txt:
            if not args.quiet:
                host_answer = input("WARN - Host Information.txt is about to be overwritten, would you like to continue? [Y/n] ")
                if host_answer.lower() == 'n' or host_answer.lower() == 'no':
                    exit(0)
except IOError as e:
    print(f'ERROR - {e}. Please close file before trying again')
    exit(1)

# Create our Excel workbook
excelWriter = CreateExcelWriter(args.out)

# Split out comma separated modules
argvars = vars(parser.parse_args())
argvars['module'] = [mod.strip() for mod in argvars['module'].split(",")]

# Need to refactor xml tags if working with compliance data first to assist with parsing
if 'compliance' in argvars['module'] or "all" in args.module:

    # Will ask user if they would like to take a backup of the Nessus file first as we are manipulating it
    backup_file = re.sub(r'\.nessus$', '_BACKUP.nessus', args.file)
    backupPath = os.getcwd() + os.sep + f'{backup_file}'
    if not os.path.isfile(backupPath):
        if args.quiet:
            if args.verbose:
                print(f'DEBUG - Taking backup of Nessus file - {backup_file}')

            shutil.copyfile(args.file, f'{backup_file}')
        else:
            comp_answer = input("To extract compliance output, changes to XML tags are required. While this should not cause any further issues, would you like to take a backup of your Nessus file first? [Y/n] ")
            if comp_answer == 'Y' or comp_answer == 'Yes' or comp_answer == 'y' or comp_answer == 'yes' or comp_answer == '':
                if args.verbose:
                    print(f'DEBUG - Taking backup of Nessus file - {backup_file}')

                shutil.copyfile(args.file, f'{backup_file}')
    else:
        if args.verbose:
            print(f'DEBUG - Nessus backup file already exists, continuing')

    # nfr could not handle the cm namespace within the compliance results. Once these are removed extraction has no issues
    search_text = "cm:compliance-"
    replace_text = "compliance-"

    with open(args.file, 'r', encoding="utf-8") as file:
        data = file.read()
        data = data.replace(search_text, replace_text)

    with open(args.file, 'w', encoding="utf-8") as file:
        file.write(data)

# Read XML and generate hosts list once
try:
    root = nfr.file.nessus_scan_file_root_element(args.file)
    GenerateHostDictionary()
except ParseError:
    print("ERROR - Invalid nessus format file chosen, please try again.")
    exit(1)

# Check which modules have been requested
if "all" in args.module:
    if args.verbose:
        print(f'DEBUG - Running all modules')
    extractAll()
else:
    if args.verbose:
        print(f'DEBUG - Modules selected: {(argvars["module"])}')

    for module in argvars["module"]:
        if 'compliance' == module.lower():
            extractCompliance() ; continue
        if 'databases' == module.lower():
            extractDatabases() ; continue
        if 'defaulthttp' == module.lower():
            extractDefaultHTTP() ; continue
        if 'hosts' == module.lower():
            extractHosts() ; continue
        if 'http' == module.lower():
            extractHTTPServers() ; continue
        if 'issues' == module.lower():
            extractIssues() ; continue
        if 'lastupdated' == module.lower():
            extractLastUpdated() ; continue
        if 'nixpatches' == module.lower():
            extractLinuxPatches() ; continue
        if 'outdatedsoftware' == module.lower():
            extractOutdatedSoftware() ; continue
        if 'ports' == module.lower():
            extractOpenPorts() ; continue
        if 'services' == module.lower():
            extractWeakServicePermissions() ; continue
        if 'software' == module.lower():
            extractInstalledSoftware() ; continue
        if 'ssh' == module.lower():
            extractWeakSSHAlgorithms() ; continue
        if 'rdp' == module.lower():
            extractWeakRDP() ; continue
        if 'smb' == module.lower():
            extractWeakSMB() ; continue
        if 'unencrypted' == module.lower():
            extractUnencryptedProtocols() ; continue
        if 'unquoted' == module.lower():
            extractUnquotedServicePaths() ; continue
        if 'unsupported' == module.lower():
            extractUnsupportedOperatingSystems() ; continue
        if 'winpatches' == module.lower():
            extractMSPatches() ; continue
        if 'search' == module.lower():
            if (args.keyword is not None):
                searchPlugins(args.keyword); continue
            else:
                raise ValueError("Search module requires a keyword")
        if 'credpatch' == module.lower():
            extractCredPatch(); continue
        if 'tls' == module.lower():
            extractTLSWeaknesses(); continue

        print(f'WARN - provided module "{module}" is invalid. Omitting')

toc = time.perf_counter()
print(f'COMPLETED! Output can be found in {os.path.join(args.out)} Total time taken: {toc - tic:0.4f} seconds')
CloseExcelWriter(excelWriter)

exit()
