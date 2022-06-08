#!/usr/bin/python3
import os, re, io, argparse, errno, shutil, string, time, textwrap, xlsxwriter
import nessus_file_reader as nfr

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

# STANDARDS
# Columns order - Hostname / IP Address / Other (Except for hosts which will be in reporter format of IP / Hostname / OS)
# Columns width - Hostname = 40 / IP Address = 15 / Operating System = 40 / Protocol = 10 / Port = 6 / Other = variable
# Long Date format - 01 January 1970 - 31 December 2049

# Globals hosts dictionary to lookup host information by report_host
Hosts = {}
root = ""

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
    extractRemediations()
    extractInstalledSoftware()
    extractUnencryptedProtocols()
    extractUnquotedServicePaths()
    extractUnsupportedOperatingSystems()
    extractWeakServicePermissions()
    extractWeakSSHAlgorithms()

# Extract system information
def extractHosts():
    tic = time.perf_counter()
    
    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('IP Address',15))
    columns.append(('Hostname',40))
    columns.append(('Operating System',60))

    tableData = []
    
    with open("Host Information.txt", "a") as txt_file:
        
        for report_host in nfr.scan.report_hosts(root):
            report_ip = nfr.host.resolved_ip(report_host)
            report_host_os = nfr.host.detected_os(report_host)
            report_fqdn = Hosts[report_ip]

            if (report_host_os is None or report_host_os.count('\n') > 0):
                report_host_os = ""

            # Write to txt
            print(f'{report_ip} {report_fqdn} {report_host_os}', file=txt_file)

            # Write to Excel worksheet
            tableData.append((report_ip,report_fqdn,report_host_os))
    
    if len(tableData) > 0:
        HostsWorksheet = CreateWorksheet(workbook,'Host Information')
        CreateSheetTable(columns,HostsWorksheet)
        AddTableData(tableData,HostsWorksheet)

    toc = time.perf_counter()
    if args.verbose:
            print (f'DEBUG - Completed Host Information. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Extract all non-informational issues
def extractIssues():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Protocol',10))
    columns.append(('Port',6))
    columns.append(('Risk',8))
    columns.append(('Issue',100))
    columns.append(('Reporter Issue',30))

    tableData = []

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
                tableData.append((report_fqdn,report_ip,issue_protocol,issue_port,risk_factor,issue_description))
    
    if len(tableData) > 0:
        IssuesWorksheet = CreateWorksheet(workbook,'All Issues')
        CreateSheetTable(columns,IssuesWorksheet)
        AddTableData(tableData,IssuesWorksheet)

    toc = time.perf_counter()
    if args.verbose:
            print (f'DEBUG - Completed Issues. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Extract and format CIS Compliance results
def extractCompliance():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('CIS Benchmark ID',17))
    columns.append(('Result',8))
    columns.append(('Assessed Host value',55))
    columns.append(('CIS Policy value',55))
    columns.append(('Description',200))

    tableData = []

    for report_host in nfr.scan.report_hosts(root):
        report_ip = nfr.host.resolved_ip(report_host)
        report_fqdn = Hosts[report_ip]

        report_items_per_host = nfr.host.report_items(report_host)
        for report_item in report_items_per_host:
            
            plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
            if plugin_id == 21156:
                compliance_host_value = nfr.plugin.report_item_value(report_item, 'compliance-actual-value')
                compliance_policy_value = nfr.plugin.report_item_value(report_item, 'compliance-policy-value')
                compliance_desc = nfr.plugin.report_item_value(report_item, 'compliance-check-name')
                compliance_result = nfr.plugin.report_item_value(report_item, 'compliance-result')

                compliance_id,compliance_name = compliance_desc.split(' ',1)

                # Write to Excel worksheet
                tableData.append((report_fqdn,report_ip,compliance_id,compliance_result,compliance_host_value,compliance_policy_value,compliance_name))

    if len(tableData) > 0:
        ComplianceWorksheet = CreateWorksheet(workbook,'Compliance')
        CreateSheetTable(columns,ComplianceWorksheet)
        AddTableData(tableData,ComplianceWorksheet)
        
    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Compliance. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Provide database asset audit and include end of life dates. TODO - This module is taking significantly longer than the rest
def extractDatabases():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Protocol',10))
    columns.append(('Port',6))
    columns.append(('Database Type',20))
    columns.append(('Version',12))
    columns.append(('MSSQL Instance Name',22))
    columns.append(('End of Life Date',16))

    tableData = []
    mssql_version = ["",""]; mssql_instance = ["",""];  
    mssql_eol = ""

    for report_host in nfr.scan.report_hosts(root):
        mssql_plugin = nfr.plugin.plugin_outputs(root, report_host, '10144')
        auth_mssql_plugin = nfr.plugin.plugin_outputs(root, report_host, '11217')
        mysql_plugin = nfr.plugin.plugin_outputs(root, report_host, '10719')
        postgres_plugin = nfr.plugin.plugin_outputs(root, report_host, '26024')
        oracle_plugin = nfr.plugin.plugin_outputs(root, report_host, '22073')
        mongo_plugin = nfr.plugin.plugin_outputs(root, report_host, '65914')

        # Microsoft SQL Server
        if ('Check Audit Trail' not in mssql_plugin) or ('Check Audit Trail' not in auth_mssql_plugin):
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]
                    
            report_items_per_host = nfr.host.report_items(report_host)
            for report_item in report_items_per_host:
                
                plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
                if (plugin_id == 11217) or (plugin_id == 10144):
                    # Auth
                    if plugin_id == 11217: 
                        lines = auth_mssql_plugin.splitlines()
                        mssql_port = '1433'
                    # Unauth
                    if (plugin_id == 10144): 
                        lines = mssql_plugin.splitlines()
                        mssql_port = nfr.plugin.report_item_value(report_item, 'port')
                    
                    for line in lines:
                        if 'Version             :' in line:
                            mssql_version = line.split()
                            if '10' in line:
                                mssql_eol = "09 July 2019"
                            if '11' in line:
                                mssql_eol = "12 July 2022"
                        if 'Instance' in line:
                            mssql_instance = line.split()

                    mssql_protocol = nfr.plugin.report_item_value(report_item, 'protocol')

                    # Write to Excel worksheet
                    tableData.append((report_fqdn,report_ip,mssql_protocol,mssql_port,"Microsoft SQL Server",mssql_version[2],mssql_instance[-1],mssql_eol))

        # MySQL 
        if 'Check Audit Trail' not in mysql_plugin:
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]
                    
            report_items_per_host = nfr.host.report_items(report_host)
            for report_item in report_items_per_host:
                
                plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
                if plugin_id == 10719:

                    mysql_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                    mysql_port = nfr.plugin.report_item_value(report_item, 'port')

                    # Write to Excel worksheet
                    tableData.append((report_fqdn,report_ip,mysql_protocol,mysql_port,"MySQL","",""))

        # PostgreSQL
        if 'Check Audit Trail' not in postgres_plugin:
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]
                    
            report_items_per_host = nfr.host.report_items(report_host)
            for report_item in report_items_per_host:
                
                plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
                if plugin_id == 26024:

                    postgres_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                    postgres_port = nfr.plugin.report_item_value(report_item, 'port')

                    # Write to Excel worksheet
                    tableData.append((report_fqdn,report_ip,postgres_protocol,postgres_port,"PostgreSQL","",""))

        # Oracle
        if 'Check Audit Trail' not in oracle_plugin:
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]
                    
            report_items_per_host = nfr.host.report_items(report_host)
            for report_item in report_items_per_host:
                
                plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
                if plugin_id == 22073:

                    lines = oracle_plugin.splitlines()
                    for line in lines:
                        if 'Version' in line:
                            oracle_version = line.split()                                    

                    oracle_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                    oracle_port = nfr.plugin.report_item_value(report_item, 'port')

                    # Write to Excel worksheet
                    tableData.append((report_fqdn,report_ip,oracle_protocol,oracle_port,"Oracle Database",oracle_version[2].strip(),""))           

        # MongoDB
        if 'Check Audit Trail' not in mongo_plugin:
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]
                    
            report_items_per_host = nfr.host.report_items(report_host)
            for report_item in report_items_per_host:
                
                plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
                if plugin_id == 65914:

                    lines = mongo_plugin.splitlines()
                    for line in lines:
                        if 'Version' in line:
                            mongo_version = line.split()                                    

                    mongo_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                    mongo_port = nfr.plugin.report_item_value(report_item, 'port')

                    # Write to Excel worksheet
                    tableData.append((report_fqdn,report_ip,mongo_protocol,mongo_port,"MongoDB",mongo_version[2].strip(),""))     
    
    if len(tableData) > 0:
        DatabaseWorksheet = CreateWorksheet(workbook,'Databases')
        CreateSheetTable(columns,DatabaseWorksheet)
        AddTableData(tableData,DatabaseWorksheet)

    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Database Audit. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Extract all Default HTTP instances
def extractDefaultHTTP():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Protocol',10))
    columns.append(('Port',6))
    columns.append(('HTTP Content',60))

    tableData = []

    for report_host in nfr.scan.report_hosts(root):
        plugin_11422 = nfr.plugin.plugin_outputs(root, report_host, '11422')

        if 'Check Audit Trail' not in plugin_11422:
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
                tableData.append((report_fqdn,report_ip,http_protocol,http_port,lines[1]))
    
    if len(tableData) > 0:
        DefaultHTTPWorksheet = CreateWorksheet(workbook,'Default HTTP Servers')
        CreateSheetTable(columns,DefaultHTTPWorksheet)
        AddTableData(tableData,DefaultHTTPWorksheet)

    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Default HTTP Servers. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Extract all HTTP(S) servers and their headers
def extractHTTPServers():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Protocol',10))
    columns.append(('Port',6))
    columns.append(('HTTP Server',60))

    tableData = []

    for report_host in nfr.scan.report_hosts(root):
        plugin_10107 = nfr.plugin.plugin_outputs(root, report_host, '10107')

        if 'Check Audit Trail' not in plugin_10107:
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            lines = plugin_10107.splitlines()

        report_items_per_host = nfr.host.report_items(report_host)
        for report_item in report_items_per_host:
            
            plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
            if plugin_id == 10107:
                http_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                http_port = nfr.plugin.report_item_value(report_item, 'port')

                # Write to Excel worksheet
                tableData.append((report_fqdn,report_ip,http_protocol,http_port,lines[2]))
    
    if len(tableData) > 0:
        HTTPServerWorksheet = CreateWorksheet(workbook,'HTTP Servers')
        CreateSheetTable(columns,HTTPServerWorksheet)
        AddTableData(tableData,HTTPServerWorksheet)

    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed HTTP Servers. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Determine when Windows system security patch levels
def extractLastUpdated():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Latest Effective Update Level',28))

    tableData = []

    for report_host in nfr.scan.report_hosts(root):
        plugin_93962 = nfr.plugin.plugin_outputs(root, report_host, '93962')

        if 'Check Audit Trail' not in plugin_93962:
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            lines = plugin_93962.splitlines()
            for line in lines:
                if 'Latest effective update level : ' in line:
                    update_level = line.replace(' Latest effective update level : ','')

            # Write to Excel worksheet
            tableData.append((report_fqdn,report_ip,update_level.replace('_','/')))
    
    if len(tableData) > 0:
        IssuesWorksheet = CreateWorksheet(workbook,'Security Update Level')
        CreateSheetTable(columns,IssuesWorksheet)
        AddTableData(tableData,IssuesWorksheet)

    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Security Patch Levels. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Extract all missing Windows security patches
def extractMSPatches():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Missing Security Patch',22))
    columns.append(('Vendor Advisory',60))

    tableData = []

    for report_host in nfr.scan.report_hosts(root):
        plugin_38153 = nfr.plugin.plugin_outputs(root, report_host, '38153')

        if 'Check Audit Trail' not in plugin_38153:
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            lines = plugin_38153.splitlines()
            for line in lines:
                line.strip()

                if len(line) > 2 and 'The patches for the following bulletins' not in line:
                    patch,advisory = line.split('(',1)

                    # Write to Excel worksheet. TODO: Advisory links are all dead
                    tableData.append((report_fqdn,report_ip,patch[3:].strip(),advisory[:-3].strip()))
    
    if len(tableData) > 0:
        MSPatchesWorksheet = CreateWorksheet(workbook,'Missing Microsoft Patches')
        CreateSheetTable(columns,MSPatchesWorksheet)
        AddTableData(tableData,MSPatchesWorksheet)

    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Microsoft Patches. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Extract all missing Linux security patches
def extractLinuxPatches():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Missing patch',67))
    columns.append(('Current Package Version',50))
    columns.append(('Latest Package Version',50))

    tableData = []

    # Will need to assess each plugin for its family
    for report_host in nfr.scan.report_hosts(root):
        all_plugins = nfr.host.report_items(report_host)
        
        for plugin in all_plugins:
            if 'Check Audit Trail' not in plugin:
                report_ip = nfr.host.resolved_ip(report_host)
                report_fqdn = Hosts[report_ip]
                plugin_id = nfr.plugin.report_item_value(plugin, 'pluginID')
                plugin_name = nfr.plugin.report_item_value(plugin, 'pluginName')
                plugin_family = nfr.plugin.report_item_value(plugin, 'pluginFamily')

                # https://www.tenable.com/plugins/nessus/families - Handily everything but Windows are captured here
                if "Local Security Checks" in plugin_family:
                    lines = nfr.plugin.plugin_output(root, report_host, plugin_id).splitlines()

                    for line in lines:
                        if "Remote package installed :" in line:
                            currentver = line.split(":",1)
                        if "Should be                :" in line:
                            latestver = line.split(":",1)
                            tableData.append((report_fqdn,report_ip,plugin_name,currentver[-1].strip(),latestver[-1].strip()))

    if len(tableData) > 0:
        LinuxPatchesWorksheet = CreateWorksheet(workbook,'Missing Linux Patches')
        CreateSheetTable(columns,LinuxPatchesWorksheet)
        AddTableData(tableData,LinuxPatchesWorksheet)

    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Linux Patches. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Extract all open ports
def extractOpenPorts():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Protocol',10))
    columns.append(('Port',6))

    tableData = []

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
                    tableData.append((report_fqdn,report_ip,protocol,port))

    if len(tableData) > 0:
        OpenPortsWorksheet = CreateWorksheet(workbook,'Open Ports')
        CreateSheetTable(columns,OpenPortsWorksheet)
        AddTableData(tableData,OpenPortsWorksheet)
    
    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Open Ports. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Extract all remediations (normally third party software update advice)
def extractRemediations():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Remediation Action',150))
    columns.append(('Impact',46))

    tableData = []
    cves, count = 0, 0
    fix = ''; impact = ''

    for report_host in nfr.scan.report_hosts(root):
        plugin_66334 = nfr.plugin.plugin_outputs(root, report_host, '66334')
        report_ip = nfr.host.resolved_ip(report_host)
        report_fqdn = Hosts[report_ip]

        if 'Check Audit Trail' not in plugin_66334:

            remediation = io.StringIO(plugin_66334)
            for line in remediation.getvalue().split('\n'):
                if '+ Action to take : ' in line:
                    fix = line.replace('+ Action to take : ','').split('. ',1)
                    if ('Microsoft has released' in fix) or ('Apply the workaround' in fix):
                        continue
                    else:
                        count = 10000000

                # This is barbaric code but we need to see if the second line down has the # of vulns fixed or not
                if (count == 10000002):
                    
                    # Write to Excel worksheet
                    if '+ Impact : ' in line:
                        cves = int(re.search(r'\d+', line).group())
                        impact = f'Taking the following action will remediate {cves} CVEs'
                        tableData.append((report_fqdn,report_ip,fix[0],impact))
                    else: 
                        tableData.append((report_fqdn,report_ip,fix[0],'This information is not available'))

                count += 1 
    
    if len(tableData) > 0:
        RemediationsWorksheet = CreateWorksheet(workbook,'Remediations')
        CreateSheetTable(columns,RemediationsWorksheet)
        AddTableData(tableData,RemediationsWorksheet)

    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Remediations. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Perform software audit on all Windows machines
def extractInstalledSoftware():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Installed Software',100))

    tableData = []

    for report_host in nfr.scan.report_hosts(root):
        report_ip = nfr.host.resolved_ip(report_host)
        report_fqdn = Hosts[report_ip]
        
        plugin_20811 = nfr.plugin.plugin_output(root, report_host, '20811')
        if 'Check Audit Trail' not in plugin_20811:
            
            plugin_20811 = plugin_20811.replace('The following software are installed on the remote host :\n\n','')
            plugin_20811 = plugin_20811.replace('The following updates are installed :\n\n','')
            software = io.StringIO(plugin_20811)
            
            for installed in software.getvalue().split('\n'):
                kb_match = re.match(r"  KB\d[0-9]{5,8}", installed)

                if installed == "" or kb_match: 
                    pass
                else:
                    # Write to Excel worksheet
                    tableData.append((report_fqdn,report_ip,installed))
    
    if len(tableData) > 0:
        InstalledSoftwareWorksheet = CreateWorksheet(workbook,'Installed Third Party Software')
        CreateSheetTable(columns,InstalledSoftwareWorksheet)
        AddTableData(tableData,InstalledSoftwareWorksheet)

    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Installed Third Party Software. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Identify all unencrypted protcols in use
def extractUnencryptedProtocols():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Protocol',10))
    columns.append(('Port',6))
    columns.append(('Description',50))

    tableData = []

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
                tableData.append((report_fqdn,report_ip,unencrypted_protocol,unencrypted_port,unencrypted_description))

    if len(tableData) > 0:
        UnencryptedProtocolsWorksheet = CreateWorksheet(workbook,'Unencrypted Protocols')
        CreateSheetTable(columns,UnencryptedProtocolsWorksheet)
        AddTableData(tableData,UnencryptedProtocolsWorksheet)
    
    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Unencrypted Protocols. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Extract all unquoted service paths along with their service name
def extractUnquotedServicePaths():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Service Name',40))
    columns.append(('Service Path',100))
    columns.append(('Exploitability',14))

    tableData = []

    for report_host in nfr.scan.report_hosts(root):
                
        plugin_63155 = nfr.plugin.plugin_outputs(root, report_host, '63155')
        if 'Check Audit Trail' not in plugin_63155:
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            lines = plugin_63155.splitlines()
            for line in lines:
                line.strip()

                if len(line) > 2 and 'Nessus found the following' not in line:
                    service,path = line.split(':',1)
                    # Write to Excel worksheet
                    if "C:\Program Files".lower() in path.lower():
                        tableData.append((report_fqdn,report_ip,service.strip(),path.strip(),'Low'))
                    else:
                        tableData.append((report_fqdn,report_ip,service.strip(),path.strip(),'High'))
    
    if len(tableData) > 0:
        UnquotedPathsWorksheet = CreateWorksheet(workbook,'Unquoted Service Paths')
        CreateSheetTable(columns,UnquotedPathsWorksheet)
        AddTableData(tableData,UnquotedPathsWorksheet)

    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Unquoted Service Paths. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Identify all unsupported operating systems 
def extractUnsupportedOperatingSystems():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Operating System',55))
    columns.append(('End of Mainstream Support Date',31))
    columns.append(('End of Extended Support Date',29))
    columns.append(('End of Extended Security Updates (ESU / ESM) Date',50))

    tableData = []

    for report_host in nfr.scan.report_hosts(root):
        report_ip = nfr.host.resolved_ip(report_host)
        report_fqdn = Hosts[report_ip]
        report_host_os = nfr.host.detected_os(report_host)

        if report_host_os is not None and report_host_os.count('\n') == 0:
            # https://docs.microsoft.com/en-gb/lifecycle/products/            
            if 'Microsoft Windows 2000' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"30 June 2005","13 July 2010",""))
            if 'Microsoft Windows Server 2003' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"13 July 2010","14 July 2015",""))
            if 'Microsoft Windows Server 2008' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"13 January 2015","14 January 2020","10 January 2023"))
            if 'Microsoft Windows XP' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"14 April 2009","08 April 2014",""))
            if 'Microsoft Windows Vista' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"10 April 2012","11 April 2017",""))
            if 'Microsoft Windows 7' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"13 January 2015","14 January 2020","10 January 2023"))
        # https://endoflife.date/   https://endoflife.software/
            if 'VMware ESXi 5.5' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"19 September 2015","19 September 2020",""))
            if 'VMware ESXi 6.0' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"12 March 2018","12 March 2022",""))
            if 'Ubuntu 10.04' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"30 April 2015","",""))
            if 'Ubuntu 12.04' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"28 April 2017","",""))
            if 'Ubuntu 14.04' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"02 April 2019","","02 April 2024"))
            if 'Ubuntu 16.04' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"02 April 2021","","02 April 2026"))
            if 'CentOS Linux 5' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"31 March 2017","",""))
            if 'CentOS Linux release 6' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"30 November 2020","",""))
            if 'CentOS Linux 8' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"31 December 2021","",""))
        # https://www.freebsd.org/security/unsupported/
            if 'FreeBSD 9.' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"31 December 2016","",""))
            if 'FreeBSD 10.' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"31 October 2018","",""))
            if 'FreeBSD 11.' in report_host_os:
                tableData.append((report_fqdn,report_ip,report_host_os,"30 September 2021","",""))

    if len(tableData) > 0:
        UnsupportedOSWorksheet = CreateWorksheet(workbook,'Unsupported Operating Systems')
        CreateSheetTable(columns,UnsupportedOSWorksheet)
        AddTableData(tableData,UnsupportedOSWorksheet)

    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Unsupported Operating Systems. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Identify all Windows services with weak permissions
def extractWeakServicePermissions():
    tic = time.perf_counter()
    path = services = dirGroups = writeGroups = ''

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column width
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Service Name',50))
    columns.append(('Service Path',85))
    columns.append(('User / Group with Write permissions',35))
    columns.append(('User / Group with Full Control',30))

    tableData = []

    for report_host in nfr.scan.report_hosts(root):
        report_ip = nfr.host.resolved_ip(report_host)
        
        plugin_65057 = nfr.plugin.plugin_outputs(root, report_host, '65057')
        if 'Check Audit Trail' not in plugin_65057:
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

                # Write to Excel worksheet
                tableData.append((report_fqdn,report_ip,services,path,dirGroups,writeGroups))
    
    if len(tableData) > 0:
        ServicePermissionsWorksheet = CreateWorksheet(workbook,'Insecure Service Permissions')
        CreateSheetTable(columns,ServicePermissionsWorksheet)
        AddTableData(tableData,ServicePermissionsWorksheet)

    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Weak Service Permissions. {len(tableData)} rows took {toc - tic:0.4f} seconds')

# Extract all Weak Algorithms and Ciphers being used by SSH services
def extractWeakSSHAlgorithms():
    tic = time.perf_counter()

    # Create worksheet with headers. Xlswriter doesn't support autofit so best guess for column widths
    columns = []
    columns.append(('Hostname',40))
    columns.append(('IP Address',15))
    columns.append(('Protocol',10))
    columns.append(('Port',6))
    columns.append(('Weak Encryption Algorithm',27))
    columns.append(('Weak Key Exchange Algorithm',33))
    columns.append(('Weak Cipher Block Chaining Cipher',33))
    columns.append(('Weak Message Authentication Code Algorithm',44))

    # Initialize some variables
    enc_algorithms = []; keyex_algorithms = []; cbc_algorithms = []; mac_algorithms = []

    tableData = []

    for report_host in nfr.scan.report_hosts(root):
        enc_plugin = nfr.plugin.plugin_outputs(root, report_host, '90317')
        keyex_plugin = nfr.plugin.plugin_outputs(root, report_host, '153953')
        cbc_plugin = nfr.plugin.plugin_outputs(root, report_host, '70658')
        mac_plugin = nfr.plugin.plugin_outputs(root, report_host, '71049')

        if ('Check Audit Trail' not in enc_plugin) or ('Check Audit Trail' not in keyex_plugin) or ('Check Audit Trail' not in cbc_plugin) or ('Check Audit Trail' not in mac_plugin):
            report_ip = nfr.host.resolved_ip(report_host)
            report_fqdn = Hosts[report_ip]

            report_items_per_host = nfr.host.report_items(report_host)
            for report_item in report_items_per_host:

                plugin_id = int(nfr.plugin.report_item_value(report_item, 'pluginID'))
                # check enc, kek, cbc or mac 
                if plugin_id == 90317 or plugin_id == 153953 or plugin_id == 70658 or plugin_id == 71049:
                    # Weak encryption ciphers
                    if plugin_id == 90317:

                        enc_output = enc_plugin.splitlines()
                        for enc_algorithm in enc_output:
                            if 'The following weak' not in enc_algorithm and 'Check Audit Trail' not in enc_algorithm and len(enc_algorithm) != 0:
                                if enc_algorithm.strip() not in enc_algorithms:
                                    enc_algorithms.append(enc_algorithm.strip())

                    # Weak key exchange ciphers
                    if plugin_id == 153953:                  
                        
                        keyex_output = keyex_plugin.splitlines()
                        for keyex_algorithm in keyex_output:
                            if 'The following weak key exchange' not in keyex_algorithm and 'Check Audit Trail' not in keyex_algorithm and len(keyex_algorithm) != 0:
                                if keyex_algorithm.strip() not in keyex_algorithms:                            
                                    keyex_algorithms.append(keyex_algorithm.strip())

                    # Weak CBC ciphers
                    if plugin_id == 70658:                       
                        
                        cbc_output = cbc_plugin.splitlines()
                        for cbc_algorithm in cbc_output:
                            if 'The following' not in cbc_algorithm and 'are supported :' not in cbc_algorithm and 'Check Audit Trail' not in cbc_algorithm and len(cbc_algorithm) != 0:
                                if cbc_algorithm.strip() not in cbc_algorithms:
                                    cbc_algorithms.append(cbc_algorithm.strip())

                    # Weak MAC ciphers
                    if plugin_id == 71049:                   
                        mac_output = mac_plugin.splitlines()

                        for mac_algorithm in mac_output:
                            if 'The following' not in mac_algorithm and 'are supported :' not in mac_algorithm and 'Check Audit Trail' not in mac_algorithm and len(mac_algorithm) != 0:
                                if mac_algorithm.strip() not in mac_algorithms:
                                    mac_algorithms.append(mac_algorithm.strip())
                    
                    ssh_protocol = nfr.plugin.report_item_value(report_item, 'protocol')
                    ssh_port = nfr.plugin.report_item_value(report_item, 'port')

            ipComplete = False
            r = 0
            while ipComplete is False:
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
                    break
                else:
                    tableData.append((report_fqdn,report_ip,ssh_protocol,ssh_port,enc,kek,cbc,mac))
                    r += 1

    if len(tableData) > 0:
        WeakSSHWorksheet = CreateWorksheet(workbook,'Weak SSH Algorithms')
        CreateSheetTable(columns,WeakSSHWorksheet)
        AddTableData(tableData,WeakSSHWorksheet)

    toc = time.perf_counter()
    if args.verbose:
        print (f'DEBUG - Completed Weak SSH Algorithms and Ciphers. {len(tableData)} rows took {toc - tic:0.4f} seconds')

#--------------------------------------------------------------------------------
# Common Nessus Functions
def GenerateHostDictionary():
    tic = time.perf_counter()

    for report_host in nfr.scan.report_hosts(root):
        # If Nessus can't resolve the hostname get it from Device Hostname plugin
        report_fqdn = nfr.host.resolved_fqdn(report_host)

        if not args.noresolve:
            if report_fqdn is None:
                plugin_55472 = nfr.plugin.plugin_outputs(root, report_host, '55472')
                hostname_plugin = io.StringIO(plugin_55472)
                for line in hostname_plugin.getvalue().split('\n'):
                    if 'Hostname : ' in line:
                        report_fqdn = line.replace('  Hostname : ','')
                        break
                    else:
                        report_fqdn = "N.A"
        else:
            if report_fqdn is None:
                report_fqdn = "N.A"
        report_ip = nfr.host.resolved_ip(report_host)
        Hosts[report_ip] = report_fqdn

    toc = time.perf_counter()

    if len(Hosts) < 1:
            print('No Hosts Found! Exiting..')
            exit()
    else:
        if args.verbose:
            print (f'DEBUG - Hosts List Generated. {len(Hosts)} rows took {toc - tic:0.4f} seconds')

# -------------------------------------------------------------------------------
# Excel Functions - First create our Excel workbook
def CreateWorkBook(workBookName):
    excelPath = os.getcwd() + os.sep + workBookName
    workbook = xlsxwriter.Workbook(excelPath)
    
    if args.verbose:
        print(f'DEBUG - Using Excel output file: {excelPath}')
    
    return workbook

# Create worksheet
def CreateWorksheet(workBook, sheetName):
    workSheet = workBook.add_worksheet(sheetName)

    return workSheet

# Format worksheet
def CreateSheetTable(columns,workSheet):
    col = 0

    for column in columns:
        workSheet.write(0,col,column[0])
        workSheet.set_column(col,col,column[1])
        col += 1
    
    alpha = string.ascii_uppercase[len(columns)-1]
    workSheet.autofilter('A1:'+alpha+'1000000')

# Write data to worksheet
def AddTableData(tableData,workSheet):
    row = 1
    col = 0
    for line in tableData:
        for item in line:
            workSheet.write(row,col,item)
            col += 1
        col = 0
        row += 1 

# Finally gracefully clean up 
def CloseWorkbook(workBook):
    workBook.close()

# -------------------------------------------------------------------------------
# Argparser to handle the usage / argument handling
parser = argparse.ArgumentParser(description='''Extract useful information out of .nessus files into Excel

nessusToExcel.py --verbose --file report.nessus --module unsupported,hosts,software --out companyName
nessusToExcel.py --file report.nessus''', formatter_class=argparse.RawTextHelpFormatter)

# Arguments
parser.add_argument('--file', '-f', required=True, help='.nessus file to extract from')
parser.add_argument('--verbose', '-v', action='store_true', help='Increase output verbosity')
parser.add_argument('--out', '-o', default='ExtractedData.xlsx', help='Name of resulting Excel workbook. (Does not need extention, default ExtractedData.xlsx)')
parser.add_argument('--quiet', '-q', action='store_true', help='Accept defaults during execution')
parser.add_argument('--noresolve', '-n', action='store_true', help='Do not use WMI / SSH Device Hostname Plugin to gain more hostnames (Comes with performance hit, default False)')
parser.add_argument('--module', '-m', type=str, default='all', 
help=textwrap.dedent('''Comma seperated list of what data you want to extract:
all          = Default
compliance   = Format CIS Compliance output
database     = Audit of all identified databases 
defaulthttp  = Web servers with default content
hosts        = Host information (also comes in .txt file)
http         = Identify all HTTP servers and their versions
issues       = Present all non-info issues
lastupdated  = View all Windows host security patch levels
nixpatches   = Missing Microsoft security patches
ports        = All identified open ports
remediations = All suggested fixes
services     = Insecure Services and their weak permissions
software     = Installed third party software (warning: can be heavy!)
ssh          = Identify all weak SSH algorithms and ciphers in use
unencrypted  = Unencrypted protocols in use. FTP, Telnet etc.
unquoted     = Unquoted service paths and their weak permissions
unsupported  = Unsupported operating systems
winpatches   = Missing Microsoft security patches
'''))

# Keep a timer to keep an eye on performance
tic = time.perf_counter()

args = parser.parse_args()
if args.verbose:
    print (f'DEBUG - Arguments provided: {args}')

# If a valid .nessus file has been provided, create our Excel workbook
if not '.xlsx' in args.out:
    args.out = args.out + '.xlsx'
    print(f'DEBUG - Output file does not contain extension, new value: {args.out}')

# As Host Information.txt is appended, check if we want to remove it before starting
hostInfoPath = os.getcwd() + os.sep + 'Host Information.txt'
if os.path.isfile(hostInfoPath):
    if args.quiet:
        if args.verbose:
            print(f'DEBUG - Removing previous Host Information.txt file - {os.getcwd()}{os.sep}Host Information.txt')
        os.remove(hostInfoPath)
    else:
        host_answer = input("Host Information.txt already present, to stop this from being appended, would you like to remove this file first? [Y/n]")
        if host_answer == 'Y' or host_answer == 'Yes' or host_answer == 'y' or host_answer == 'yes' or host_answer == '':
            if args.verbose:
                print(f'DEBUG - Removing previous Host Information.txt file - {os.getcwd()}{os.sep}Host Information.txt')
            os.remove(hostInfoPath)

# Ensure provided file or directory exists before we carry on
if not os.path.isfile(args.file):
    raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), args.file)
else:
    # Create our Excel workbook
    workbook = CreateWorkBook(args.out)

# Split out comma separated modules
argvars = vars(parser.parse_args())
argvars['module'] = [mod.strip() for mod in argvars['module'].split(",")]

# Need to refactor xml tags if working with compliance data first to assist with parsing
if 'compliance' in argvars['module'] or "all" in args.module:

    # Will ask user if they would like to take a backup of the Nessus file first as we are manipulating it
    backupPath = os.getcwd() + os.sep + f'{args.file}.bak'
    if not os.path.isfile(backupPath):
        if args.quiet:
            if args.verbose:
                print(f'DEBUG - Taking backup of Nessus file - {os.getcwd()}{os.sep}{args.file}.bak')

            shutil.copyfile(args.file, f'{args.file}.bak')
        else:
            comp_answer = input("To extract compliance output, changes to XML tags are required. While this should not cause any further issues, would you like to take a backup of your Nessus file first? [Y/n]")
            if comp_answer == 'Y' or comp_answer == 'Yes' or comp_answer == 'y' or comp_answer == 'yes' or comp_answer == '':
                if args.verbose:
                    print(f'DEBUG - Taking backup of Nessus file - {os.getcwd()}{os.sep}{args.file}.bak')

                shutil.copyfile(args.file, f'{args.file}.bak')
    else:
        if args.verbose:
            print(f'DEBUG - Nessus backup file already exists, continuing')

    # nfr could not handle the cm namespace within the compliance results. Once these are removed extraction has no issues
    search_text = "cm:compliance-"
    replace_text = "compliance-"

    with open(args.file, 'r') as file:
        data = file.read()
        data = data.replace(search_text, replace_text)

    with open(args.file, 'w') as file:
        file.write(data)

# Read XML and generate hosts list once
root = nfr.file.nessus_scan_file_root_element(args.file)
GenerateHostDictionary()

# Check which modules have been requested
if "all" in args.module:
    if args.verbose:
        print(f'DEBUG - Running all modules')
    extractAll()
else:
    if args.verbose:
        print(f'DEBUG - Modules selected: {(argvars["module"])}')
    
    # TODO - make into switch statement as currently invalid modules will be omitted without warning
    if 'compliance' in argvars['module']:
        extractCompliance()
    if 'database' in argvars['module']:
        extractDatabases()
    if 'defaulthttp' in argvars['module']:
        extractDefaultHTTP()  
    if 'hosts' in argvars['module']:
        extractHosts()
    if 'http' in argvars['module']:
        extractHTTPServers()
    if 'issues' in argvars['module']:
        extractIssues()    
    if 'lastupdated' in argvars['module']:
        extractLastUpdated()   
    if 'nixpatches' in argvars['module']:
        extractLinuxPatches()
    if 'ports' in argvars['module']:
        extractOpenPorts()
    if 'remediations' in argvars['module']:
        extractRemediations()
    if 'services' in argvars['module']:
        extractWeakServicePermissions()
    if 'software' in argvars['module']:
        extractInstalledSoftware()
    if 'ssh' in argvars['module']:
        extractWeakSSHAlgorithms()
    if 'unencrypted' in argvars['module']:
        extractUnencryptedProtocols()
    if 'unquoted' in argvars['module']:
        extractUnquotedServicePaths()
    if 'unsupported' in argvars['module']:
        extractUnsupportedOperatingSystems()
    if 'winpatches' in argvars['module']:
        extractMSPatches()
    else:
        print('Invalid module provided. Omitting')

toc = time.perf_counter()
print (f'COMPLETED! Output can be found in {os.getcwd()}{os.sep}{args.out} Total time taken: {toc - tic:0.4f} seconds')
CloseWorkbook(workbook)
exit()