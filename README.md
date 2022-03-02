# Helpers

Little helper scripts to aid infrastructure testing and reporting

## Pre-reqs

python 3.8

pip install -r requirements.txt

## Installation

Recommended to put this directory in your PATH so you can execute scripts from anywhere. Example .zshrc addition below:

`export PATH=$PATH:/opt/helper-scripts`

## Mergers

[Nmap merger](https://github.com/CBHue/nMap_Merger)

[Nessus merger](https://github.com/0xprime/NessusReportMerger.git) - has been modified with pwsh shebang to work on WSL / Linux & reversed \ to / to support *nix filepaths.

## nessusToExcel Extractor

This script will take in a single file or directory of nessus files and will output an Excel Workbook as well a Host Information.txt file in your current working directory.

A nessus file of around 8000 hosts takes around 5 minutes to process. Use --help or -h for full help and examples output.

## Sparta.conf

An extended configuration file providing a wrapper around the nmap NSE library and hydra to automatically brute force common management ports.

```
sudo apt install python3-sqlalchemy python3-pyqt5 wkhtmltopdf ldap-utils rwho rsh-client x11-apps finger seclists
sudo git clone https://github.com/secforce/sparta.git /usr/share/sparta
sudo mv /usr/share/sparta /usr/bin/sparta
sudo chmod +x /usr/bin/sparta
wget https://raw.githubusercontent.com/spyr0-sec/helper-scripts/main/sparta.conf -O /usr/share/sparta/sparta.conf
```

## VLANer

Wrapper script to handle creation and deletion of multiple VLANs when testing via trunk ports

## PyShark

CLI raw packet capturer for offline analysis

## Named_Pipes

Extended list of named pipes to increase success of SMB based vulnerabilities. Replace /usr/share/metasploit-framework/data/wordlists/named_pipes.txt with this updated list.