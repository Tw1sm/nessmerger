# Nessus Merger
Will search a specified folder for .nessus files and format them into an Excel report in .xlsx format.

## Customization
Edit the `Customization` class near the top of nessmerger.py with logo and company name to replace the defaults.

## Installation
`pip3 install -r requirements.txt`

## Usage
```
usage: nessmerger.py [-h] directory

Merge all .nessus files within a folder into one Excel .xlsx report

positional arguments:
  directory   Folder containing .nessus files

optional arguments:
  -h, --help  show this help message and exit
```
