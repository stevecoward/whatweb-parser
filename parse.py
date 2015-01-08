#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script designed to take log output from WhatWeb and translate the results
to another file type (presently CSV format) for enumeration information 
gathering.

Requires: WhatWeb (duh), Python packages: see requirements.txt

:author Steve Coward
:version 0.1
"""

import sys
import os
import glob
import argparse
import simplejson as json
import tldextract

"""
Mapping of WhatWeb values nested within plugin key values.
Most seem to be: {
    key: {
        'string': ['value']
    }
}
But may be a variant like: {
    key: {
        'module': ['value'],
        'version': ['value'],
    }
}
"""
PLUGIN_FIELD_KEYS = {
    'HTTPServer': {
        'key': 'string',
        'output_key': 'server',
    },
    'IP': {
        'key': 'string',
        'output_key': 'ip_address',
    },
    'RedirectLocation': {
        'key': 'string',
        'output_key': 'redirects_to',
    },
    'X-Powered-By': {
        'key': 'string',
        'output_key': 'powered_by',
    },
    'PoweredBy': {
        'key': 'string',
        'output_key': 'powered_by',
    },
    'Parked-Domain': {
        'key': 'string',
        'output_key': 'is_parked',
    },
    'WWW-Authenticate': {
        'key': 'module',
        'output_key': 'is_auth',
    },
}

def build_args():
    """
    Build out the args required for script execution.
    """
    args = argparse.ArgumentParser()
    args.add_argument('-i', '--input-folder', required=True, type=str, help='Folder containing WhatWeb log output')
    args.add_argument('-f', '--log-format', type=str, choices=['json','xml'], 
        help='WhatWeb log format to parse (JSON is default, XML not supported in v0.1)', default='json')
    args.add_argument('-p', '--plugin-fields', required=True, 
        help='List of which WhatWeb plugin fields need to be parsed and stored (e.g. HTTPServer, IP, X-Powered-By')
    args.add_argument('-o', '--output-file', required=True, type=str, help='Where the parsed output should be saved to')
    return args.parse_args()

def fetch_folder_and_files(input_folder_path, log_format):
    """
    :param input_folder_path
    :param log_format

    Takes a path to WhatWeb log output and either 'json' or 'xml', 
    returns a list of file paths to each log file if any are found, 
    otherwise exits if the path is invalid or if there aren't any log files
    found.
    """
    log_files = []
    if os.path.isdir(input_folder_path):
        log_files = glob.glob('%s/*.%s' % (input_folder_path, log_format))
    else:
        print '[-] Error: Path to WhatWeb logs %s does not exist.' % input_folder_path
        sys.exit(0)

    if not len(log_files):
        print '[-] Error: No log files found matching format: %s.' % log_format
        sys.exit(0)

    return log_files

def parse_json_log_output(file_path, output_file):
    """
    :param file_path

    Takes a file path to a WhatWeb json log file and attempts
    to parse its contents, returning a list of json blobs if
    possible otherwise an error message.
    """
    file_contents = ''
    json_blobs = []
    with open(file_path, 'r') as fh:
        file_contents = fh.read()
        file_contents = file_contents.rstrip()
    try:
        json_blobs = map(json.loads,file_contents.split('\n'))
    except Exception as e:
        print '[-] Error parsing file as json: %s.' % file_path

        # If using accompanying bulk_scan.sh, any WhatWeb errors will be written to the URL.json file.
        # Parsing this script as json will fail with these error messages, so this bit
        # will take into account those records and write to file.
        target = file_contents.split(' ')[0]
        if 'Connection refused' in file_contents:
            status = 'Server Error'
        elif 'Hostname not known' in file_contents:
            status = 'Server Not Found'
        elif 'ERROR: SSL_connect' in file_contents:
            status = 'Server Error - SSL_connect'
        elif 'Timed out' in file_contents:
            status = 'Server Error - Timed Out'
        else:
            status = 'Server Error - Catch All'
        with open(output_file, 'a') as fh:
            fh.write('%(target)s,%(status)s\n' % {
                'target': target,
                'status': status,
            })

    return json_blobs

def extract_url_data_from_json(json_blobs, plugin_fields):
    """
    :param json_blobs
    :param plugin_fields

    The bulk of the parsing logic is found here. A number of cases need
    to be checked in order to properly set a URL's status field. When a
    redirect is evaluated, we only care about the first and last target info.

    Plugin data requested by the user to be extracted is gathered here. There
    are some specific cases in that section of code to make note of some special
    plugin field data which can be removed or appended to as-needed.

    Generally this method can probably be optimized in the future, but it does
    the job for now.
    """
    # Cleanup user-input params
    plugin_fields = map(str.strip,plugin_fields.split(','))
    extracted_data = {}

    # Fetch base info
    target = json_blobs[0]['target']
    target_tld = tldextract.extract(target)
    status = json_blobs[0]['http_status']
    notes = ''
    redirects_to = ''
    powered_by = ''

    # Case: Mark as 'Valid' if http_status startswith(20)
    if str(status).startswith('20'):
        status = 'Valid'
    # Case: Mark as 'Forbidden - :error_code' if http_status startswith(40)
    elif str(status).startswith('40'):
        status = 'Forbidden - %s' % status

    # Multiple json blobs are indicative of a redirect
    if len(json_blobs) > 1:
        redirects_to = json_blobs[-1]['target'].rstrip('/')
        status = str(json_blobs[0]['http_status'])
        redirect_status = str(json_blobs[-1]['http_status'])

        if redirect_status.startswith('20'):
            # Case: Mark as 'Valid' if the redirect is http -> https
            if redirects_to == 'https://www.%s.%s' % (target_tld.domain, target_tld.suffix)\
            or redirects_to == 'https://%s.%s' % (target_tld.domain, target_tld.suffix):
                status = 'Valid'
            else:
                status = 'Redirect - %s' % json_blobs[0]['http_status']

        # Case: Mark as 'Forbidden - :error_code' if http_status startswith(40)
        if redirect_status.startswith('40'):
            status = 'Forbidden - %s' % redirect_status

        # Get the standard fields into the final output
        extracted_data.update({'redirects_to': redirects_to})


    # Enumerate plugin_fields from user input and try to extract them
    plugin_fields.extend(['Parked-Domain','WWW-Authenticate'])
    for field in plugin_fields:
        try:
            field_value = json_blobs[0]['plugins'][field][PLUGIN_FIELD_KEYS[field]['key']][0]
            
            # Case: Mark as 'Parked' if Parked-Domain is present
            if field == 'Parked-Domain' and field_value:
                status = 'Parked'
                notes = field_value
            # Case: Mark as 'Auth Required' if WWW-Authenticate is present
            elif field == 'WWW-Authenticate' and field_value:
                status = 'Auth Required'
                notes = field_value
            else:
                extracted_data[PLUGIN_FIELD_KEYS[field]['output_key']] = field_value
        except:
            pass

    extracted_data.update({
        'target': target,
        'status': status,
        'notes': notes,
    })
    
    return extracted_data

def parse_and_extract_data(args):
    """
    :param log_file
    :param plugin_fields

    Method just combines log parsing and json data extraction for multiprocessing
    """
    log_file, plugin_fields, output_file = args
    expected_keys = ['target','status','ip_address','server','powered_by','redirects_to','notes']

    json_blobs = parse_json_log_output(log_file, output_file)
    if len(json_blobs):
        extracted_data = extract_url_data_from_json(json_blobs, plugin_fields)
        
        # Account for missing fields so the CSV output will line up
        for key in expected_keys:
            if key not in extracted_data:
                extracted_data[key] = ''

        with open(output_file, 'a') as fh:
            fh.write('%(target)s,%(status)s,%(ip_address)s,%(server)s,%(powered_by)s,%(redirects_to)s,%(notes)s\n' % extracted_data)

if __name__ == '__main__':
    args = build_args()

    # Validate input_folder exists and contains logs of type log_format
    file_list = fetch_folder_and_files(args.input_folder, args.log_format)
    print '[+] Found %d log files to parse from WhatWeb...' % len(file_list)

    # Write CSV header
    with open(args.output_file, 'w') as fh:
        fh.write('Scope List,Status,IP Address,Server,Frameworks,Redirects To,Notes\n')

    # Do it NOW
    for log_file in file_list:
        parse_and_extract_data((log_file, args.plugin_fields, args.output_file))
