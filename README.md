# WhatWeb Results Parser

## Description
This script aims to assist users in parsing **WhatWeb** results into an easy to view CSV format. Bash script `bulk_scan.sh` reads file `urls.txt`; for each line (or URL) in `urls.txt`, `whatweb` is run, logging results to a json-formatted file in the `scan_output` folder.

Once `bulk_scan.sh` completes, Python script `parse.py` can be run to translate **WhatWeb** json output into CSV format.

## parse.py Commandline Options
### -i | --input-folder | REQUIRED
Path to folder that contains WhatWeb output.

### -f | --log-format
WhatWeb log format to parse. Acceptable options:

* json
* xml

 If this argument is not set, **json** is default. **xml** not supported in v0.1.

### -p | --plugin-fields | REQUIRED
Comma-delimited list of WhatWeb plugin fields to be parsed and documented (e.g. **HTTPServer, IP, X-Powered-By**).

### -o | --output-file | REQUIRED
Filename to save parsed **WhatWeb** results to.

## Example

```
python parse.py -i scan_output -p HTTPServer,IP,X-Powered-By -o results.csv
```

## Requirements
### whatweb ([link](http://www.morningstarsecurity.com/research/whatweb))
### Python libraries:
* simplejson
* tldextract
 
**Installation via pip:**

```
pip install -r requirements.txt
```

**Installation via easy_install**

```
easy_install `cat requirements.txt`
```
