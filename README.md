# Cisco Catalyst Center Device Role Manager

A simple interactive command-line tool to browse Cisco Catalyst Center (formerly DNA Center) device inventory and **bulk update device roles** (ACCESS, CORE, DISTRIBUTION, BORDER ROUTER, etc.).

Built with Python using only standard libraries + `requests`.

## Features

* Authenticates to Catalyst Center using Basic Auth → Token
* Fetches full device inventory (`/network-device`)
* Interactive selection of devices using:
  - Individual indices (`select 3`)
  - Ranges (`select 2-5`)
  - Lists (`select 1,4,7-9`)
  - Regex patterns (`select regex:^SW.*0[1-4]$`)
* Displays selected devices in JSON format
* Shows any single attribute across selected devices (`showattr role`)
* **Bulk updates the `role`** attribute of selected devices via the Intent API
* Graceful SSL bypass prompt (when certificate validation fails)
* Ctrl+C safe exit
* Refresh inventory without restarting

## Requirements

* Python 3.6+
* `requests` library (`pip install requests`)

## Environment Variables (required)

```bash
export CATALYST_CENTER_URL="https://your-catalyst-center.example.com"
export CATALYST_CENTER_USER="admin"
export CATALYST_CENTER_PASSWORD="your-secure-password"
# Optional – set to "true"/"yes"/"1" to skip SSL verification from the start
export CATALYST_CENTER_SSL_BYPASS="false"
```

## Developer Notes

- Tested on Catalyst Center 2.3.7.9.70301.10
- Tested with API 2-3-7-9
- This code is in protoype/development stages and should be used with caution in production environments. Please raise an issue in this repository to get in touch with the developer if you have any questions or known issues

## Release Notes

- Code cleanup; consolidated environment variable names into global variables
- List filter for tons of devices giving user the option to not flood their terminal with prints. Added options for providing regex and device attribute filters.

## To-do

- [ ] Clean up comments, reference APIs in the script
- [ ] clean up the help functionality. Command library supports help features for each function
- [ ] Add functionality testing, work toward full coverage
- [ ] Add pip-audit or safety to your GitHub Actions pipeline to check dependency security
- [ ] pylint
- [ ] static and dynamic security testing, ZAP, semgrep, veracode
- [ ] add video walkthrough & install guide to readme
- [ ] avoiding need to manually type out device role
- [ ] regarding selection and listing filters, consider providing OR logic as well as AND logic.
- [ ] what happens when the user doesn't exist, doesn't enter right password, doesn't have permissions to access inventory, etc. 