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
  - Attributes (`select attr:role="BORDER ROUTER"`)
* Displays selected devices in JSON format
* Shows any single attribute across selected devices (`showattr role`)
* **Bulk updates the `role`** attribute of selected devices via the Intent API
* Graceful SSL bypass prompt (when certificate validation fails)
* Ctrl+C safe exit
* Refresh inventory without restarting

## Requirements

* Python 3.6+
* `requests` library (`pip install requests`)

## Installation

```
git clone https://github.com/irongiant33/Catalyst-Center-Inventory-Manager.git
cd Catalyst-Center-Inventory-Manager
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
deactivate
```

Without a virtual environment, `pip3 install -r requirements.txt` 

## Environment Variables (required) & Running the Program

From the Catalyst-Center-Inventory-Manager directory:

```bash
export CATALYST_CENTER_URL="https://your-catalyst-center.example.com"
export CATALYST_CENTER_USER="admin"
export CATALYST_CENTER_PASSWORD="your-secure-password"
# Optional – set to "true"/"yes"/"1" to skip SSL verification from the start
export CATALYST_CENTER_SSL_BYPASS="false"
source venv/bin/activate
python3 catalyst_center_device_role_update.py
deactivate
```

For the `CATALYST_CENTER_URL`, ensure there are no trailing `/` otherwise you may receive a 404 Client Error on startup.

Python Virtual Environments are not required but are recommended to improve shareability, isolate project dependencies, and prevent version conflcits. You can read more about virtual environments and how to get them running here: [https://docs.python.org/3/tutorial/venv.html](https://docs.python.org/3/tutorial/venv.html). If you choose to avoid using virtual environments, your install would look as follows:

```bash
export CATALYST_CENTER_URL="https://your-catalyst-center.example.com"
export CATALYST_CENTER_USER="admin"
export CATALYST_CENTER_PASSWORD="your-secure-password"
# Optional – set to "true"/"yes"/"1" to skip SSL verification from the start
export CATALYST_CENTER_SSL_BYPASS="false"
pip3 install -r requirements.txt
python3 catalyst_center_device_role_update.py
```

## Developer Notes

- Tested on Catalyst Center 2.3.7.9.70301.10
- Tested with API 2-3-7-9
- This code is in protoype/development stages and should be used with caution in production environments. Please raise an issue in this repository to get in touch with the developer if you have any questions or known issues

## Changelog

V0.2 -> V0.3
- Adding install guide to readme
- Added option to provide a string input to the attribute filter that contains spaces
- Added option to provide regex matches when filtering by device attribute

V0.1 -> V0.2
- Code cleanup; consolidated environment variable names into global variables
- Added functionality to the `list` command; filter for tons of devices giving user the option to not flood their terminal with prints. Added options for providing regex and device attribute filters.
- Added functionality to the `select` command; filter for tons of devices giving user the option to not flood their terminal with prints. Added options for providing regex and device attribute filters.
- Added functionality to the `show` command; filter for tons of devices giving user the option to not flood their terminal with prints. Added options for providing regex and device attribute filters. Consolidated the `showattr` command into the `show` command.
- Cleaned up the help functionality; Command library supports help features for each function as well as a general help

## To-do

- [ ] Clean up comments, reference APIs in the script
- [ ] Add functionality testing, work toward full coverage
- [ ] Add pip-audit or safety to your GitHub Actions pipeline to check dependency security
- [ ] pylint
- [ ] static and dynamic security testing, ZAP, semgrep, veracode
- [ ] add video walkthrough & install guide to readme
- [ ] avoiding need to manually type out device role
- [ ] regarding selection and listing filters, consider providing OR logic as well as AND logic.
- [ ] what happens when the user doesn't exist, doesn't enter right password, doesn't have permissions to access inventory, etc. 
- [ ] option to completely filter out any InsecureRequestWarnings