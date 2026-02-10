# 3rd party imports
import requests # https://docs.python-requests.org/en/latest/index.html

# standard library imports
import os
import sys
import signal
import base64
import json
import re
import cmd
import shlex

# global variables
CATALYST_CENTER_URL_ENV = "CATALYST_CENTER_URL"
USERNAME_ENV = "CATALYST_CENTER_USER"
PASSWORD_ENV = "CATALYST_CENTER_PASSWORD"
BYPASS_SSL_ENV = "CATALYST_CENTER_SSL_BYPASS"
INV_LIMIT = 50

class Device:
    """
    Class representing a device in the Catalyst Center inventory.
    """
    def __init__(self, device_dict):
        self.data = device_dict
        self.hostname = device_dict.get("hostname", "Unknown")
        # You can add more attributes here if needed for convenience

    def __hash__(self):
        # Use hostname as unique identifier for hashing
        return hash(self.hostname)

    def __eq__(self, other):
        if not isinstance(other, Device):
            return False
        return self.hostname == other.hostname

    def __repr__(self):
        return f"<Device hostname={self.hostname}>"

    def to_json(self):
        return json.dumps(self.data, indent=2)
    
def parse_cli_filters(args_str: str):
    """
    Parse filter arguments supporting quoted keys/values with spaces.
    Keys and values are treated as regex patterns.
    Returns (regex_pattern: re.Pattern | None, attr_filters: list of (key_regex, value_regex))
    """
    hostname_regex = None
    attr_filter_pairs = []  # list of (compiled_key_regex, compiled_value_regex)

    try:
        tokens = shlex.split(args_str)
    except ValueError as e:
        print(f"Parsing error (check quotes): {e}")
        return None, None

    i = 0
    while i < len(tokens):
        token = tokens[i].strip()

        if token.startswith("regex:"):
            pattern = token[len("regex:"):].strip()
            if pattern:
                try:
                    hostname_regex = re.compile(pattern)
                except re.error as e:
                    print(f"Invalid hostname regex: {e}")
                    return None, None

        elif token.startswith("attr:"):
            attr_part = token[len("attr:"):].strip()

            if '=' not in attr_part:
                print(f"Invalid attribute filter format (missing =): {token}")
                return None, None

            key_pat_str, value_pat_str = attr_part.split("=", 1)
            key_pat_str = key_pat_str.strip()
            value_pat_str = value_pat_str.strip()

            # Remove surrounding quotes if present (for readability)
            for ch in ['"', "'"]:
                if value_pat_str.startswith(ch) and value_pat_str.endswith(ch):
                    value_pat_str = value_pat_str[1:-1]
                    break

            try:
                key_regex = re.compile(key_pat_str)
                value_regex = re.compile(value_pat_str)
                attr_filter_pairs.append((key_regex, value_regex))
            except re.error as e:
                print(f"Invalid regex in attribute filter: {e}")
                return None, None

        i += 1

    return hostname_regex, attr_filter_pairs

def signal_handler(sig, frame):
    """
    Function to execute when a SIGINT (Ctrl+C) is received.
    """
    print('\nSafely exiting... Cleaning up resources.')
    sys.exit(0)

def string_to_bool(s: str) -> bool:
    """
    Converts a string to a boolean with sanitization.

    Args:
        s: The string to convert.

    Returns:
        The boolean value (True or False).

    Raises:
        ValueError: If the input string is not a recognized boolean value.
    """
    # Define a mapping of acceptable input strings to boolean values
    # Convert input to lowercase to make the check case-insensitive
    bool_map = {
        'true': True, 'yes': True, 'y': True, 'on': True, '1': True,
        'false': False, 'no': False, 'n': False, 'off': False, '0': False,
        '': False # Treat empty string as False
    }

    cleaned_s = ''
    if(s is not None):
        cleaned_s = s.strip().lower() # Sanitize: remove leading/trailing whitespace and convert to lowercase

    if cleaned_s in bool_map:
        return bool_map[cleaned_s]

def get_auth_token(base_url, username, password, bypass_ssl):
    """
    Issues a POST request to Catalyst Center to obtain an access token which remains valid for
    1 hour. The token obtained is required to be set as value to the X-Auth-Token HTTP header
    for all following API calls to Catalyst Center.
    Relevant API: https://developer.cisco.com/docs/dna-center/2-3-7-9/authentication-api/
    
    :param base_url: Catalyst Center URL
    :param username: login information
    :param password: user's password
    :param bypass_ssl: true/false flag to automatically bypass SSL (true) or prompt for user input (false)
    """
    auth_str = f"{username}:{password}"
    b64_auth_str = base64.b64encode(auth_str.encode("ascii")).decode()
    headers = {
        "Authorization": f"Basic {b64_auth_str}",
        "Content-Type": "application/json"
    }
    url = f"{base_url}/dna/system/api/v1/auth/token"
    response = ''
    if(not bypass_ssl):
        try:
            response = requests.post(url, headers=headers)
        except requests.exceptions.SSLError as ssl_err:
            print(f"SSL certificate verification error encountered: {ssl_err}")
            bypass_str = input("Do you want to bypass SSL certificate verification and retry? (yes/no): ").strip().lower()
            bypass_ssl = string_to_bool(bypass_str)
    if(bypass_ssl):
        response = requests.post(url, headers=headers, verify=False)
    else:
        print(f"Aborted due to SSL certificate verification error.")
        sys.exit(0)
    response.raise_for_status()
    token = response.json().get("Token")
    return token

def get_device_inventory(base_url: str, token: str, bypass_ssl: bool):
    """
    Issues a GET request to Catalyst Center to retrieve a list of devices and their attributes
    Relevant API: https://developer.cisco.com/docs/dna-center/2-3-7-9/retrieve-network-devices/
    
    :param base_url: Catalyst Center URL
    :param token: Authentication Token retrieved from the get_auth_token function
    :param bypass_ssl: True/False flag to bypass SSL automatically (true) or prompt the user for action (false) 
    """
    url = f"{base_url}/dna/intent/api/v1/network-device"
    headers = {
        "X-Auth-Token": token,
        "Content-Type": "application/json"
    }
    response = ''
    if(not bypass_ssl):
        try:
            response = requests.get(url, headers=headers)
        except requests.exceptions.SSLError as ssl_err:
            print(f"SSL certificate verification error encountered: {ssl_err}")
            bypass_str = input("Do you want to bypass SSL certificate verification and retry? (yes/no): ").strip().lower()
            bypass_ssl = string_to_bool(bypass_str)
    if(bypass_ssl):
        response = requests.get(url, headers=headers, verify=False)
    else:
        print(f"Aborted due to SSL certificate verification error.")
        sys.exit(0)
    response.raise_for_status()
    devices_list = response.json().get("response", [])
    # Wrap each device dictionary into a Device object
    return [Device(d) for d in devices_list]

class DeviceSelector(cmd.Cmd):
    intro = "Enter device selection commands. Type 'help' or '?' for instructions."
    prompt = "(devices) "

    def __init__(self, devices, catalyst_center_url, token, bypass_ssl):
        super().__init__()
        self.devices = devices
        self.selected_devices = set()
        self.token = token
        self.catalyst_center_url = catalyst_center_url
        self.bypass_ssl = bypass_ssl

    def _match_device(self, device, hostname_regex, attr_filter_pairs):
        if hostname_regex and not hostname_regex.search(device.hostname):
            return False

        if not attr_filter_pairs:
            return True

        # For each attr filter: at least one attribute must match both key and value regex
        for key_regex, value_regex in attr_filter_pairs:
            found_match = False
            for attr_name, attr_value in device.data.items():
                if key_regex.search(attr_name):
                    if value_regex.search(str(attr_value)):
                        found_match = True
                        break
            if not found_match:
                return False  # all filters must be satisfied (AND logic)
        return True

    def do_list(self, arg):
        """
        List devices with their indices and hostnames. Supports regex for attribute keys
        and values.

        If result count > INV_LIMIT, prompts for confirmation before showing all.
        Supports filtering modes (can be combined):
          - list                          → show all devices
          - list regex:<pattern>          → filter by hostname regex (last one wins if multiple)
          - list attr:<key>=<value>       → filter by exact attribute match. Enclose values in 
                                            quotes if they contain a space.
          - Multiple attr:... are AND-ed together
          - regex + attr filters are also AND-ed

        Examples:
          list
          list regex:^SW.*01$
          list regex:core.* regex:^PE-     # only the last regex (^PE-) is used
          list attr:role=ACCESS
          list attr:role="BORDER ROUTER"
          list attr:managementIpAddress=10.95.0   # matches IPs that contain 10.95.0
          list attr:family=Catalyst attr:role=ACCESS attr:platformId=C9300
          list regex:^PE- attr:role=BORDER attr:family=Switches
          list regex:.*SW.* attr:family=Catalyst attr:role=ACCESS
        """
        arg = arg.strip()
        hostname_regex, attr_filter_pairs = parse_cli_filters(arg)

        if hostname_regex is None and attr_filter_pairs is None:
            return

        matching_devices = []
        for idx, device in enumerate(self.devices, 1):
            if self._match_device(device, hostname_regex, attr_filter_pairs):
                matching_devices.append((idx, device))

        if not matching_devices:
            print("No devices match the specified filters.")
            return

        display_count = len(matching_devices)
        if display_count > INV_LIMIT:
            print(f"Warning: {display_count} devices match the filters (limit is {INV_LIMIT}).")
            confirm = input("Display all? (yes/no): ").strip().lower()
            if confirm not in ('y', 'yes', '1', 'true'):
                print("List command aborted.")
                return

        print("Matching devices (original indices):")
        for orig_idx, device in matching_devices:
            print(f"{orig_idx}: {device.hostname}")

        print(f"Total matching: {len(matching_devices)}")

    def do_select(self, arg):
        """
        Select devices by indices, ranges, regex, and/or attribute filters. Attribute
        filters support regex for keys and values.

        Supports the same filtering syntax as the 'list' command:
          - select 3
          - select 2-5
          - select 1,4,7
          - select 1-3,5,7-9
          - select regex:^SW.*01$
          - select regex:core.*
          - select attr:role=ACCESS
          - select attr:maangementIpAddress=10.95.5  # selects IPs that contain 10.95.5
          - select attr:role="BORDER ROUTER"
          - select attr:family=Catalyst attr:role=ACCESS attr:platformId=C9300
          - select regex:^PE- attr:role=BORDER attr:family=Switches
          - select regex:.*SW.* attr:family=Catalyst attr:role=ACCESS

        Multiple 'regex:' arguments → only the last one is used.
        Multiple 'attr:key=value' → all must match (logical AND). Enclose values in quotes
                                    if they contain spaces.
        """
        arg = arg.strip()
        if not arg:
            print("Please specify device indices, ranges, regex, and/or attribute filters.")
            return

        # Pure index/range mode
        try:
            tokens = shlex.split(arg)
            if not any(t.startswith(("regex:", "attr:")) for t in tokens):
                selected = set()
                for part in arg.split(","):
                    part = part.strip()
                    if "-" in part:
                        start, end = map(int, part.split("-", 1))
                        for i in range(start, end + 1):
                            selected.add(self.devices[i - 1])
                    else:
                        idx = int(part)
                        selected.add(self.devices[idx - 1])
                if selected:
                    self.selected_devices = selected
                    print(f"Selected {len(selected)} device(s) by index/range.")
                    return
        except:
            pass

        # Filter mode
        hostname_regex, attr_filter_pairs = parse_cli_filters(arg)

        if hostname_regex is None and attr_filter_pairs is None:
            return

        selected = set()
        for device in self.devices:
            if self._match_device(device, hostname_regex, attr_filter_pairs):
                selected.add(device)

        if not selected:
            print("No devices match the specified filters.")
            return

        self.selected_devices = selected
        count = len(selected)

        desc = []
        if hostname_regex:
            desc.append(f"hostname regex: {hostname_regex.pattern}")
        if attr_filter_pairs:
            attr_desc = " AND ".join(f"{kr.pattern}={vr.pattern}" for kr, vr in attr_filter_pairs)
            desc.append(f"attributes: {attr_desc}")

        print(f"Selected {count} device(s) matching {' + '.join(desc)}.")
        print("Use 'show' or 'showattr' to view details, or 'updaterole' to modify roles.")
    
    def do_updaterole(self, arg):
        """
        Update the 'role' attribute for the selected devices. You will have to enter the
        role manually as if it were a string, case-sensitive. 

        Uses PUT request to /dna/intent/api/v1/network-device/brief with payload:
        {
            "id": "<device id>",
            "role": "<new role>",
            "roleSource": "MANUAL"
        }
        Handles SSL certificate verification errors by prompting user to bypass.
        Relevant API: https://developer.cisco.com/docs/dna-center/2-3-7-9/update-device-role/
        
        Usage:
          updaterole
        """
        if not self.selected_devices:
            print("No devices selected. Use 'select' command first.")
            return

        role = input("Enter the new role for the selected devices: ").strip()
        if not role:
            print("Role cannot be empty.")
            return

        username = os.getenv(f"{USERNAME_ENV}")
        password = os.getenv(f"{PASSWORD_ENV}")
        if not username or not password:
            print(f"Environment variables {USERNAME_ENV} and {PASSWORD_ENV} must be set.")
            return

        url_base = f"{self.catalyst_center_url}/dna/intent/api/v1/network-device/brief"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Auth-Token": self.token
        }

        success_count = 0
        error_count = 0

        for device in sorted(self.selected_devices, key=lambda d: d.hostname):
            device_id = device.data.get("id")
            if not device_id:
                print(f"Skipping {device.hostname}: no device ID found.")
                error_count += 1
                continue

            payload = {
                "id": device_id,
                "role": role,
                "roleSource": "MANUAL"
            }

            try:
                response = requests.put(url_base, auth=(username, password),
                                        headers=headers, data=json.dumps(payload))
                if response.status_code in (200, 201, 202, 204, 206):
                    print(f"{device.hostname}: role updated successfully.")
                    success_count += 1
                else:
                    print(f"{device.hostname}: failed to update role. "
                          f"Status code: {response.status_code}, Response: {response.text}")
                    error_count += 1

            except requests.exceptions.SSLError as ssl_err:
                if(not self.bypass_ssl):
                    print(f"{device.hostname}: SSL certificate verification error encountered: {ssl_err}")
                    bypass_str = input("Do you want to bypass SSL certificate verification and retry? (yes/no): ").strip().lower()
                    self.bypass_ssl = string_to_bool(bypass_str)
                if self.bypass_ssl:
                    try:
                        response = requests.put(url_base, auth=(username, password),
                                                headers=headers, data=json.dumps(payload), verify=False)
                        if response.status_code in (200, 201, 202, 204, 206):
                            print(f"{device.hostname}: role updated successfully (SSL verification bypassed).")
                            success_count += 1
                        else:
                            print(f"{device.hostname}: failed to update role even after bypassing SSL verification. "
                                  f"Status code: {response.status_code}, Response: {response.text}")
                            error_count += 1
                    except requests.RequestException as e:
                        print(f"{device.hostname}: error during update request after bypassing SSL verification: {e}")
                        error_count += 1
                else:
                    print(f"{device.hostname}: update aborted due to SSL certificate verification error.")
                    error_count += 1

            except requests.RequestException as e:
                print(f"{device.hostname}: error during update request: {e}")
                error_count += 1

        print(f"Update complete: {success_count} succeeded, {error_count} failed out of {len(self.selected_devices)} selected devices")
        self.do_refresh('')
        self.do_clear('')
    
    def do_show(self, arg):
        """
        Show information about selected devices (enhanced version).
        Supports multiple modes:

        show
            → Basic list: hostname + original index of current selection

        show detail
            → Full JSON details of current selection

        show attr <attribute_name>
            → Show the value of the specified attribute for all currently selected devices

        show regex:<pattern> [attr:key=value ...] [detail|attr <attr_name>]
            → First apply filters to current selection (last regex wins, attrs = AND)
            → Then show basic list, full details, or single attribute values
            → If a value has a space, enclose the entire value in quotes
            → Supports regex for attribute keys and values for partial matches

        Examples:
          show
          show detail
          show attr role
          show attr dnsResolvedManagementAddress
          show regex:^core.* attr role
          show regex:^PE- attr:role=BORDER attr family detail
          show attr role regex:SW.* attr:family=Catalyst
          show attr:role="BORDER ROUTER"
        """
        arg = arg.strip()
        parts = shlex.split(arg) if arg else []

        show_detail = "detail" in parts
        show_attr_name = None
        if "attr" in parts:
            idx = parts.index("attr")
            if idx + 1 < len(parts):
                show_attr_name = parts[idx + 1]
                if show_attr_name.startswith(('"', "'")) and show_attr_name.endswith(('"', "'")):
                    show_attr_name = show_attr_name[1:-1]

        filter_parts = [p for p in parts if p not in ("detail", "attr", show_attr_name)]

        if filter_parts:
            filter_str = " ".join(filter_parts)
            hostname_regex, attr_filter_pairs = parse_cli_filters(filter_str)
            if hostname_regex is None and attr_filter_pairs is None:
                return
        else:
            hostname_regex = None
            attr_filter_pairs = []

        devices_to_show = {
            d for d in self.selected_devices
            if self._match_device(d, hostname_regex, attr_filter_pairs)
        }

        if not devices_to_show:
            print("No devices match within current selection.")
            return

        count = len(devices_to_show)
        sorted_devices = sorted(
            ((self.devices.index(d) + 1, d) for d in devices_to_show),
            key=lambda x: x[1].hostname
        )

        if not show_detail and count > INV_LIMIT:
            print(f"Warning: {count} devices (limit {INV_LIMIT})")
            if input("Display all? (yes/no): ").strip().lower() not in ('y', 'yes'):
                return

        if show_attr_name:
            print(f"Attribute '{show_attr_name}' for {count} device(s):")
            print("-" * 70)
            for idx, dev in sorted_devices:
                val = dev.data.get(show_attr_name, "<not found>")
                print(f"{idx}: {dev.hostname:40} → {val}")
            print(f"Total: {count}")
            return

        header = f"{'Detailed' if show_detail else 'Basic'} view of {count} device(s)"
        if filter_parts:
            header += " matching additional filters"
        print(header + " (original indices):")
        print("-" * 80)

        if show_detail:
            for _, dev in sorted_devices:
                print(dev.to_json())
                print("-" * 80)
        else:
            for idx, dev in sorted_devices:
                print(f"{idx}: {dev.hostname}")

        print(f"Total displayed: {count}")

    def do_clear(self, arg):
        "Clear current selection."
        self.selected_devices.clear()
        print("Selection cleared.")

    def do_refresh(self, arg):
        "Refresh device inventory"
        self.devices = get_device_inventory(self.catalyst_center_url, self.token, self.bypass_ssl)
        print("Inventory refreshed.")

    def do_exit(self, arg):
        "Exit the selector."
        print("Exiting.")
        return True

    def do_help(self, arg):
        if arg:
            return super().do_help(arg)
        print("""
Commands:
  list <args>     - List all devices with indices and hostnames.
  select <args>   - Select devices by indices, ranges, or regex.
  show <args>     - Show detailed info for selected devices.
  updaterole      - Update the role attribute for selected devices
  clear           - Clear current selection.
  refresh         - Refresh the device inventory
  exit            - Exit the selector.
  help <args>     - Explain commands with `help` or explain a command in detail with `help <command>`
              Examples:
                - help list
                - help updaterole
""")

def main():
    catalyst_center_url = os.getenv(CATALYST_CENTER_URL_ENV)
    username = os.getenv(USERNAME_ENV)
    password = os.getenv(PASSWORD_ENV)
    bypass_ssl_str = os.getenv(BYPASS_SSL_ENV)
    bypass_ssl = string_to_bool(bypass_ssl_str)
    signal.signal(signal.SIGINT, signal_handler)

    if not all([catalyst_center_url, username, password]):
        print(f"Please set {CATALYST_CENTER_URL_ENV}, {USERNAME_ENV}, and {PASSWORD_ENV} environment variables.")
        print(f"{CATALYST_CENTER_URL_ENV}={'set' if catalyst_center_url is not None else 'unset'}")
        print(f"{USERNAME_ENV}={'set' if username is not None else 'unset'}")
        print(f"{PASSWORD_ENV}={'set' if password is not None else 'unset'}")
        exit(1)

    token = get_auth_token(catalyst_center_url, username, password, bypass_ssl)
    inventory = get_device_inventory(catalyst_center_url, token, bypass_ssl)

    if not inventory:
        print("No devices found in inventory.")
        return

    if(len(inventory) < INV_LIMIT):
        print("Device Inventory Hostnames:")
        for idx, device in enumerate(inventory, 1):
            print(f"{idx}: {device.hostname}")
    else:
        print(f"Inventory size greater than {INV_LIMIT}, please use `list` command to show all devices")

    selector = DeviceSelector(inventory, catalyst_center_url, token, bypass_ssl)
    selector.cmdloop()

if __name__ == "__main__":
    main()
