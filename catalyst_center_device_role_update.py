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
    Returns (regex_pattern: re.Pattern | None, attr_filters: dict)
    """
    regex_pattern = None
    attr_filters = {}

    # shlex handles quotes properly
    try:
        tokens = shlex.split(args_str)
    except ValueError as e:
        print(f"Parsing error (check quotes): {e}")
        return None, None

    i = 0
    while i < len(tokens):
        token = tokens[i]

        if token.startswith("regex:"):
            pattern = token[len("regex:"):].strip()
            if pattern:
                try:
                    regex_pattern = re.compile(pattern)
                except re.error as e:
                    print(f"Invalid regex: {e}")
                    return None, None
        elif token.startswith("attr:"):
            # attr:key=value  or  attr:"key with space"=value
            attr_part = token[len("attr:"):].strip()

            # Find the = sign (could be after quoted key)
            if '=' not in attr_part:
                print(f"Invalid attr format (missing =): {token}")
                return None, None

            key_part, value_part = attr_part.split("=", 1)
            key = key_part.strip()
            value = value_part.strip()

            # Remove surrounding quotes from value if present
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]

            attr_filters[key] = value

        i += 1

    return regex_pattern, attr_filters

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

    def do_list(self, arg):
        """
        List devices with their indices and hostnames.
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
          list attr:family=Catalyst attr:role=ACCESS attr:platformId=C9300
          list regex:^PE- attr:role=BORDER attr:family=Switches
          list regex:.*SW.* attr:family=Catalyst attr:role=ACCESS
        """
        arg = arg.strip()
        regex_pattern, attr_filters = parse_cli_filters(arg)

        if regex_pattern is None and attr_filters is None:
            return

        use_regex = regex_pattern is not None
        use_attr = bool(attr_filters)

        # Collect matching devices
        matching_devices = []
        for idx, device in enumerate(self.devices, 1):
            match = True

            # Apply regex (only the last one, if any)
            if use_regex:
                if not regex_pattern.search(device.hostname):
                    match = False

            # Apply all attribute filters (must match EVERY one)
            if use_attr and match:
                for key, required_value in attr_filters.items():
                    actual_value = device.data.get(key)
                    if actual_value is None or str(actual_value) != required_value:
                        match = False
                        break

            if match:
                matching_devices.append((idx, device))

        if not matching_devices:
            if use_regex and use_attr:
                attr_str = " AND ".join(f"{k}={v}" for k, v in attr_filters.items())
                print(f"No devices match regex pattern AND attributes: {attr_str}")
            elif use_regex:
                print("No devices match the regex pattern.")
            elif use_attr:
                attr_str = " AND ".join(f"{k}={v}" for k, v in attr_filters.items())
                print(f"No devices match attributes: {attr_str}")
            else:
                print("No devices found.")
            return

        # Apply display limit check
        display_count = len(matching_devices)
        if display_count > INV_LIMIT:
            if use_regex and use_attr:
                attr_str = " AND ".join(f"{k}={v}" for k, v in attr_filters.items())
                msg = f"Warning: {display_count} devices match regex + {attr_str} "
            elif use_regex:
                msg = f"Warning: {display_count} devices match the regex pattern "
            elif use_attr:
                attr_str = " AND ".join(f"{k}={v}" for k, v in attr_filters.items())
                msg = f"Warning: {display_count} devices match {attr_str} "
            else:
                msg = f"Warning: {display_count} devices in inventory "

            msg += f"(limit is {INV_LIMIT})."
            print(msg)

            confirm = input("Display all devices? (yes/no): ").strip().lower()
            if confirm not in ('y', 'yes', '1', 'true'):
                print("List command aborted.")
                return

        # Display header
        header_parts = []
        if use_regex:
            header_parts.append(f"regex:{regex_pattern.pattern}")
        if use_attr:
            attr_str = " AND ".join(f"{k}={v}" for k, v in attr_filters.items())
            header_parts.append(f"attributes: {attr_str}")

        if header_parts:
            print(f"Matching devices ({' + '.join(header_parts)}, original indices):")
        else:
            print("Device Inventory (original indices):")

        for orig_idx, device in matching_devices:
            print(f"{orig_idx}: {device.hostname}")

        print(f"Total matching: {len(matching_devices)}")

    def do_select(self, arg):
        """
        Select devices by indices, ranges, regex, and/or attribute filters.
        Supports the same filtering syntax as the 'list' command:
          - select 3
          - select 2-5
          - select 1,4,7
          - select 1-3,5,7-9
          - select regex:^SW.*01$
          - select regex:core.*
          - select attr:role=ACCESS
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

        # First, check if this is an index/range selection (no regex/attr keywords)
        if not any(p.startswith(("regex:", "attr:")) for p in arg.split()):
            selected = set()
            parts = arg.split(",")
            for part in parts:
                part = part.strip()
                if "-" in part:
                    try:
                        start_str, end_str = part.split("-", 1)
                        start = int(start_str)
                        end = int(end_str)
                        if start < 1 or end > len(self.devices) or start > end:
                            print(f"Invalid range: {part}")
                            continue
                        for i in range(start, end + 1):
                            selected.add(self.devices[i - 1])
                    except ValueError:
                        print(f"Invalid range format: {part}")
                else:
                    try:
                        idx = int(part)
                        if idx < 1 or idx > len(self.devices):
                            print(f"Index out of range: {idx}")
                            continue
                        selected.add(self.devices[idx - 1])
                    except ValueError:
                        print(f"Invalid index: {part}")
            if not selected:
                print("No valid devices selected.")
                return
            self.selected_devices = selected
            print(f"Selected {len(self.selected_devices)} device(s). Use 'show' or 'showattr' to view details.")
            return

        # --- Filter mode (regex and/or attr) ---
        regex_pattern, attr_filters = parse_cli_filters(arg)

        if regex_pattern is None and attr_filters is None:
            return

        use_regex = regex_pattern is not None
        use_attr = bool(attr_filters)

        if not (use_regex or use_attr):
            print("No valid filter provided.")
            return

        # Collect matching devices
        selected = set()
        for device in self.devices:
            match = True

            # Apply regex (only the last one, if present)
            if use_regex:
                if not regex_pattern.search(device.hostname):
                    match = False

            # Apply all attribute filters (must match EVERY one)
            if use_attr and match:
                for key, required_value in attr_filters.items():
                    actual_value = device.data.get(key)
                    if actual_value is None or str(actual_value) != required_value:
                        match = False
                        break

            if match:
                selected.add(device)

        if not selected:
            if use_regex and use_attr:
                attr_str = " AND ".join(f"{k}={v}" for k, v in attr_filters.items())
                print(f"No devices match regex pattern AND attributes: {attr_str}")
            elif use_regex:
                print("No devices match the regex pattern.")
            elif use_attr:
                attr_str = " AND ".join(f"{k}={v}" for k, v in attr_filters.items())
                print(f"No devices match attributes: {attr_str}")
            return

        self.selected_devices = selected
        count = len(self.selected_devices)

        # Build feedback message
        filter_desc = []
        if use_regex:
            filter_desc.append(f"regex:{regex_pattern.pattern}")
        if use_attr:
            attr_str = " AND ".join(f"{k}={v}" for k, v in attr_filters.items())
            filter_desc.append(f"attributes: {attr_str}")

        desc = " + ".join(filter_desc) if filter_desc else "no filter"
        print(f"Selected {count} device(s) matching {desc}.")
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
        parts = arg.split() if arg else []

        # Detect requested mode
        show_detail = "detail" in parts
        show_attr = "attr" in parts

        # Remove known mode keywords to get filter parts
        filter_parts = []
        attr_name = None

        i = 0
        while i < len(parts):
            p = parts[i]
            if p in ("detail", "attr"):
                if p == "attr":
                    # Expect one more token as attribute name
                    i += 1
                    if i < len(parts):
                        attr_name = parts[i].strip()
                    else:
                        print("Error: 'attr' keyword requires an attribute name (e.g. attr role)")
                        return
                # skip the keyword itself
            else:
                filter_parts.append(p)
            i += 1

        # If attr mode is active → it takes precedence over detail
        if show_attr and not attr_name:
            print("Error: 'attr' keyword requires an attribute name (e.g. show attr role)")
            return

        # If no filters → use current selection
        if not filter_parts:
            devices_to_show = self.selected_devices
            filter_desc = "currently selected"
        else:
            filter_str = " ".join(filter_parts)
            regex_pattern, attr_filters = parse_cli_filters(filter_str)

            if regex_pattern is None and attr_filters is None:
                return

            use_regex = regex_pattern is not None
            use_attr_filters = bool(attr_filters)

            if not (use_regex or use_attr_filters):
                print("No valid filter provided.")
                return

            # Filter from current selection
            devices_to_show = set()
            for device in self.selected_devices:
                match = True
                if use_regex and not regex_pattern.search(device.hostname):
                    match = False
                if use_attr_filters and match:
                    for key, req_val in attr_filters.items():
                        actual = device.data.get(key)
                        if actual is None or str(actual) != req_val:
                            match = False
                            break
                if match:
                    devices_to_show.add(device)

            # Build description
            desc_parts = []
            if use_regex:
                desc_parts.append(f"regex:{regex_pattern.pattern}")
            if use_attr_filters:
                desc_parts.append("attributes: " + " AND ".join(f"{k}={v}" for k,v in attr_filters.items()))
            filter_desc = " + ".join(desc_parts)

        if not devices_to_show:
            print(f"No devices match the specified filters within current selection.")
            return

        count = len(devices_to_show)

        # Prepare sorted list with original indices
        sorted_devices = sorted(
            ((self.devices.index(d) + 1, d) for d in devices_to_show),
            key=lambda x: x[1].hostname
        )

        # Limit check (only for basic list and attr mode)
        if not show_detail:
            if count > INV_LIMIT:
                print(f"Warning: {count} devices to display (limit is {INV_LIMIT}).")
                confirm = input("Display all? (yes/no): ").strip().lower()
                if confirm not in ('y', 'yes', '1', 'true'):
                    print("Show command aborted.")
                    return

        # ── Output ───────────────────────────────────────────────────────────────

        if show_attr:
            # Single attribute mode
            print(f"Attribute '{attr_name}' for {count} device(s) matching {filter_desc}:")
            print("-" * 60)
            for orig_idx, device in sorted_devices:
                value = device.data.get(attr_name, "<not found>")
                print(f"{orig_idx}: {device.hostname:40} → {attr_name} = {value}")
            print("-" * 60)
            print(f"Total: {count}")
            return

        # Normal modes (basic list or detail)
        if show_detail:
            header = f"Detailed information for {count} device(s)"
        else:
            header = f"Basic list of {count} device(s)"

        if filter_desc != "currently selected":
            header += f" matching {filter_desc}"
        header += " (original indices):"

        print(header)
        print("-" * 80)

        if show_detail:
            for _, device in sorted_devices:
                print(device.to_json())
                print("-" * 80)
        else:
            for orig_idx, device in sorted_devices:
                print(f"{orig_idx}: {device.hostname}")
            print("-" * 80)

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
