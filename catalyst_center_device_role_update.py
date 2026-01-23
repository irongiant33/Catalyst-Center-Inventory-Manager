import os
import sys
import signal
import requests
import base64
import json
import re
import cmd

class Device:
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

def get_device_inventory(base_url, token, bypass_ssl):
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
    prompt = "(select) "

    def __init__(self, devices, catalyst_center_url, token, bypass_ssl):
        super().__init__()
        self.devices = devices
        self.selected_devices = set()
        self.token = token
        self.catalyst_center_url = catalyst_center_url
        self.bypass_ssl = bypass_ssl

    def do_list(self, arg):
        "List all devices with their indices and hostnames."
        for idx, device in enumerate(self.devices, 1):
            print(f"{idx}: {device.hostname}")

    def do_select(self, arg):
        """
        Select devices by indices, ranges, or regex patterns.
        Examples:
          select 3
          select 2-5
          select 1,4,7
          select 1-3,5,7-9
          select regex:^SW.*01$
        """
        arg = arg.strip()
        if not arg:
            print("Please specify device indices, ranges, or regex pattern.")
            return

        selected = set()

        if arg.startswith("regex:"):
            pattern = arg[len("regex:"):].strip()
            try:
                regex = re.compile(pattern)
            except re.error as e:
                print(f"Invalid regex pattern: {e}")
                return
            for device in self.devices:
                if regex.search(device.hostname):
                    selected.add(device)
        else:
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
            print("No devices matched your selection.")
            return

        self.selected_devices = selected
        print(f"Selected {len(self.selected_devices)} device(s). Use 'show' to display details.")

    def do_showattr(self, arg):
        """
        Show specific attribute(s) of the selected devices.
        Usage:
          showattr <attribute_name>
        Example:
          showattr role
        """
        attr = arg.strip()
        if not attr:
            print("Please specify an attribute name to show.")
            return
        if not self.selected_devices:
            print("No devices selected. Use 'select' command first.")
            return

        for device in sorted(self.selected_devices, key=lambda d: d.hostname):
            # Safely get the attribute from the device data dictionary
            value = device.data.get(attr, "<Attribute not found>")
            print(f"{device.hostname}: {attr} = {value}")
    
    def do_updaterole(self, arg):
        """
        Update the 'role' attribute for the selected devices.
        Uses PUT request to /dna/intent/api/v1/network-device/brief with payload:
        {
            "id": "<device id>",
            "role": "<new role>",
            "roleSource": "string"
        }
        Handles SSL certificate verification errors by prompting user to bypass.
        Usage:
          updateattr
        """
        if not self.selected_devices:
            print("No devices selected. Use 'select' command first.")
            return

        role = input("Enter the new role for the selected devices: ").strip()
        if not role:
            print("Role cannot be empty.")
            return

        username = os.getenv("CATALYST_CENTER_USERNAME")
        password = os.getenv("CATALYST_CENTER_PASSWORD")
        if not username or not password:
            print("Environment variables CATALYST_CENTER_USERNAME and CATALYST_CENTER_PASSWORD must be set.")
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
        "Show detailed inventory for selected devices."
        if not self.selected_devices:
            print("No devices selected. Use 'select' command first.")
            return
        for device in sorted(self.selected_devices, key=lambda d: d.hostname):
            print(device.to_json())
            print("-" * 40)

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
        print(self.__doc__)
        print("""
Commands:
  list            - List all devices with indices and hostnames.
  select <args>   - Select devices by indices, ranges, or regex.
                    Examples:
                      select 3
                      select 2-5
                      select 1,4,7
                      select 1-3,5,7-9
                      select regex:^SW.*01$
  show            - Show detailed info for selected devices.
  showattr        - Show a specific attribute for selected devices by specifying the key name shown with the show command (ex: showattr role)
  updaterole      - Update the role attribute for selected devices
  clear           - Clear current selection.
  refresh         - Refresh the device inventory
  exit            - Exit the selector.
""")

def main():
    catalyst_center_url = os.getenv("CATALYST_CENTER_URL")
    username = os.getenv("CATALYST_CENTER_USER")
    password = os.getenv("CATALYST_CENTER_PASSWORD")
    bypass_ssl_str = os.getenv("CATALYST_CENTER_SSL_BYPASS")
    bypass_ssl = string_to_bool(bypass_ssl_str)
    signal.signal(signal.SIGINT, signal_handler)

    if not all([catalyst_center_url, username, password]):
        raise EnvironmentError("Please set CATALYST_CENTER_URL, CATALYST_CENTER_USER, and CATALYST_CENTER_PASSWORD environment variables.")

    token = get_auth_token(catalyst_center_url, username, password, bypass_ssl)
    inventory = get_device_inventory(catalyst_center_url, token, bypass_ssl)

    if not inventory:
        print("No devices found in inventory.")
        return

    print("Device Inventory Hostnames:")
    for idx, device in enumerate(inventory, 1):
        print(f"{idx}: {device.hostname}")

    selector = DeviceSelector(inventory, catalyst_center_url, token, bypass_ssl)
    selector.cmdloop()

if __name__ == "__main__":
    main()
