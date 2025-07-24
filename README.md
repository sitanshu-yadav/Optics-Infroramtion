# Optics Information Cisco_Juniper_Extreme

This script automates the retrieval and parsing of optical transceiver information from Cisco, Juniper, and Extreme network devices. It connects to devices via SSH, runs relevant commands, and extracts Rx power and threshold data for specified interfaces.

## Features

- **Device Type Detection:** Automatically detects device type (Cisco, Juniper, Extreme) based on hostname.
- **Encrypted Passwords:** Supports password decryption using OpenSSL.
- **Interface Search:** Searches for interfaces by description.
- **Optics Data Extraction:** Retrieves and parses Rx power and threshold values.
- **Vendor-Specific Handling:** Runs appropriate commands for each vendor.

## Requirements

- Python 3.x
- [netmiko](https://pypi.org/project/netmiko/)
- [pycryptodome](https://pypi.org/project/pycryptodome/)
- OpenSSL (for password decryption)
- pip install netmiko pycryptodome

Install dependencies:
```sh
pip install netmiko pycryptodome
```

## Usage

1. **Edit Credentials:**
   - Set the following variables in the script:
     - `enc_file`: Path to the encrypted password file.
     - `decryption_key`: Passphrase for decryption.
     - `username`: Username for device login.

2. **Run the Script:**
   ```sh
   python Optics\ Information\ Cisco_Juniper_Extreme.py
   ```

3. **Follow Prompts:**
   - Enter the device hostname (e.g., `csco-router1`).
   - Enter the string to search for in interface descriptions.

## Example

```
Enter device hostname--- csco-router1
Enter host/device name to search in interface description: core-link
```

The script will connect to the device, search for interfaces matching the description, and display optics information.

## Notes

- Hostnames should contain `csco`, `jnpr`, or `extr` to detect device type.
- The script assumes device hostnames are resolvable with `.wlink.com.np` domain.
- Update the script as needed for your network environment.
