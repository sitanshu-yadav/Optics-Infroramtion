from netmiko import ConnectHandler
from Crypto.Cipher import AES
import hashlib
import os
import subprocess
import re

#-----------------------------------------------------------------------------
#DECRYPT-PASSWORD
#-----------------------------------------------------------------------------
def decrypt_password_openssl(enc_file, passphrase):
    try:
        result = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-d", "-in", enc_file, "-pass", f"pass:{passphrase}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return result.stdout.decode().strip()
    except subprocess.CalledProcessError as e:
        print(f"OpenSSL error: {e.stderr.decode().strip()}")
        return None
#------------------------------------------------------------------------------
#DETECT DEVICE TYPE
#------------------------------------------------------------------------------
def detect_device_type(hostname):
    name = hostname.lower()
    if "csco" in name or name=='......'or name=='......':
        return "cisco_xr"
    elif "jnpr" in name or 'gw-' in name:
        return "juniper"
    elif "extr" in name:
        return "extreme"
    elif "olt" in name:
        return "nokia_sros"

    else:
        return None
#-----------------------------------------------------------------------------
#CONNECT TO DEVICE
#-----------------------------------------------------------------------------
def connect_device(hostname, username, password, device_type):
    device = {
        "device_type": device_type,
        "host": hostname + ".wlink.com.np",
        "username": username,
        "password": password,
        "conn_timeout": 40,
    }

    try:
        print(f"\n[✓] Connecting to {hostname}...")
        conn = ConnectHandler(**device)
        return conn
    except Exception as e:
        print(f"\n[✗] Connection to {hostname} failed: {e}")
        return None
#-----------------------------------------------------------------------------
#CISCO HANDELING COMMAND \TO MATCH DESCRIPTION AND CHECK POWER LEVEL  
#-----------------------------------------------------------------------------
def handle_cisco(conn,host_search,hostname):
  #  print("[✓] Cisco CLI History:")
  #  output = conn.send_command("show version")
  #  print(output)
  #  print(host_search)
    print("[✓]"+ hostname)
    interface_output = conn.send_command(f"show interface description | include {host_search}")
    print(interface_output)
    # Extract physical interface names ---
    # Match strings like Te0/0/0/19 or Gi0/0/1 etc. at beginning of line
    try:
        interfaces = re.findall(r'^(?:Te|Hu|TF|Fo)\S+', interface_output, re.MULTILINE)
        # Remove duplicates and preserve order
        seen = set()
        unique_interfaces = [i for i in interfaces if not (i in seen or seen.add(i))]
        # Run "show controller <interface>" for each ---
        print("\n[Filtered Controller Info for Interfaces]\n")
        filter_cmd = '| include "interface|Rx Power|Receive|n/a|Lane|Threshold|Warning" | exclude control'
        for iface in unique_interfaces:
            print(f"\n--- show controller {iface} (filtered) ---")
            full_cmd = f"show controller {iface} {filter_cmd}"
            ctrl_output = conn.send_command(full_cmd)
            print(ctrl_output)


        print("[✓]"+ hostname)
        print(interface_output)
        print("\n Summary \n")
        print("[✓]"+ hostname)

        for iface in unique_interfaces:
            ctrl_output = conn.send_command(f"show controller {iface}")

            # Te interfaces (single Rx Power line)
            if iface.startswith("Te") or iface.startswith("TenGigE"):
                rx_values = []
                thresholds = []
                # --- 1. Extract Rx Power (usually single lane) ---
                for line in ctrl_output.splitlines():
                    if re.search(r'\s+-?\d+\.\d+\s+', line):
                        parts = line.split()
                        if len(parts) >= 5:
                            rx_values.append(parts[4])
                            break

                # --- 2. Extract Thresholds for Rx Power ---
                for line in ctrl_output.splitlines():
                    if "Receive Power (dBm):" in line:
                        thresholds = line.split(":")[1].split()
                        break

                # --- Display ---
                if rx_values:
                    print(f"{iface}: Rx Power = {rx_values[0]} dBm")
                else:
                    print(f"{iface}: Rx Power not found")

                if len(thresholds) == 4:
                    print(f"Thresholds (dBm) = Alarm High: {thresholds[0]}, Warn High: {thresholds[1]}, Warn Low: {thresholds[2]}, Alarm Low: {thresholds[3]}\n")
                else:
                    print(f"Thresholds not found or incomplete\n")

######Twentifive
            elif iface.startswith("TF") or iface.startswith("TwentyFiveGigE"):
                rx_values = []
                thresholds = []
                # --- 1. Extract Rx Power (usually single lane) ---
                for line in ctrl_output.splitlines():
                    if re.search(r'\s+-?\d+\.\d+\s+', line):
                        parts = line.split()
                        if len(parts) >= 5:
                            rx_values.append(parts[4])
                            break

                # --- 2. Extract Thresholds for Rx Power ---
                for line in ctrl_output.splitlines():
                    if "Receive Power (dBm):" in line:
                        thresholds = line.split(":")[1].split()
                        break

                # --- Display ---
                if rx_values:
                    print(f"{iface}: Rx Power = {rx_values[0]} dBm")
                else:
                    print(f"{iface}: Rx Power not found")

                if len(thresholds) == 4:
                    print(f"Thresholds (dBm) = Alarm High: {thresholds[0]}, Warn High: {thresholds[1]}, Warn Low: {thresholds[2]}, Alarm Low: {thresholds[3]}\n")
                else:
                    print(f"Thresholds not found or incomplete\n")

##### Fourty 
            elif iface.startswith("Fo") or iface.startswith("FortyGigE"):
                rx_values = []
                thresholds = []
                # --- 1. Extract Rx Power (usually single lane) ---
                for line in ctrl_output.splitlines():
                    if re.search(r'\s+-?\d+\.\d+\s+', line):
                        parts = line.split()
                        if len(parts) >= 5:
                            rx_values.append(parts[4])
                            break

                # --- 2. Extract Thresholds for Rx Power ---
                for line in ctrl_output.splitlines():
                    if "Receive Power (dBm):" in line:
                        thresholds = line.split(":")[1].split()
                        break

                # --- Display ---
                if rx_values:
                    print(f"{iface}: Rx Power = {rx_values[0]} dBm")
                else:
                    print(f"{iface}: Rx Power not found")

                if len(thresholds) == 4:
                    print(f"Thresholds (dBm) = Alarm High: {thresholds[0]}, Warn High: {thresholds[1]}, Warn Low: {thresholds[2]}, Alarm Low: {thresholds[3]}\n")
                else:
                    print(f"Thresholds not found or incomplete\n")



            # Hu interfaces (multiple lanes)
            elif iface.startswith("Hu") or iface.startswith("HundredGigE"):
                rx_values = []
                thresholds = []


        # --- 1. Extract per-lane Rx Power values ---
                for line in ctrl_output.splitlines():
                    if re.match(r'^\s*[0-3]\s+', line) and re.search(r'-?\d+\.\d+', line):
                        parts = line.split()
                        if len(parts) >= 5:
                            rx_values.append(parts[4])

        # --- 2. Extract Receive Power Thresholds (dBm) ---
                for line in ctrl_output.splitlines():
                    if "Receive Power (dBm):" in line:
                        thresholds = line.split(":")[1].split()
                        break

        # --- Display Results ---
                if rx_values:
                    print(f"{iface}: Rx Powers per lane = {', '.join(rx_values)} dBm")
                else:
                    print(f"{iface}: Rx lane Rx Power not found")

                if len(thresholds) == 4:
                    print(f"Thresholds (dBm) = Alarm High: {thresholds[0]}, Warn High: {thresholds[1]}, Warn Low: {thresholds[2]}, Alarm Low: {thresholds[3]}\n")
                else:
                    print(f"Threshold values not found or incomplete\n")

    except Exception as e:
        print(e)
        print("\n An error occured while executing Command")
    # Add more Cisco-specific operations here

#-----------------------------------------------------------------------------
#JUNIPER HANDELING COMMAND \ TO MACH DESCRIPTION AND CHECK POWER LEVEL
#-----------------------------------------------------------------------------
def handle_juniper(conn,host_search,hostname):
   # print("[✓] Juniper Uptime:")
   # output = conn.send_command("show system uptime")
   # print(output)
   # print(host_search)
    try:
        print("[✓]"+ hostname)
        description_output=conn.send_command("show interfaces descriptions | match " + host_search + "| except \\.")
        print(description_output)
        interfaces = re.findall(r'^(xe-\S+|et-\S+)', description_output, re.MULTILINE) 
        filter_cmd1 = '| match "Lane|dBm|rx" | except "alarm|loss|Inf|output|off" '
    
        print("[✓]"+ hostname)

        for iface in interfaces:
            print(f"\n--- Optics Info for {iface} ---")
            output = conn.send_command(f"show interfaces diagnostics optics {iface} {filter_cmd1}")
            print(output)

            output = conn.send_command(f"show interfaces {iface} | match flap")

            print(output)
    except Exception as e:
        print(f"Error while parsing optics output: {e}")
    

    try:
        print(f"[✓] {hostname}")
        description_output = conn.send_command(f"show interfaces descriptions | match {host_search} | except \\.")
        print(description_output)

        # Extract interfaces from description output
        interfaces = re.findall(r'^(xe-\S+|et-\S+|ge-\S+|ae\d+)', description_output, re.MULTILINE)
        print("\n Summary \n")
        print("[✓]"+ hostname)

        for iface in interfaces:
            if iface.startswith(("ae", "lo", "irb", "reth")):
                continue
          # print(f"\n--- Checking optics for {iface} ---")

            # Get optics diagnostics
            output = conn.send_command(f"show interfaces diagnostics optics {iface}")

            # Parse thresholds
            high_warn = re.search(r'Laser rx power high warning threshold\s+:\s+[\d.]+\s+mW\s+/\s+([-\d.]+)\s+dBm', output)
            low_warn = re.search(r'Laser rx power low warning threshold\s+:\s+[\d.]+\s+mW\s+/\s+([-\d.]+)\s+dBm', output)
            high_alarm = re.search(r'Laser rx power high alarm threshold\s+:\s+[\d.]+\s+mW\s+/\s+([-\d.]+)\s+dBm', output)
            low_alarm = re.search(r'Laser rx power low alarm threshold\s+:\s+[\d.]+\s+mW\s+/\s+([-\d.]+)\s+dBm', output)



            # Parse lane RX powers
            lane_powers = re.findall(r'(?:Laser receiver power|Laser rx power)\s+:\s+[\d.]+\s+mW\s+/\s+([-\d.]+)\s+dBm', output)

            # Get flap info
            flap_output = conn.send_command(f"show interfaces {iface} | match flap")
            flap_match = re.search(r'Last flapped\s*:\s*(.*)', flap_output)

            # Format and print results
            if lane_powers:
                rx_power_str = ", ".join(lane_powers)
            else:
                rx_power_str = "N/A"

            print(f"{iface}: Rx Powers per lane = {rx_power_str} dBm")
            print(f"Thresholds (dBm) = Warn High: {high_warn.group(1) if high_warn else 'N/A'}, Warn Low: {low_warn.group(1) if low_warn else 'N/A'}, Alarm High: {high_alarm.group(1) if high_alarm else 'N/A'}, Alarm Low : {low_alarm.group(1) if low_alarm else 'N/A'}\n")
        #    print('\n')

       #    if flap_match:
        #       print(f"Last Flap: {flap_match.group(1)}")

    except Exception as e:
        print(f"[✗] Error while parsing optics output: {e}")



    # Add more Juniper-specific operations here

#-----------------------------------------------------------------------------
#EXTREME HANDELING COMMAND \ MATCH DESCRIPTION AND CHECK POWER LEVEL
#-----------------------------------------------------------------------------
def handle_extreme(conn,host_search,hostname):
  #  print("[✓] Extreme Inventory:")
  #  output = conn.send_command("show version")
  #  print(output)
  #  print(host_search)
    try:
        print("[✓]"+ hostname)
        print(conn.send_command("show port no-refresh | include " + host_search))
        output = conn.send_command("show ports description | include " + host_search)
        output = output.split("\n")
        output_text = "\n".join(output)
        port_numbers = [int(match) for match in re.findall(r'^\s*(\d+)', output_text, re.MULTILINE)]


        ports_c = ','.join(map(str, port_numbers))
        command = conn.send_command(f"show port {ports_c} tr i ")
        print(command)
        command = conn.send_command(f"show port {ports_c} tr i d ")
        print(command)

    except Exception as e:
            print(e)



#------------------------------------------------------------------------------
#HANDLE OLT
#------------------------------------------------------------------------------
def handle_olt(conn,host_search,hostname):
    try:
        print("[✓]"+ hostname)
        conn.send_command(f"environment inhibit-alarms", expect_string=r"#")
        print("\n🔍 Fetching port descriptions...")
        output = conn.send_command("show port description | match nt-a:xfp", expect_string=r"#")
        print(output)
        print("\n 🔍 Fetching Port Status...")
        output1 = conn.send_command("show port | match nt-a:xfp", expect_string=r"#")
        print(output1)
        print("\n")
        # Step 2: Parse lines and find ports matching keyword
        lines = output.strip().splitlines()
        matching_ports = []

        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                port_name = parts[0].strip()
                description = " ".join(parts[1:]).strip()
                if host_search in description:
                    matching_ports.append(port_name)
                    print(f"   ✅ Matched: {port_name} → '{description}'")

        if not matching_ports:
            print(f"❌ No ports found with keyword '{host_search}'")
            exit()

        # Step 3: For each matching port, get SFP diagnostics
        print(f"\n📊 Fetching SFP diagnostics for {len(matching_ports)} port(s)...\n")

        for port in matching_ports:
            print(f"--- {port} ---")
            try:
                sfp_output = conn.send_command(
                f"show equipment diagnostics sfp {port} detail",
                cmd_verify=False,
                expect_string=r"#",
                read_timeout=30
                )
        # Extract RX Power
                rx_match = re.search(r'^\s*rx-power\s*:\s*"([+-]?\d+\.\d+)\s*dBm"', sfp_output, re.MULTILINE | re.IGNORECASE)
                tx_match = re.search(r'^\s*tx-power\s*:\s*"([+-]?\d+\.\d+)\s*dBm"', sfp_output, re.MULTILINE | re.IGNORECASE)
                tx_power = tx_match.group(1) if tx_match else "N/A"


                if rx_match:
                    rx_power = rx_match.group(1)
                    print(f"📡 RX Power: {rx_power} dBm")

                else:
                    print("⚠  RX Power not found in output")
                    print("👉 Check raw output above for clues")

                print(f"📡 TX Power: {tx_power} dBm")
                print()

            except Exception as e:
                print(f"❌ Command failed for {port}: {e}")

    except Exception as e:
        print(f"❌ Error: {e}")

#-----------------------------------------------------------------------------
#DISCONNECT DEVICE
#-----------------------------------------------------------------------------
def disconnect_device(conn):
    if conn:
        conn.disconnect()
        print("[✓] Session closed.")


#-----------------------------------------------------------------------------
#MAIN PROGRAM
#-----------------------------------------------------------------------------
if __name__ == "__main__":
    enc_file = "******************"
    decryption_key = "************"
    username = "*************"

    hostname = input("Enter device hostname--- ").strip()
    host_search = input("Enter host/device name to search in interface description: ")

    try:
        password = decrypt_password_openssl(enc_file, decryption_key)
    except Exception as e:
        print(f"[✗] Failed to decrypt password: {e}")
        exit()

    try:
       device_type=detect_device_type(hostname)
       conn = connect_device(hostname, username, password, device_type)
    except Exception as e:
        print(e)
        exit()




    if conn:
        if device_type == "cisco_xr":
            handle_cisco(conn,host_search,hostname)
        elif device_type == "juniper":
            handle_juniper(conn,host_search,hostname)
        elif device_type == "extreme":
            handle_extreme(conn,host_search,hostname)
        elif device_type == "nokia_sros":
            handle_olt(conn,host_search,hostname)

    disconnect_device(conn)
