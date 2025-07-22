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
            ["openssl", "enc", "-aes-256-cbc", "-d", "-in", enc_file, "-pass", f"pass:{passphrase}"],
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
    if "csco" in name:
        return "cisco_xr"
    elif "jnpr" in name:
        return "juniper"
    elif "extr" in name:
        return "extreme"
    else:
        return None
#-----------------------------------------------------------------------------
#CONNECT TO DEVICE
#-----------------------------------------------------------------------------
def connect_device(hostname, username, password, device_type):
    device = {
        "device_type": device_type,
        "host": hostname + ".wlink.com.np",   #Edit Hostname according to your network
        "username": username,
        "password": password,
        "conn_timeout": 20,
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
        filter_cmd1 = '| match "Lane|dBm|rx" | except "alarm|loss|Inf|output" '
    


        for iface in interfaces:
            print(f"\n--- Optics Info for {iface} ---")
            output = conn.send_command(f"show interfaces diagnostics optics {iface} {filter_cmd1}")
            print(output)

            
          

    except Exception as e:
        print(f"Error while parsing optics output: {e}")





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
    enc_file = "------------"    ##Encryption file Location
    decryption_key = "---------"  ##Encryption Passowrd
    username = "---------"   ## Username for device login

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

        disconnect_device(conn)
