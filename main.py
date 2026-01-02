"""
FlashPrint Proxy

Purpose:
  Intercepts traffic between FlashPrint and FlashForge Explorer series printers.
  Its primary function is to intercept the file list command (M661) and reorder 
  the files alphabetically, addressing a usability flaw in the native firmware 
  where files are listed unsorted.
"""
import socket
import threading
import argparse
import sys
import subprocess
import ipaddress
import time

# Configuration
PRINTER_IP = '192.168.1.XXX' # Change to your Adventurer 3 IP
UDP_PORT = 48899
TCP_PORT = 8899

def get_network_info():
    broadcast_ip = '255.255.255.255'
    local_ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))  # Dummy connect to determine interface
        local_ip = s.getsockname()[0]
        s.close()
        
        # Attempt to find real netmask via ipconfig (Windows)
        netmask = '255.255.255.0' # Fallback
        try:
            output = subprocess.check_output('ipconfig', text=True)
            lines = output.splitlines()
            for i, line in enumerate(lines):
                if local_ip in line:
                    for j in range(i, min(i + 10, len(lines))):
                        if "Subnet Mask" in lines[j]:
                            netmask = lines[j].split(':')[-1].strip()
                            break
                    break
        except Exception:
            pass

        interface = ipaddress.IPv4Interface(f"{local_ip}/{netmask}")
        broadcast_ip = str(interface.network.broadcast_address)
    except Exception:
        pass
    return local_ip, broadcast_ip

def discover_printers():
    print("Scanning network for FlashForge printers...")
    found_printers = []

    local_ip, broadcast_ip = get_network_info()
    if local_ip:
        print(f"[INFO] Local IP: {local_ip}")
        print(f"[INFO] Broadcast IP: {broadcast_ip}")

    try:
        # Listener socket on 18004
        print("[INFO] Binding listener socket on port 18004...")
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind(('0.0.0.0', 18004))
        listen_sock.settimeout(3)

        # Send Multicast Announcement (225.0.0.9:19000)
        if local_ip:
            mcast_payload = socket.inet_aton(local_ip) + (18004).to_bytes(2, 'big') + b'\x00\x00'
            print(f"[INFO] Sending multicast packet to 225.0.0.9:19000...")
            listen_sock.sendto(mcast_payload, ('225.0.0.9', 19000))

        # Sender socket on 18005
        print("[INFO] Binding sender socket on port 18005...")
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if local_ip:
            send_sock.bind((local_ip, 18005))
        else:
            send_sock.bind(('0.0.0.0', 18005))
        
        # Send USR-CN discovery command (www.usr.cn)
        msg = bytes.fromhex('7777772e7573722e636e00000000000000000000')
        print(f"[INFO] Sending broadcast to {broadcast_ip}:{UDP_PORT}...")
        send_sock.sendto(msg, (broadcast_ip, UDP_PORT))
        send_sock.close()
        
        print("[INFO] Waiting for responses...")
        while True:
            try:
                data, addr = listen_sock.recvfrom(1024)
                if addr[0] not in found_printers:
                    found_printers.append(addr[0])
                    print(f"Found printer at: {addr[0]} | Data: {data.decode('utf-8', 'ignore').strip()}")
            except socket.timeout:
                break
        listen_sock.close()
    except Exception as e:
        print(f"Discovery error: {e}")
    return found_printers

def get_command_description(text):
    descriptions = {
        'M601': 'Control On', 'M602': 'Control Off',
        'M115': 'Get Machine Info', 'M119': 'Get Endstop Status',
        'M105': 'Get Temperature', 'M27': 'Get Print Progress',
        'M23': 'Select File', 'M24': 'Start/Resume Print',
        'M25': 'Pause Print', 'M26': 'Set SD Position',
        'M28': 'Write to SD', 'M29': 'Stop Writing to SD',
        'M140': 'Set Bed Temp', 'M104': 'Set Extruder Temp',
        'G0': 'Move Linear', 'G1': 'Move Linear', 'G28': 'Home Axes',
        'M114': 'Get Current Position', 'M112': 'Emergency Stop',
        'M18': 'Disable Steppers', 'M17': 'Enable Steppers',
        'M106': 'Fan On', 'M107': 'Fan Off',
        'M650': 'Set Peeling', 'M651': 'Do Peeling',
        'M108': 'Cancel', 'M132': 'Read PID', 'M133': 'Set PID',
        'M146': 'Set LED Color', 'M147': 'Set LED Color',
        'M148': 'Set LED Color', 'M160': 'Set Fan Speed',
        'M600': 'Filament Change', 'M109': 'Wait for Extruder Temp', 
        'M190': 'Wait for Bed Temp', 'M82': 'Absolute Extrusion', 
        'M83': 'Relative Extrusion', 'G90': 'Absolute Positioning', 
        'G91': 'Relative Positioning', 'G92': 'Set Position',
        'M662': 'Get File Preview',
    }
    
    clean = text.replace('~', '').strip()
    parts = clean.split()
    if not parts: return None
    
    cmd = parts[0]
    
    if cmd == "CMD" and len(parts) > 1:
        cmd = parts[1]
        desc = descriptions.get(cmd, "Unknown Command")
        return f"Response to {cmd} ({desc})"
    
    if cmd.lower() == "ok":
        return "Acknowledge (OK)"
        
    if cmd in descriptions:
        return f"{cmd} ({descriptions[cmd]})"
        
    if len(cmd) > 1 and cmd[0] in ('M', 'G') and cmd[1:].isdigit():
        return f"{cmd} (Unknown Command)"
        
    return None

def handle_traffic(source, destination, direction):
    # Commands to suppress from logging (Heartbeat/Polling)
    IGNORED_COMMANDS = [
        b'~M105', b'CMD M105', # Temperature
        b'~M27',  b'CMD M27',  # Print Progress
        b'~M119', b'CMD M119'  # Status/Endstops
    ]

    while True:
        try:
            data = source.recv(4096)
            if not data:
                break
            
            # Intercept M661 (Get File List) and reorder alphabetically
            if direction == "PRINTER -> PC" and b'CMD M661 Received.' in data:
                try:
                    # Attempt to read the full list if fragmented
                    source.settimeout(0.5)
                    while True:
                        try:
                            chunk = source.recv(4096)
                            if not chunk: break
                            data += chunk
                        except socket.timeout:
                            break
                    source.settimeout(None)

                    if b'::' in data:
                        parts = data.split(b'::')
                        if len(parts) > 1:
                            header = parts[0]
                            files = parts[1:]
                            files.sort(key=lambda x: x[x.find(b'/data/')+6:].lower() if b'/data/' in x else x)
                            data = header + b'::' + b'::'.join(files)
                            print(f"[PROXY] M661: Reordered {len(files)} files.")
                except Exception as e:
                    print(f"[PROXY] Error processing M661: {e}")

            # Print only if not in ignored list
            if not any(cmd in data for cmd in IGNORED_COMMANDS):
                try:
                    text = data.decode('utf-8', 'ignore').strip()
                    desc = get_command_description(text)
                    
                    if desc:
                        print(f"[{direction}] {desc}")
                        if len(text) > 60:
                            print(f"    Data: {text[:60]}... [truncated]")
                        elif text and "CMD" not in text and text != "ok":
                             print(f"    Data: {text}")
                    else:
                        if len(data) > 100 and data.count(b'\x00') > 10:
                            print(f"[{direction}] Binary Data: {len(data)} bytes")
                        else:
                            print(f"[{direction}] Raw: {data.hex(' ')} | {text[:50]}")
                except:
                    print(f"[{direction}] Binary: {len(data)} bytes")
            
            destination.sendall(data)
        except:
            break
    source.close()
    destination.close()

def handle_discovery_proxy(target_ip):
    print("Starting UDP Discovery Proxy...")
    
    local_ip, _ = get_network_info()
    if not local_ip:
        print("Error: Could not determine local IP for discovery proxy.")
        return

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        udp_sock.bind((local_ip, UDP_PORT))
    except Exception as e:
        print(f"Failed to bind UDP port {UDP_PORT} for discovery: {e}")
        return

    while True:
        try:
            data, addr = udp_sock.recvfrom(1024)
            
            # Ignore our own broadcasts (from the sender socket on 18007)
            if addr[0] == local_ip and addr[1] == 18007:
                continue
            
            # Handle USR-CN discovery (www.usr.cn)
            if b'www.usr.cn' in data:
                try:
                    _, broadcast_ip = get_network_info()

                    # 1. Setup Listener on 18006 (avoid conflict with FlashPrint on 18004)
                    sock_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock_recv.bind(('0.0.0.0', 18006))
                    sock_recv.settimeout(2)

                    # 2. Send Multicast Registration (tell printer to reply to 18006)
                    mcast_payload = socket.inet_aton(local_ip) + (18006).to_bytes(2, 'big') + b'\x00\x00'
                    sock_recv.sendto(mcast_payload, ('225.0.0.9', 19000))

                    # 3. Send Broadcast Query
                    sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock_send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    sock_send.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    # Use 18007 to avoid conflict with FlashPrint on 18005
                    sock_send.bind((local_ip, 18007))
                    sock_send.sendto(data, (broadcast_ip, UDP_PORT))
                    sock_send.close()
                    
                    # 4. Wait for response from target_ip
                    while True:
                        resp, r_addr = sock_recv.recvfrom(2048)
                        if r_addr[0] == target_ip:
                            # Prepend "PROXY " to the printer name
                            try:
                                prefix = b'PROXY '
                                null_idx = resp.find(b'\x00')
                                if null_idx != -1:
                                    # Find end of padding to preserve packet structure
                                    suffix_idx = null_idx
                                    while suffix_idx < len(resp) and resp[suffix_idx] == 0:
                                        suffix_idx += 1
                                    
                                    padding_len = suffix_idx - null_idx
                                    if padding_len >= len(prefix):
                                        resp = prefix + resp[:null_idx] + b'\x00' * (padding_len - len(prefix)) + resp[suffix_idx:]
                            except Exception:
                                pass

                            udp_sock.sendto(resp, addr)
                            print(f"Discovery (USR): Responded to {addr}")
                            break
                    sock_recv.close()
                except Exception as e:
                    print(f"Discovery error (USR): {e}")

            elif b'~M601' in data:
                # Query the real printer
                try:
                    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    temp_sock.settimeout(2)
                    temp_sock.sendto(data, (target_ip, UDP_PORT))
                    resp, _ = temp_sock.recvfrom(2048)
                    temp_sock.close()

                    # Replace printer IP with proxy IP in response
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect((addr[0], 80))
                        local_ip = s.getsockname()[0]
                        s.close()
                        resp_str = resp.decode('utf-8', 'ignore')
                        resp = resp_str.replace(target_ip, local_ip).encode('utf-8')
                    except:
                        pass

                    udp_sock.sendto(resp, addr)
                    print(f"Discovery: Responded to {addr}")
                except Exception as e:
                    print(f"Discovery error querying printer: {e}")
        except Exception as e:
            print(f"UDP Proxy error: {e}")

def start_proxy(printer_ip):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    server.bind(('0.0.0.0', TCP_PORT))
    server.listen(5)
    server.settimeout(1.0)
    print(f"Proxy listening on TCP port {TCP_PORT}... Point FlashPrint to THIS computer's IP.")
    print(f"Forwarding traffic to Printer at: {printer_ip}")

    # Start UDP Discovery Proxy
    threading.Thread(target=handle_discovery_proxy, args=(printer_ip,), daemon=True).start()

    try:
        while True:
            try:
                client_sock, addr = server.accept()
            except socket.timeout:
                continue

            print(f"FlashPrint connected from {addr}")
            
            printer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            printer_sock.connect((printer_ip, TCP_PORT))
            printer_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            # Attempt to release control (~M602) to clear any stale sessions
            try:
                print("[PROXY] Sending ~M602 (Release Control) to printer...")
                printer_sock.sendall(b'~M602\r\n')
                printer_sock.settimeout(1.0)
                try:
                    resp = printer_sock.recv(1024)
                    print(f"[PROXY] Release response: {resp.decode('utf-8', 'ignore').strip()}")
                except socket.timeout:
                    pass
                printer_sock.settimeout(None)
            except Exception as e:
                print(f"[PROXY] Failed to send release command: {e}")

            # Start two threads: one for each direction
            threading.Thread(target=handle_traffic, args=(client_sock, printer_sock, "PC -> PRINTER")).start()
            threading.Thread(target=handle_traffic, args=(printer_sock, client_sock, "PRINTER -> PC")).start()
    except KeyboardInterrupt:
        print("\nStopping proxy...")
        server.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='FlashPrint Proxy - Alphabetizes File Lists for FlashForge Explorer Series')
    parser.add_argument('--ip', help='Manually specify the printer IP address')
    parser.add_argument('--scan', action='store_true', help='Scan the network for printers')
    args = parser.parse_args()

    target_ip = PRINTER_IP

    # Default to scan if no IP provided or scan flag is set
    if args.scan or not args.ip:
        printers = discover_printers()
        if printers:
            target_ip = printers[0]
            if len(printers) > 1:
                print(f"Multiple printers found. Defaulting to first found: {target_ip}")
        elif 'XXX' in PRINTER_IP:
            print("No printers found during scan.")
            sys.exit(1)
    elif args.ip:
        target_ip = args.ip

    if 'XXX' in target_ip:
        print("Error: No valid IP configured. Use --scan, --ip <ADDRESS>, or edit PRINTER_IP in the script.")
        sys.exit(1)

    try:
        start_proxy(target_ip)
    except KeyboardInterrupt:
        print("\nExiting...")