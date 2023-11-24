import scapy.all as scapy
import threading
import time
import tkinter as tk
from tkinter import scrolledtext, simpledialog
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import subprocess
from keras.models import load_model
import numpy as np

class NetworkAnalyzer:
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_counter = pd.DataFrame(columns=['IP', 'DestinationIP', 'Service', 'Flags', 'Length', 'Count', 'Class'])
        self.anomaly_detector = IsolationForest(contamination=0.05)
        self.blocked_ips = set()
        self.suspicious_packets = []
        self.model = load_model('models/network_model.h5')
        self.syn_threshold = 50
        self.syn_counter = pd.DataFrame(columns=['IP', 'Count'])

    def pad_and_convert(self, s):
        if len(s) < 2000:
            s += '00' * (2000-len(s))
        else:
            s = s[:2000]
        return np.array([float(int(s[i]+s[i+1], 16)/255) for i in range(0, 2000, 2)])

    def packet_callback(self, packet):
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            raw_data = bytes(packet)
            hex_data = raw_data.hex()

            prepared_data = self.pad_and_convert(hex_data).reshape(1, 1000, 1)
            classification_result = self.model.predict(prepared_data)

            if packet.haslayer(scapy.TCP):
                protocol = "TCP"
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                flags = packet[scapy.TCP].flags

                if flags == 2:
                    if src_ip in self.syn_counter['IP'].values:
                        self.syn_counter.loc[self.syn_counter['IP'] == src_ip, 'Count'] += 1
                    else:
                        self.syn_counter = self.syn_counter.append({'IP': src_ip, 'Count': 1}, ignore_index=True)

                    if self.syn_counter.loc[self.syn_counter['IP'] == src_ip, 'Count'].values[0] > self.syn_threshold:
                        print(f"Possible SYN flood attack detected from {src_ip}")

            elif packet.haslayer(scapy.UDP):
                protocol = "UDP"
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
                flags = None
            else:
                protocol = "Other"
                src_port = None
                dst_port = None
                flags = None

            packet_length = len(packet)
            detected_protocol = determine_protocol(classification_result)

            new_row_src = {
                'IP': src_ip,
                'DestinationIP': dst_ip,
                'Service': f"{protocol}:{src_port}",
                'Flags': flags,
                'Length': packet_length,
                'Count': 1,
                'Class': detected_protocol
            }

            new_row_dst = {
                'IP': dst_ip,
                'DestinationIP': src_ip,
                'Service': f"{protocol}:{dst_port}",
                'Flags': flags,
                'Length': packet_length,
                'Count': 1,
                'Class': detected_protocol
            }

            for new_row in [new_row_src, new_row_dst]:
                row_exists = False
                for idx, row in self.packet_counter.iterrows():
                    if all(row[key] == new_row[key] for key in ['IP', 'DestinationIP', 'Service', 'Flags', 'Length', 'Class']):
                        self.packet_counter.at[idx, 'Count'] += 1
                        row_exists = True
                        break

                if not row_exists:
                    self.packet_counter = self.packet_counter.append(new_row, ignore_index=True)



    def start_sniffer(self):
        scapy.sniff(iface=self.interface, store=False, prn=self.packet_callback)

    def analyze_traffic(self):
        while True:
            time.sleep(10)

            print("\nTraffic Analysis:")
            print(self.packet_counter.sort_values(by='Count', ascending=False))

            self.visualize_traffic()
            self.detect_anomalies()

    def visualize_traffic(self):
        top_ips = self.packet_counter.groupby('IP')['Count'].sum().sort_values(ascending=False).head(10)

        plt.barh(top_ips.index, top_ips)
        plt.title('Top 10 IPs by Packet Count')
        plt.xlabel('Packet Count')
        plt.ylabel('IP Address')
        plt.show()

    def detect_anomalies(self):
        data = self.packet_counter[['Count']].values.reshape(-1, 1)
        self.anomaly_detector.fit(data)
        predictions = self.anomaly_detector.predict(data)
        anomalies = self.packet_counter[self.packet_counter.index.isin(self.packet_counter.index[predictions == -1])]

        if not anomalies.empty:
            print("\nAnomalies Detected:")
            print(anomalies)

            self.suspicious_packets.extend(anomalies.to_dict(orient='records'))

    def block_ip(self, ip_address):
        self.blocked_ips.add(ip_address)
        try:
            command_inbound = ["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block-{ip_address}-Inbound", "dir=in", "interface=any", "action=block", f"remoteip={ip_address}"]
            subprocess.run(command_inbound, check=True)

            command_outbound = ["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block-{ip_address}-Outbound", "dir=out", "interface=any", "action=block", f"remoteip={ip_address}"]
            subprocess.run(command_outbound, check=True)

            print(f"Blocked traffic from and to {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error blocking traffic from and to {ip_address}: {e}")

    def unblock_ip(self, ip_address):
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            try:
                command_inbound = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=Block-{ip_address}-Inbound"]
                subprocess.run(command_inbound, check=True)

                command_outbound = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=Block-{ip_address}-Outbound"]
                subprocess.run(command_outbound, check=True)

                print(f"Unblocked traffic from and to {ip_address}")
            except subprocess.CalledProcessError as e:
                if "No rules match the specified criteria" in str(e):
                    print(f"No matching rule found. Traffic from and to {ip_address} may already be unblocked.")
                else:
                    print(f"Error unblocking traffic from and to {ip_address}: {e}")

    def get_packet_counts(self):
        return self.packet_counter

    def clear_suspicious_packets(self):
        self.suspicious_packets = []


class App:
    def __init__(self, root, network_analyzer):
        self.root = root
        self.network_analyzer = network_analyzer

        self.root.title("Network Traffic Analyzer")
        self.root.geometry("600x600")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)
        self.text_area.pack(expand=True, fill='both')

        sniffer_control_frame = tk.Frame(root)
        sniffer_control_frame.pack(pady=10)

        self.start_button = tk.Button(sniffer_control_frame, text="Start Sniffer", command=self.start_sniffer)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.analyze_button = tk.Button(sniffer_control_frame, text="Analyze Traffic", command=self.analyze_traffic)
        self.analyze_button.pack(side=tk.LEFT, padx=5)

        display_info_frame = tk.Frame(root)
        display_info_frame.pack(pady=10)

        self.show_counts_button = tk.Button(display_info_frame, text="Show Packet Counts", command=self.show_packet_counts)
        self.show_counts_button.pack(side=tk.LEFT, padx=5)

        self.show_suspicious_button = tk.Button(display_info_frame, text="Show Suspicious Packets", command=self.show_suspicious_packets)
        self.show_suspicious_button.pack(side=tk.LEFT, padx=5)

        self.show_blocked_ips_button = tk.Button(display_info_frame, text="Show Blocked IPs", command=self.show_blocked_ips)
        self.show_blocked_ips_button.pack(side=tk.LEFT, padx=5)

        packet_management_frame = tk.Frame(root)
        packet_management_frame.pack(pady=10)

        self.clear_suspicious_button = tk.Button(packet_management_frame, text="Clear Suspicious Packets", command=self.clear_suspicious_packets)
        self.clear_suspicious_button.pack(side=tk.LEFT, padx=5)

        ip_blocking_frame = tk.Frame(root)
        ip_blocking_frame.pack(pady=10)

        self.block_ip_button = tk.Button(ip_blocking_frame, text="Block IP", command=self.block_ip_dialog)
        self.block_ip_button.pack(side=tk.LEFT, padx=5)

        self.unblock_ip_button = tk.Button(ip_blocking_frame, text="Unblock IP", command=self.unblock_ip_dialog)
        self.unblock_ip_button.pack(side=tk.LEFT, padx=5)

    def start_sniffer(self):
        self.network_analyzer.interface = self.get_network_interface()
        sniffer_thread = threading.Thread(target=self.network_analyzer.start_sniffer)
        sniffer_thread.start()

    def analyze_traffic(self):
        analysis_thread = threading.Thread(target=self.network_analyzer.analyze_traffic)
        analysis_thread.start()

    def show_packet_counts(self):
        packet_counts = self.network_analyzer.get_packet_counts()
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, packet_counts)

    def show_suspicious_packets(self):
        suspicious_packets = self.network_analyzer.suspicious_packets
        self.text_area.delete(1.0, tk.END)
        if suspicious_packets:
            self.text_area.insert(tk.END, "Suspicious Packets:\n")
            for idx, packet in enumerate(suspicious_packets, start=1):
                self.text_area.insert(tk.END, f"Packet {idx}:\n")
                self.text_area.insert(tk.END, f"Source IP: {packet['IP']}\n")
                self.text_area.insert(tk.END, f"Destination IP: {packet['DestinationIP']}\n")
                self.text_area.insert(tk.END, f"Service: {packet['Service']}\n")
                self.text_area.insert(tk.END, f"Flags: {packet['Flags']}\n")
                self.text_area.insert(tk.END, f"Length: {packet['Length']}\n")
                self.text_area.insert(tk.END, f"Count: {packet['Count']}\n")
                self.text_area.insert(tk.END, f"Class: {packet['Class']}\n")
                self.text_area.insert(tk.END, "\n")
        else:
            self.text_area.insert(tk.END, "No suspicious packets found.\n")

    def show_blocked_ips(self):
        blocked_ips = self.network_analyzer.blocked_ips
        self.text_area.delete(1.0, tk.END)
        if blocked_ips:
            self.text_area.insert(tk.END, "Blocked IPs:\n")
            for ip in blocked_ips:
                self.text_area.insert(tk.END, f"{ip}\n")
        else:
            self.text_area.insert(tk.END, "No IPs are currently blocked.\n")

    def clear_suspicious_packets(self):
        self.network_analyzer.clear_suspicious_packets()
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, "Cleared suspicious packets list.\n")

    def block_ip_dialog(self):
        ip_to_block = simpledialog.askstring("Block IP", "Enter the IP address to block:")
        if ip_to_block:
            self.network_analyzer.block_ip(ip_to_block)

    def unblock_ip_dialog(self):
        ip_to_unblock = simpledialog.askstring("Unblock IP", "Enter the IP address to unblock:")
        if ip_to_unblock:
            self.network_analyzer.unblock_ip(ip_to_unblock)

    def get_network_interface(self):
        interface = simpledialog.askstring("Input", "Enter the network interface (e.g., Wi-Fi):")
        return interface

def determine_protocol(array):
    if array.size == 0 or len(array[-1]) != 4:
        return "The table should contain 4 elements." 
    
    
    max_index = np.argmax(array[-1])

    if max_index == 0:
        return "HTTP"
    elif max_index == 1:
        return "SFTP"
    elif max_index == 2:
        return "SNMP"
    elif max_index == 3:
        return "VOIP"
    

if __name__ == "__main__":
    pd.set_option("display.max_rows", None)
    pd.set_option("display.max_columns", None)

    network_analyzer = NetworkAnalyzer(interface="Wi-Fi")
    root = tk.Tk()
    app = App(root, network_analyzer)
    root.mainloop()
