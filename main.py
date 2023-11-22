import scapy.all as scapy
import threading
import time
import tkinter as tk
from tkinter import scrolledtext, simpledialog
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import subprocess


class NetworkAnalyzer:
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_counter = pd.DataFrame(columns=['IP', 'DestinationIP', 'Service', 'Flags', 'Length', 'Count'])
        self.anomaly_detector = IsolationForest(contamination=0.05)
        self.blocked_ips = set()

    def packet_callback(self, packet):
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            if packet.haslayer(scapy.TCP):
                protocol = "TCP"
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                flags = packet[scapy.TCP].flags
            elif packet.haslayer(scapy.UDP):
                protocol = "UDP"
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
                flags = None  # No flags for UDP
            else:
                # You can handle other protocols as needed
                protocol = "Other"
                src_port = None
                dst_port = None
                flags = None

            # Additional information
            packet_length = len(packet)

            # Update packet counter with more information
            self.packet_counter = self.packet_counter.append({
                'IP': src_ip,
                'DestinationIP': dst_ip,
                'Service': f"{protocol}:{src_port}",
                'Flags': flags,
                'Length': packet_length,
                'Count': 1
            }, ignore_index=True)

            self.packet_counter = self.packet_counter.append({
                'IP': dst_ip,
                'DestinationIP': src_ip,
                'Service': f"{protocol}:{dst_port}",
                'Flags': flags,
                'Length': packet_length,
                'Count': 1
            }, ignore_index=True)

            # Remove old entries
            self.packet_counter = self.packet_counter.groupby(['IP', 'DestinationIP', 'Service', 'Flags', 'Length']).sum().reset_index()


    def start_sniffer(self):
        scapy.sniff(iface=self.interface, store=False, prn=self.packet_callback)

    def analyze_traffic(self):
        while True:
            time.sleep(10)  # Analyze traffic every 10 seconds

            # Display real-time packet counts
            print("\nTraffic Analysis:")
            print(self.packet_counter.sort_values(by='Count', ascending=False))

            # Visualize traffic
            self.visualize_traffic()

            # Detect anomalies using Isolation Forest
            self.detect_anomalies()

    def visualize_traffic(self):
        # Plot the top 10 IP addresses based on packet count
        top_ips = self.packet_counter.groupby('IP')['Count'].sum().sort_values(ascending=False).head(10)

        # Ensure only the top 10 IPs are plotted
        plt.barh(top_ips.index, top_ips)
        plt.title('Top 10 IPs by Packet Count')
        plt.xlabel('Packet Count')
        plt.ylabel('IP Address')
        plt.show()



    def detect_anomalies(self):
        # Prepare data for anomaly detection
        data = self.packet_counter[['Count']].values.reshape(-1, 1)

        # Fit the Isolation Forest model
        self.anomaly_detector.fit(data)

        # Predict anomalies
        predictions = self.anomaly_detector.predict(data)

        # Identify anomalies using the original index
        anomalies = self.packet_counter[self.packet_counter.index.isin(self.packet_counter.index[predictions == -1])]

        if not anomalies.empty:
            print("\nAnomalies Detected:")
            print(anomalies)



    def block_ip(self, ip_address):
        self.blocked_ips.add(ip_address)
        try:
            # Use netsh command to add a firewall rule blocking the specified IP address for both inbound and outbound traffic
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
                # Use netsh command to delete both inbound and outbound firewall rules named with the IP address
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

class App:
    def __init__(self, root, network_analyzer):
        self.root = root
        self.network_analyzer = network_analyzer

        self.root.title("Network Traffic Analyzer")
        self.root.geometry("600x400")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)
        self.text_area.pack(expand=True, fill='both')

        self.start_button = tk.Button(root, text="Start Sniffer", command=self.start_sniffer)
        self.start_button.pack()

        self.analyze_button = tk.Button(root, text="Analyze Traffic", command=self.analyze_traffic)
        self.analyze_button.pack()

        self.show_counts_button = tk.Button(root, text="Show Packet Counts", command=self.show_packet_counts)
        self.show_counts_button.pack()

        self.block_ip_button = tk.Button(root, text="Block IP", command=self.block_ip_dialog)
        self.block_ip_button.pack()

        self.unblock_ip_button = tk.Button(root, text="Unblock IP", command=self.unblock_ip_dialog)
        self.unblock_ip_button.pack()

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


if __name__ == "__main__":
    pd.set_option("display.max_rows", None)
    pd.set_option("display.max_columns", None)

    network_analyzer = NetworkAnalyzer(interface="Wi-Fi")
    root = tk.Tk()
    app = App(root, network_analyzer)
    root.mainloop()
