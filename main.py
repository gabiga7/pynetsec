import scapy.all as scapy
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog
import pandas as pd


class NetworkAnalyzer:
    def _init_(self, interface=None):
        self.interface = interface
        self.packet_counter = pd.DataFrame(columns=['IP', 'Count'])

    def packet_callback(self, packet):
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

    def start_sniffer(self):
        scapy.sniff(iface=self.interface, store=False, prn=self.packet_callback)

    def get_packet_counts(self):
        return self.packet_counter


class App:
    def _init_(self, root, network_analyzer):
        self.root = root
        self.network_analyzer = network_analyzer

        self.root.title("Network Traffic Analyzer")
        self.root.geometry("600x400")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)
        self.text_area.pack(expand=True, fill='both')

        self.start_button = tk.Button(root, text="Start Sniffer", command=self.start_sniffer)
        self.start_button.pack()

    def start_sniffer(self):
        self.network_analyzer.interface = self.get_network_interface()
        sniffer_thread = threading.Thread(target=self.network_analyzer.start_sniffer)
        sniffer_thread.start()

    def get_network_interface(self):
        interface = simpledialog.askstring("Input", "Enter the network interface (e.g., eth0):")
        return interface


if __name__ == "__main__":
    pd.set_option("display.max_rows", None)
    pd.set_option("display.max_columns", None)

    network_analyzer = NetworkAnalyzer(interface="Wi-Fi")
    root = tk.Tk()
    app = App(root, network_analyzer)
    root.mainloop()

