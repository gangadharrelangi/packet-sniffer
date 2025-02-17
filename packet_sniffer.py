from scapy.all import sniff, IP, Ether, TCP, UDP
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Combobox
import threading
import argparse
import sys

class PacketSniffer:
    def __init__(self, win=None, filter_option=None):
        self.win = win
        self.sniffing = False
        self.filter_option = filter_option or ""  # Use filter_option from CLI if provided
        self.filter_value = ""
        
        if self.win:
            self.setup_gui()

    def setup_gui(self):
        button_frame = Frame(self.win)
        button_frame.pack(pady=10)

        self.start = Button(button_frame, text='Start', command=self.start_sniff, width=10, height=2)
        self.start.pack(side='left', padx=5)
        
        self.end = Button(button_frame, text='End', command=self.end_sniff, width=10, height=2)
        self.end.pack(side='left', padx=5)

        self.clear = Button(button_frame, text='Clear', command=self.clear_output, width=10, height=2)
        self.clear.pack(side='left', padx=5)

        filter_frame = Frame(self.win)
        filter_frame.pack(pady=10, fill=X)

        self.filter_combobox = Combobox(filter_frame, values=[
            "No Filter",
            "TCP",
            "UDP",
            "HTTP",
            "Source IP",
            "Destination IP",
            "Port"
        ])
        self.filter_combobox.current(0)
        self.filter_combobox.pack(side='left', padx=5)

        self.filter_value_entry = Entry(filter_frame)
        self.filter_value_entry.pack(side='left', padx=5)
        
        self.text_area = ScrolledText(self.win)
        self.text_area.pack(fill=BOTH, expand=True)

        self.status_var = StringVar()
        self.status_var.set("Status: Idle")
        self.status_bar = Label(self.win, textvariable=self.status_var, bd=1, relief=SUNKEN, anchor=W)
        self.status_bar.pack(side=BOTTOM, fill=X)

    def start_sniff(self):
        self.sniffing = True
        
        if self.win:
            self.text_area.insert(END, "Starting packet sniffing...\n")
            self.text_area.see(END)
            self.status_var.set("Status: Sniffing...")
            
            selected_filter = self.filter_combobox.get()
            self.filter_value = self.filter_value_entry.get()
            self.filter_option = self.get_filter(selected_filter)

        sniff_thread = threading.Thread(target=self.sniff_packets)
        sniff_thread.daemon = True
        sniff_thread.start()

    def get_filter(self, selected_filter):
        if selected_filter == "TCP":
            return "tcp"
        elif selected_filter == "UDP":
            return "udp"
        elif selected_filter == "HTTP":
            return "tcp port 80"
        elif selected_filter == "Source IP":
            return f"src host {self.filter_value}"
        elif selected_filter == "Destination IP":
            return f"dst host {self.filter_value}"
        elif selected_filter == "Port":
            return f"port {self.filter_value}"
        else:
            return ""

    def sniff_packets(self):
        def packet_callback(packet):
            if not self.sniffing:
                return
            output = self.process_packet(packet)

            if self.win:
                self.text_area.insert(END, output)
                self.text_area.see(END)
            else:
                print(output)  # Print packets in CLI mode

        sniff(prn=packet_callback, store=False, filter=self.filter_option)

    def process_packet(self, packet):
        output = ""
        if Ether in packet:
            output += f"Ethernet Frame: {packet[Ether].src} -> {packet[Ether].dst}\n"
        if IP in packet:
            output += f"IP Packet: {packet[IP].src} -> {packet[IP].dst}\n"
        if TCP in packet:
            output += f"TCP Segment: {packet[TCP].sport} -> {packet[TCP].dport}\n"
        if UDP in packet:
            output += f"UDP Datagram: {packet[UDP].sport} -> {packet[UDP].dport}\n"
        output += "\n"
        return output

    def end_sniff(self):
        self.sniffing = False
        if self.win:
            self.text_area.insert(END, 'Stopped packet sniffing.\n')
            self.text_area.see(END)
            self.status_var.set("Status: Stopped")
        else:
            print('Stopped packet sniffing.')

    def clear_output(self):
        if self.win:
            self.text_area.delete(1.0, END)

def cli_interface(filter_option=None):
    sniffer = PacketSniffer(filter_option=filter_option)
    print("Starting packet sniffing... (Press Ctrl+C to stop)")
    try:
        sniffer.start_sniff()
        while sniffer.sniffing:
            pass  # Keep CLI alive
    except KeyboardInterrupt:
        sniffer.end_sniff()

def gui_interface():
    win = Tk()
    win.title("Packet Sniffer")
    win.geometry("800x600")
    sniffer = PacketSniffer(win)
    win.mainloop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer with CLI and GUI support.")
    parser.add_argument('--cli', action='store_true', help="Run in CLI mode.")
    parser.add_argument('--filter', type=str, help="Filter packets by protocol (e.g., tcp, udp).")
    parser.add_argument('--port', type=str, help="Filter packets by port.")
    parser.add_argument('--src', type=str, help="Filter packets by source IP.")
    parser.add_argument('--dst', type=str, help="Filter packets by destination IP.")
    args = parser.parse_args()

    if args.cli:
        filter_option = ""
        if args.filter:
            filter_option = args.filter.lower()
        elif args.port:
            filter_option = f"port {args.port}"
        elif args.src:
            filter_option = f"src host {args.src}"
        elif args.dst:
            filter_option = f"dst host {args.dst}"
        cli_interface(filter_option)
    else:
        gui_interface()
