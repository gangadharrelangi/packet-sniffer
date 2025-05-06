from scapy import sniff, IP, Ether, TCP, UDP
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Combobox, Treeview
import threading
import argparse
import sys
import json
import os
from datetime import datetime

class PacketSniffer:
    def __init__(self, win=None, filter_option=None):
        self.win = win
        self.sniffing = False
        self.filter_option = filter_option or ""
        self.filter_value = ""
        self.packet_storage = []
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        # saving path to Downloads folder
        self.downloads_dir = os.path.join(os.path.expanduser('~'), 'Downloads')
        self.output_dir = os.path.join(self.downloads_dir, 'packet_captures', self.session_id)
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        if self.win:
            self.setup_gui()

    def setup_gui(self):
        self.win.title("Advanced Packet Sniffer")
        self.win.geometry("1200x800")
        # Main container
        main_frame = Frame(self.win)
        main_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
        # Control panel
        control_frame = Frame(main_frame)
        control_frame.pack(fill=X, pady=5)
        # Filter controls
        filter_frame = Frame(control_frame)
        filter_frame.pack(side=LEFT, padx=5)

        self.filter_combobox = Combobox(filter_frame, values=[
            "No Filter",
            "TCP",
            "UDP",
            "HTTP",
            "Source IP",
            "Destination IP",
            "Port"
        ], width=15)
        self.filter_combobox.current(0)
        self.filter_combobox.pack(side=LEFT, padx=5)

        self.filter_value_entry = Entry(filter_frame, width=20)
        self.filter_value_entry.pack(side=LEFT, padx=5)
        
        # Button controls
        button_frame = Frame(control_frame)
        button_frame.pack(side=RIGHT, padx=5)
        
        self.start = Button(button_frame, text='Start', command=self.start_sniff, width=10)
        self.start.pack(side=LEFT, padx=2)
        
        self.end = Button(button_frame, text='End', command=self.end_sniff, width=10)
        self.end.pack(side=LEFT, padx=2)

        self.clear = Button(button_frame, text='Clear', command=self.clear_output, width=10)
        self.clear.pack(side=LEFT, padx=2)

        self.save = Button(button_frame, text='Save', command=self.save_packets, width=10)
        self.save.pack(side=LEFT, padx=2)
        
        # Packet list and detail view
        display_frame = Frame(main_frame)
        display_frame.pack(fill=BOTH, expand=True)
        
        # Packet list (Treeview)
        list_frame = Frame(display_frame)
        list_frame.pack(fill=BOTH, expand=True, side=LEFT, padx=5)
        
        self.packet_list = Treeview(list_frame, columns=('ID', 'Time', 'Source', 'Destination', 'Protocol', 'Length'), show='headings')
        self.packet_list.heading('ID', text='ID')
        self.packet_list.heading('Time', text='Time')
        self.packet_list.heading('Source', text='Source')
        self.packet_list.heading('Destination', text='Destination')
        self.packet_list.heading('Protocol', text='Protocol')
        self.packet_list.heading('Length', text='Length')
        
        self.packet_list.column('ID', width=40)
        self.packet_list.column('Time', width=120)
        self.packet_list.column('Source', width=150)
        self.packet_list.column('Destination', width=150)
        self.packet_list.column('Protocol', width=80)
        self.packet_list.column('Length', width=60)
        
        self.packet_list.pack(fill=BOTH, expand=True)
        self.packet_list.bind('<<TreeviewSelect>>', self.show_packet_details)
        
        # Packet detail view
        detail_frame = Frame(display_frame)
        detail_frame.pack(fill=BOTH, expand=True, side=RIGHT, padx=5)
        
        self.detail_text = ScrolledText(detail_frame, wrap=WORD)
        self.detail_text.pack(fill=BOTH, expand=True)
        
        # Status bar
        self.status_var = StringVar()
        self.status_var.set("Status: Idle")
        self.status_bar = Label(self.win, textvariable=self.status_var, bd=1, relief=SUNKEN, anchor=W)
        self.status_bar.pack(side=BOTTOM, fill=X)

    def get_filter(self, selected_filter):
        """Convert GUI filter selection to BPF filter string"""
        if selected_filter == "No Filter":
            return ""
        elif selected_filter == "TCP":
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

    def start_sniff(self):
        self.sniffing = True
        self.packet_storage = []
        
        if self.win:
            self.packet_list.delete(*self.packet_list.get_children())  # Clear packet list
            self.detail_text.delete(1.0, END)
            self.detail_text.insert(END, "Starting packet sniffing...\n")
            self.status_var.set("Status: Sniffing...")
            
            selected_filter = self.filter_combobox.get()
            self.filter_value = self.filter_value_entry.get()
            self.filter_option = self.get_filter(selected_filter)
        else:
            print("Starting packet sniffing...")

        sniff_thread = threading.Thread(target=self.sniff_packets)
        sniff_thread.daemon = True
        sniff_thread.start()

    def sniff_packets(self):
        def packet_callback(packet):
            if not self.sniffing:
                return
            
            packet_info = self.process_packet(packet)
            self.packet_storage.append(packet_info)
            
            if self.win:
                self.win.after(0, self.add_to_packet_list, packet_info)
            else:
                print(self.format_packet_output(packet_info))
                
        sniff(prn=packet_callback, store=False, filter=self.filter_option)

    def process_packet(self, packet):
        #Extract and return structured packet information
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'layers': {}
        }
        
        if Ether in packet:
            packet_info['layers']['ethernet'] = {
                'src': packet[Ether].src,
                'dst': packet[Ether].dst
            }
        
        if IP in packet:
            packet_info['layers']['ip'] = {
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'version': packet[IP].version,
                'ttl': packet[IP].ttl
            }
        
        if TCP in packet:
            packet_info['layers']['tcp'] = {
                'sport': packet[TCP].sport,
                'dport': packet[TCP].dport,
                'flags': str(packet[TCP].flags)
            }
        
        if UDP in packet:
            packet_info['layers']['udp'] = {
                'sport': packet[UDP].sport,
                'dport': packet[UDP].dport
            }
        
        return packet_info

    def format_packet_output(self, packet_info):
        #Format the structured packet info for display
        output = ""
        if 'ethernet' in packet_info['layers']:
            eth = packet_info['layers']['ethernet']
            output += f"Ethernet Frame: {eth['src']} -> {eth['dst']}\n"
        if 'ip' in packet_info['layers']:
            ip = packet_info['layers']['ip']
            output += f"IP Packet: {ip['src']} -> {ip['dst']} (v{ip['version']}, TTL: {ip['ttl']})\n"
        if 'tcp' in packet_info['layers']:
            tcp = packet_info['layers']['tcp']
            output += f"TCP Segment: {tcp['sport']} -> {tcp['dport']} [Flags: {tcp['flags']}]\n"
        if 'udp' in packet_info['layers']:
            udp = packet_info['layers']['udp']
            output += f"UDP Datagram: {udp['sport']} -> {udp['dport']}\n"
        output += "\n"
        return output

    def add_to_packet_list(self, packet_info):
        # Add packet to the Treeview list (GUI only)
        packet_id = len(self.packet_storage)
        timestamp = packet_info['timestamp'][11:19]  # Just show time
        
        # Determine protocol
        protocol = ""
        if 'tcp' in packet_info['layers']:
            protocol = "TCP"
        elif 'udp' in packet_info['layers']:
            protocol = "UDP"
        
        # Get source and destination
        src = ""
        dst = ""
        if 'ip' in packet_info['layers']:
            src = packet_info['layers']['ip']['src']
            dst = packet_info['layers']['ip']['dst']
        elif 'ethernet' in packet_info['layers']:
            src = packet_info['layers']['ethernet']['src']
            dst = packet_info['layers']['ethernet']['dst']
        
        # Calculate packet length (simplified)
        length = sum(len(str(v)) for layer in packet_info['layers'].values() for v in layer.values())
        
        self.packet_list.insert('', 'end', 
                              values=(packet_id, timestamp, src, dst, protocol, length),
                              tags=(str(packet_id),))
        
        # Auto-scroll to new packet
        self.packet_list.see(self.packet_list.get_children()[-1])

    def show_packet_details(self, event):
        """Show detailed packet information when selected (GUI only)"""
        selected_item = self.packet_list.selection()
        if not selected_item:
            return
            
        packet_id = int(self.packet_list.item(selected_item)['values'][0])
        packet_info = self.packet_storage[packet_id]
        
        self.detail_text.delete(1.0, END)
        
        # Format the detailed view
        self.detail_text.insert(END, f"Packet #{packet_id} - {packet_info['timestamp']}\n")
        self.detail_text.insert(END, "="*50 + "\n\n")
        
        for layer_name, layer_info in packet_info['layers'].items():
            self.detail_text.insert(END, f"{layer_name.upper()} Layer:\n")
            for key, value in layer_info.items():
                self.detail_text.insert(END, f"  {key:15}: {value}\n")
            self.detail_text.insert(END, "\n")
        
        self.detail_text.insert(END, "\nPacket Analysis Complete\n")

    def save_packets(self):
        """Save captured packets to a JSON file in Downloads folder"""
        if not self.packet_storage:
            if self.win:
                self.detail_text.insert(END, "No packets to save.\n")
            else:
                print("No packets to save.")
            return
            
        filename = os.path.join(self.output_dir, f"capture_{datetime.now().strftime('%H%M%S')}.json")
        try:
            with open(filename, 'w') as f:
                json.dump(self.packet_storage, f, indent=2)
            if self.win:
                self.detail_text.insert(END, f"\nPackets saved to: {filename}\n")
            else:
                print(f"\nPackets saved to: {filename}")
        except Exception as e:
            if self.win:
                self.detail_text.insert(END, f"\nError saving packets: {str(e)}\n")
            else:
                print(f"\nError saving packets: {str(e)}")

    def end_sniff(self):
        self.sniffing = False
        if self.win:
            self.status_var.set("Status: Stopped")
            self.detail_text.insert(END, "\nPacket sniffing stopped.\n")
        else:
            print("\nPacket sniffing stopped.")

    def clear_output(self):
        if self.win:
            self.packet_list.delete(*self.packet_list.get_children())
            self.detail_text.delete(1.0, END)
            self.packet_storage = []
            self.status_var.set("Status: Ready")

def cli_interface(filter_option=None):
    sniffer = PacketSniffer(filter_option=filter_option)
    print("Starting packet sniffing... (Press Ctrl+C to stop)")
    try:
        # Start sniffing in CLI mode
        sniffer.sniffing = True
        sniffer.packet_storage = []
        
        # Start sniffing in a separate thread
        sniff_thread = threading.Thread(target=sniffer.sniff_packets)
        sniff_thread.daemon = True
        sniff_thread.start()
        
        # Keep main thread alive
        while sniffer.sniffing:
            pass
            
    except KeyboardInterrupt:
        sniffer.end_sniff()
        if sniffer.packet_storage:
            filename = os.path.join(sniffer.output_dir, "cli_capture.json")
            with open(filename, 'w') as f:
                json.dump(sniffer.packet_storage, f, indent=2)
            print(f"\nPackets saved to: {filename}")

def gui_interface():
    win = Tk()
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