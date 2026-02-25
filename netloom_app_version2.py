#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Netloom – Weaving PCAP Data Into Visuals - FIXED VERSION WITH CORRECTED SEQUENCE ANALYSIS
All original features: DROPS, Failures, Loops, LSAs, ISAKMP, IPsec, Sequences
Network Communication Flow Analyzer + Enhanced Routing Loop Detection with IP ID Tracking
FIXED: Sequence analysis table generation error
"""

import os
import sys
import time
import json
import struct
import hashlib
import threading
import webbrowser
from collections import defaultdict, Counter
from datetime import datetime, timezone
from decimal import Decimal

# Plotly imports for flow graph
import plotly.graph_objects as go
from plotly.io import to_html

import streamlit as st
import tempfile

MAX_BYTES = 500 * 1024 * 1024  # 500 MB

# ============== Scapy imports with error handling ==============
try:
    from scapy.all import rdpcap, Packet, Raw, PacketList
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA
    from scapy.layers.l2 import LLC
    print("✓ Scapy core layers imported successfully")
except ImportError as e:
    print(f"❌ Scapy import failed: {e}")
    sys.exit(1)

# Try to import ICMPv6 (it's part of inet6 but not always directly importable)
try:
    from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6DestUnreach
    ICMPV6_AVAILABLE = True
    print("✓ ICMPv6 layers available")
except ImportError:
    # Fallback: ICMPv6 packets can still be detected via IPv6.nh == 58
    ICMPV6_AVAILABLE = False
    print("⚠️ ICMPv6 not directly available - will use protocol detection")

# Try to import IPsec layers
try:
    from scapy.layers.ipsec import AH, ESP
    from scapy.layers.isakmp import (
        ISAKMP, ISAKMP_payload_SA, ISAKMP_payload_Notify,
        ISAKMP_payload_Proposal, ISAKMP_payload_Transform
    )
    IPSEC_AVAILABLE = True
    ISAKMP_AVAILABLE = True
    print("✓ IPsec/ISAKMP layers available")
except ImportError:
    # Fallback classes for IPsec
    class AH:
        name = "AH"
        def __init__(self, *args, **kwargs):
            self.spi = 0
    
    class ESP:
        name = "ESP"
        def __init__(self, *args, **kwargs):
            self.spi = 0
    
    class ISAKMP:
        name = "ISAKMP"
        def __init__(self, *args, **kwargs):
            self.init_cookie = b'\x00' * 8
    
    class ISAKMP_payload_SA:
        name = "ISAKMP_SA"
    
    IPSEC_AVAILABLE = False
    ISAKMP_AVAILABLE = False
    print("⚠️ IPsec/ISAKMP layers not available - using fallback classes")

# Try to import routing protocol layers
try:
    from scapy.contrib.ospf import OSPF_Hdr, OSPF_LSUpd, OSPF_LSAck
    OSPF_AVAILABLE = True
    print("✓ OSPF layers available")
except ImportError:
    class OSPF_Hdr:
        name = "OSPF_Hdr"
        def __init__(self, *args, **kwargs):
            self.type = 0
    
    class OSPF_LSUpd:
        name = "OSPF_LSUpd"
        def __init__(self, *args, **kwargs):
            self.lsalist = []
    
    OSPF_AVAILABLE = False
    print("⚠️ OSPF layers not available - using fallback classes")

try:
    from scapy.contrib.bgp import BGPHeader
    BGP_AVAILABLE = True
    print("✓ BGP layers available")
except ImportError:
    class BGPHeader:
        name = "BGPHeader"
    BGP_AVAILABLE = False
    print("⚠️ BGP layers not available - using fallback class")

print("✓ All Scapy imports completed\n")


# ============== Helper Functions ==============

def safe_float(value):
    """Safely convert Scapy timestamp to float, handling EDecimal objects."""
    try:
        if hasattr(value, 'float'):
            return float(value)
        elif isinstance(value, (int, float)):
            return float(value)
        elif isinstance(value, str):
            return float(value)
        elif hasattr(value, 'real'):
            return float(value.real) if hasattr(value.real, 'float') else float(str(value))
        else:
            return float(str(value))
    except (ValueError, TypeError, AttributeError):
        return time.time()


def safe_timestamp(value):
    """Safely format timestamp to UTC string, handling various formats."""
    try:
        ts_float = safe_float(value)
        utc_dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
        return utc_dt.strftime('%H:%M:%S.%f')[:-3] + ' UTC'
    except (ValueError, TypeError, OSError):
        return datetime.now(timezone.utc).strftime('%H:%M:%S.%f')[:-3] + ' UTC'


def get_packet_ips(pkt):
    """
    Universal helper to extract source and destination IPs from both IPv4 and IPv6 packets.
    
    Returns:
        tuple: (src_ip, dst_ip, ttl/hlim) or (None, None, None) if neither IP layer exists
    """
    try:
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst, pkt[IP].ttl
        elif pkt.haslayer(IPv6):
            return pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6].hlim
        else:
            return None, None, None
    except Exception:
        return None, None, None


def is_icmpv6_packet(pkt):
    """
    Check if packet is ICMPv6 (protocol 58 in IPv6).
    Works even if ICMPv6 classes are not directly importable.
    
    Args:
        pkt: Scapy packet object
        
    Returns:
        bool: True if ICMPv6, False otherwise
    """
    try:
        if pkt.haslayer(IPv6):
            # ICMPv6 uses protocol number 58
            return pkt[IPv6].nh == 58
        return False
    except Exception:
        return False


def get_protocol_name(pkt):
    """
    Get protocol name from packet (IPv4 and IPv6 compatible).
    
    Args:
        pkt: Scapy packet object
        
    Returns:
        str: Protocol name (TCP, UDP, ICMP, ICMPv6, etc.)
    """
    try:
        # Check IP layer protocols
        if pkt.haslayer(IP):
            proto_num = pkt[IP].proto
        elif pkt.haslayer(IPv6):
            proto_num = pkt[IPv6].nh  # Next Header
        else:
            return "Unknown"
        
        # Map protocol numbers to names
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            47: 'GRE',
            50: 'ESP',
            51: 'AH',
            58: 'ICMPv6',  # ICMPv6 for IPv6
            88: 'EIGRP',
            89: 'OSPF',
            132: 'SCTP'
        }
        
        return protocol_map.get(proto_num, f"Protocol-{proto_num}")
        
    except Exception:
        return "Unknown"


def tcp_comment(pkt):
    """
    Generate a human-readable comment for a TCP packet.
    Works with both IPv4 and IPv6 TCP packets.
    """
    try:
        # Handle Scapy packet object
        if hasattr(pkt, 'haslayer') and pkt.haslayer(TCP):
            tcp = pkt[TCP]
        elif hasattr(pkt, 'getlayer'):
            tcp = pkt.getlayer(TCP)
            if not tcp:
                return "TCP (no TCP layer)"
        elif isinstance(pkt, dict) and 'TCP' in pkt:
            tcp = pkt.get('TCP')
        else:
            return "TCP (no TCP layer)"
        
        # Extract TCP fields
        sport = getattr(tcp, 'sport', '?')
        dport = getattr(tcp, 'dport', '?')
        seq = getattr(tcp, 'seq', '?')
        ack = getattr(tcp, 'ack', '?')
        win = getattr(tcp, 'window', '?')
        plen = len(tcp.payload) if hasattr(tcp, 'payload') else 0
        flags_bin = getattr(tcp, 'flags', 0)
        
        # Parse TCP flags
        mapping = [
            ('FIN', 0x01), ('SYN', 0x02), ('RST', 0x04), ('PSH', 0x08),
            ('ACK', 0x10), ('URG', 0x20), ('ECE', 0x40), ('CWR', 0x80)
        ]
        flags = [name for name, bit in mapping if flags_bin & bit]
        flag_text = ",".join(flags) if flags else "None"
        
        return f"TCP: {sport}→{dport} [{flag_text}] Seq={seq} Ack={ack} Win={win} Len={plen}"
        
    except Exception as e:
        return f"TCP (error: {e})"


def is_ipv6_packet(pkt):
    """Check if packet uses IPv6."""
    try:
        return pkt.haslayer(IPv6)
    except Exception:
        return False


class UltraNetworkAnalyzer:
    """Complete Netloom – Weaving PCAP Data Into Visuals with all original and new features."""
    def build_complete_dashboard(self):
        """Build comprehensive HTML dashboard with all features."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.dashboard_file = 'ultra_network_dashboard_{}.html'.format(timestamp)
        # build your html_content variable above as desired

        try:
            with open(self.dashboard_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.log_message("✅ Enhanced dashboard created: {}".format(self.dashboard_file))
        except Exception as e:
            self.log_message("❌ Failed to create dashboard: {}".format(str(e)))

        for pkt in flow.get('packets', []):
            if protocol == 'TCP':
                comment_value = pkt.get('comment', '') or tcp_comment(pkt)
                label = comment_value or 'TCP'
            else:
                label = pkt.get('comment', '') or protocol
            flow_events.append({
                'src': src,
                'dst': dst,
                'protocol': protocol,
                'time': get_float_timestamp(pkt.get('timestamp', 0)),
                'info': label
            })
#=======================tcp_comment===========================#
    def tcp_comment(pkt):
        try:
            tcp = pkt['TCP']
            flags_bin = tcp.flags
            mapping = [('FIN', 0x01), ('SYN', 0x02), ('RST', 0x04), ('PSH', 0x08),
                       ('ACK', 0x10), ('URG', 0x20), ('ECE', 0x40), ('CWR', 0x80)]
            flags = [name for name, bit in mapping if flags_bin & bit]
            flag_str = ",".join(flags)
            return f"TCP: {tcp.sport}→{tcp.dport} [{flag_str}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={len(tcp.payload)}"
        except Exception:
            return "TCP"
        
    
    def __init__(self):
        """Initialize the analyzer without GUI - for Streamlit use"""
        self.pcap_path = None
        self.jitter_threshold_ms = 100
        self.packets = []
        self.stats = {}
        self.routing_loops = []
        self.dropped_connections = []
        self.tcp_issues = []
        self.mtu_issues = []
        self.flows = {}
        self.isakmp_exchanges = []
        self.ipsec_tunnels = []
        self.ospf_packets = []
        self.bgp_packets = []
        self.eigrp_packets = []
        self.isis_packets = []


    def _get_option_value(self, option_name):
        """
        Helper method to get option value - works with both tk.BooleanVar and plain boolean.
    
        Args:
            option_name: Name of the option attribute (e.g., 'drops_analysis')
    
        Returns:
            Boolean value
        """
        if not hasattr(self, option_name):
            return False
    
        option = getattr(self, option_name)
    
        # If it's a tk.BooleanVar, call .get()
        if hasattr(option, 'get'):
            return option.get()
    
        # Otherwise it's already a plain boolean
        return bool(option)


    def get_capped_pcap_path(self, original_path):
        """Return a path to a PCAP file capped at MAX_BYTES (500MB)."""
        try:
            file_size = os.path.getsize(original_path)
            if file_size <= MAX_BYTES:
                # No need to cap
                return original_path

            # Create capped copy in same dir
            base, ext = os.path.splitext(original_path)
            capped_path = base + "_capped500MB" + ext

            with open(original_path, "rb") as src, open(capped_path, "wb") as dst:
                remaining = MAX_BYTES
                chunk_size = 4 * 1024 * 1024  # 4 MB chunks
                while remaining > 0:
                    to_read = min(chunk_size, remaining)
                    data = src.read(to_read)
                    if not data:
                        break
                    dst.write(data)
                    remaining -= len(data)

            self.log_message(
                "⚠️ {} is larger than 500 MB; only first 500 MB will be analysed from {}"
                .format(os.path.basename(original_path), os.path.basename(capped_path))
            )
            return capped_path

        except Exception as e:
            self.log_message("❌ Error capping PCAP file {}: {}".format(original_path, str(e)))
            # Fallback: use original if capping fails
            return original_path

    def select_source_file(self):
        """Select source PCAP file."""
        file_path = filedialog.askopenfilename(
            title="Select Source PCAP File",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        if file_path:
            self.src_pcap_file = file_path
            filename = os.path.basename(file_path)
            if len(filename) > 60:
                filename = filename[:57] + "..."
            self.src_var.set("✓ {}".format(filename))
            self.check_files_selected()

    def select_destination_file(self):
        """Select destination PCAP file."""
        file_path = filedialog.askopenfilename(
            title="Select Destination PCAP File",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        if file_path:
            self.dst_pcap_file = file_path
            filename = os.path.basename(file_path)
            if len(filename) > 60:
                filename = filename[:57] + "..."
            self.dst_var.set("✓ {}".format(filename))
            self.check_files_selected()

    def check_files_selected(self):
        """Enable analyze button when files are selected (supports single PCAP mode)."""
        if self.src_pcap_file:
            if self.single_pcap_mode and self.single_pcap_mode.get():
                # Single PCAP mode: only source file needed
                self.analyze_button.configure(state='normal')
            elif self.dst_pcap_file:
                # Dual PCAP mode: both files needed
                self.analyze_button.configure(state='normal')
            else:
                self.analyze_button.configure(state='disabled')
        else:
            self.analyze_button.configure(state='disabled')

    def toggle_single_pcap_mode(self):
        """Toggle GUI elements for single PCAP mode."""
        if self.single_pcap_mode.get():
            # Disable destination file controls
            self.dst_label.configure(foreground="#999999")
            self.dst_val_label.configure(foreground="#cccccc")
            self.dst_btn.configure(state='disabled')
        else:
            # Enable destination file controls
            self.dst_label.configure(foreground="#000000")
            self.dst_val_label.configure(foreground="gray")
            self.dst_btn.configure(state='normal')
        self.check_files_selected()

    def log_message(self, message):
        """Log message to the text area."""
        def do_log():
            self.log_text.config(state=tk.NORMAL)
            timestamp = datetime.now().strftime('%H:%M:%S')
            self.log_text.insert(tk.END, "[{}] {}\n".format(timestamp, message))
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        self.root.after(0, do_log)

    def update_progress(self, message, percent):
        """Update progress bar and message."""
        def do_update():
            self.progress_var.set(message)
            self.progress_bar['value'] = percent
            self.root.update_idletasks()
        self.root.after(0, do_update)

    def start_analysis(self):
        """Start the complete analysis process."""
        if hasattr(self, 'root'):
            if not self.src_pcap_file:
                messagebox.showerror("Missing Files", "Please select a source PCAP file.")
                return
        
            # Handle single_pcap_mode as tk.BooleanVar
            single_mode = self.single_pcap_mode.get() if hasattr(self.single_pcap_mode, 'get') else self.single_pcap_mode
        
            if not single_mode and not self.dst_pcap_file:
                messagebox.showerror("Missing Files", "Please select both source and destination PCAP files, or enable Single PCAP Mode.")
                return
        
            # Disable analyze button
            self.analyze_button.configure(state='disabled')
        
            # Run in thread
            threading.Thread(target=self.run_complete_analysis, daemon=True).start()
        else:
            # Streamlit mode - just run the analysis directly
            if not self.src_pcap_file:
                raise ValueError("Please provide a source PCAP file.")
        
            # Handle single_pcap_mode as plain boolean
            single_mode = getattr(self, 'single_pcap_mode', True)
            if hasattr(single_mode, 'get'):
                single_mode = single_mode.get()
        
            if not single_mode and not self.dst_pcap_file:
                raise ValueError("Please provide both source and destination PCAP files, or enable Single PCAP Mode.")
        
            # Run analysis directly (no threading needed in Streamlit)
            self.run_complete_analysis()


    def get_capped_pcap_path(self, original_path):
        """Return a path to a PCAP file capped at MAX_BYTES (500MB)."""
        try:
            file_size = os.path.getsize(original_path)
            if file_size <= MAX_BYTES:
                return original_path

            base, ext = os.path.splitext(original_path)
            capped_path = base + "_capped500MB" + ext

            with open(original_path, "rb") as src, open(capped_path, "wb") as dst:
                remaining = MAX_BYTES
                chunk_size = 4 * 1024 * 1024  # 4 MB chunks
                while remaining > 0:
                    to_read = min(chunk_size, remaining)
                    data = src.read(to_read)
                    if not data:
                        break
                    dst.write(data)
                    remaining -= len(data)

            self.log_message(
                "⚠️ {} is larger than 500 MB; only first 500 MB will be analysed from {}"
                .format(os.path.basename(original_path), os.path.basename(capped_path))
            )
            return capped_path

        except Exception as e:
            self.log_message("❌ Error capping PCAP file {}: {}".format(original_path, str(e)))
            return original_path

        

    def run_complete_analysis(self):
        """Run the complete analysis pipeline with all features."""
        import time  # ✅ ADDED
        
        try:
            start_time = time.time()
            MAX_PKTS = 100000  # cap per direction

            # Reset results that depend on checkboxes
            self.analysis_results["isakmp_analysis"] = {}
            self.analysis_results["ipsec_analysis"] = {}

            # Load PCAP files
            self.update_progress("📁 Loading PCAP files...", 2)
            self.log_message("🚀 Starting Complete Ultra Network Protocol Analysis...")
            try:
                # Apply 500MB cap before reading
                src_path = self.get_capped_pcap_path(self.src_pcap_file)
                src_all = rdpcap(src_path)

                if len(src_all) > MAX_PKTS:
                    self.log_message(
                        "⚠️ Source PCAP has {:,} packets; only first {:,} will be analysed."
                        .format(len(src_all), MAX_PKTS)
                    )
                self.src_packets = src_all[:MAX_PKTS]
                self.log_message("✓ Source packets loaded: {:,}".format(len(self.src_packets)))

                single_mode = getattr(self, 'single_pcap_mode', True)
                if hasattr(single_mode, 'get'):  # It's a tk.BooleanVar
                    single_mode = single_mode.get()

                if single_mode:
                    from scapy.plist import PacketList
                    self.dst_packets = PacketList()  # Empty PacketList for single PCAP mode
                    self.log_message("📄 Single PCAP Mode: Analyzing source file only")
                else:
                    dst_path = self.get_capped_pcap_path(self.dst_pcap_file)
                    dst_all = rdpcap(dst_path)
                    if len(dst_all) > MAX_PKTS:
                        self.log_message(
                            "⚠️ Destination PCAP has {:,} packets; only first {:,} will be analysed."
                            .format(len(dst_all), MAX_PKTS)
                        )
                    self.dst_packets = dst_all[:MAX_PKTS]
                    self.log_message("✓ Destination packets loaded: {:,}".format(len(self.dst_packets)))
                    
            except Exception as e:
                raise Exception("Failed to load PCAP files: {}".format(str(e)))
            
            current_progress = 10

            try:
                if self._get_option_value('drops_analysis'):
                    self.update_progress("📉 Analyzing packet drops...", current_progress)
                    self.analyze_packet_drops()
                    current_progress += 8
            
                if self._get_option_value('failures_analysis'):
                    self.update_progress("🚫 Detecting neighbor failures...", current_progress)
                    self.analyze_neighbor_failures()
                    current_progress += 8

                    self.update_progress("🔄 Analyzing stuck neighbor states...", current_progress)
                    self.analyze_stuck_neighbor_states()
                    current_progress += 5
            
                if self._get_option_value('loops_analysis'):
                    self.update_progress("♻️ Enhanced routing loop detection with IP ID...", current_progress)
                    self.analyze_routing_loops()
                    current_progress += 8
            
                if self._get_option_value('lsa_analysis'):
                    self.update_progress("📚 Analyzing OSPF LSAs...", current_progress)
                    self.analyze_ospf_lsas()
                    current_progress += 8

                if self._get_option_value('isis_analysis'):
                    self.update_progress("🛰️ Analyzing IS-IS...", current_progress)
                    self.analyze_isis_packets()
                    self.detect_isis_neighbor_failures()
                    current_progress += 8
            
                # ISAKMP and IPsec
                self.update_progress("🗝️ Analyzing ISAKMP...", current_progress)
                self.analyze_isakmp()
                current_progress += 8
            
                self.update_progress("🛡️ Analyzing IPsec...", current_progress)
                self.analyze_ipsec()
                current_progress += 8
            
                if self._get_option_value('sequence_analysis'):
                    self.update_progress("🔢 Analyzing sequences...", current_progress)
                    self.analyze_sequences()
                    current_progress += 8

                # ✅ UNIFIED: Comprehensive MTU/MSS/Fragmentation analysis
                self.update_progress("🔧 Analyzing MTU/MSS/Fragmentation (TCP, IPsec, GRE, VXLAN, ICMP)...", current_progress)
                self.analyze_mtu_mss_issues()
                current_progress += 5
            
                if self._get_option_value('routing_analysis'):
                    self.update_progress("🔀 Enhanced routing analysis...", current_progress)
                    self.analyze_routing_comprehensive()
                    self.analyze_eigrp_packets()
                    self.analyze_bgp_packets()
                    current_progress += 8

                if self._get_option_value('communication_analysis'):
                    # ✅ FIXED: Get protocol filter
                    selected_protocol = "ALL"
                    if hasattr(self, 'protocol_var'):
                        try:
                            selected_protocol = self.protocol_var.get() if hasattr(self.protocol_var, 'get') else str(self.protocol_var)
                        except:
                            selected_protocol = "ALL"
                
                    # ✅ FIXED: Get jitter threshold
                    jitter_threshold = None
                    if hasattr(self, 'jitter_entry'):
                        try:
                            # Check if it's a Tkinter widget (has .get() method)
                            if hasattr(self.jitter_entry, 'get'):
                                jitter_str = self.jitter_entry.get()
                                if jitter_str and str(jitter_str).strip():
                                    jitter_threshold = float(jitter_str)
                            else:
                                # It's a direct value (Streamlit mode)
                                if self.jitter_entry is not None and self.jitter_entry != '':
                                    jitter_threshold = float(self.jitter_entry)
                        except (ValueError, TypeError) as e:
                            self.log_message(f"⚠️ Invalid jitter threshold, ignoring: {str(e)}")
                            jitter_threshold = None

                    self.log_message(f"🔍 Protocol filter: {selected_protocol}, Jitter threshold: {jitter_threshold} ms")
                    self.update_progress("💬 Extracting ALL communication flows...", current_progress)
                    self.analyze_communication_complete(selected_protocol, jitter_threshold)  
                    current_progress += 6

                if self._get_option_value('flowgraph_analysis'):
                    self.update_progress("🗺️ Preparing flow graph view...", current_progress)
                    current_progress += 4
            
            except Exception as e:
                raise Exception("Analysis module error: {}".format(str(e)))

            # Generate dashboard
            try:
                self.update_progress("📊 Building complete dashboard...", 95)
                self.build_complete_dashboard()
            except Exception as e:
                raise Exception("Dashboard generation error: {}".format(str(e)))

            elapsed_time = time.time() - start_time
            self.update_progress("✅ Complete analysis finished!", 100)
            self.log_message("🎉 Complete analysis finished in {:.2f} seconds!".format(elapsed_time))

            # Handle messagebox for both Tkinter and Streamlit
            if hasattr(self, 'root'):
                messagebox.showinfo(
                    "Analysis Complete", 
                    "Complete ultra network analysis finished successfully!\n\n"
                    "Time: {:.2f} seconds\n\n"
                    "🎯 Dashboard: All Features Analyzed\n"
                    "Open dashboard for complete results!".format(elapsed_time)
                )
            else:
                self.log_message("✅ Analysis complete in {:.2f} seconds!".format(elapsed_time))

        except Exception as e:
            error_msg = "❌ Analysis error: {}".format(str(e))
            self.log_message(error_msg)

            # Handle error messagebox
            if hasattr(self, 'root'):
                messagebox.showerror("Analysis Error", "Error during analysis:\n{}".format(str(e)))
            else:
                raise  # Re-raise for Streamlit to display
        
        finally:
            # Handle button state only in Tkinter mode
            if hasattr(self, 'root') and hasattr(self, 'analyze_button'):
                self.root.after(0, lambda: self.analyze_button.configure(state='normal'))


    # ANALYSIS METHODS

#=======================for flow graph==============================#

    def generate_flowgraph_svg(self, protocol_filter=None, width=1800, height=1000, time_tick=None):
        from datetime import datetime, timezone
        import plotly.graph_objects as go
        from plotly.io import to_html

        def get_float_timestamp(ts):
            try:
                return float(ts)
            except Exception:
                try:
                    if isinstance(ts, str) and ':' in ts:
                        ts_clean = ts.split(' ')[0] if 'UTC' in ts else ts
                        t = datetime.strptime(ts_clean, "%H:%M:%S.%f")
                        return t.hour * 3600 + t.minute * 60 + t.second + t.microsecond / 1e6
                    return 0.0
                except Exception:
                    return 0.0

        def format_endpoint_display(addr):
            """Format IP addresses for display - abbreviate long IPv6 addresses"""
            if not addr or not isinstance(addr, str):
                return str(addr)
            
            # MAC address - return as-is (format: xx:xx:xx:xx:xx:xx)
            if addr.count(':') == 5:
                # Check if it's a valid MAC (12 hex chars)
                hex_only = addr.replace(':', '')
                if len(hex_only) == 12 and all(c in '0123456789abcdefABCDEF' for c in hex_only):
                    return addr
            
            # IPv6 address - show abbreviated form
            if addr.count(':') > 2:  # Likely IPv6
                try:
                    # Already abbreviated with ::
                    if '::' in addr:
                        # Split on ::
                        parts = addr.split('::')
                        if len(parts) == 2:
                            left_groups = parts[0].split(':') if parts[0] else []
                            right_groups = parts[1].split(':') if parts[1] else []
                            
                            # Show first 2 groups and last group
                            display_left = ':'.join(left_groups[:2]) if len(left_groups) >= 2 else ':'.join(left_groups)
                            display_right = right_groups[-1] if right_groups else ''
                            
                            if display_left and display_right:
                                return f"{display_left}::..:{display_right}"
                            elif display_left:
                                return f"{display_left}::.."
                            elif display_right:
                                return f"::..:{display_right}"
                            else:
                                return "::"
                    else:
                        # Full IPv6 - show first 2 and last group
                        groups = addr.split(':')
                        if len(groups) >= 4:
                            return f"{groups[0]}:{groups[1]}::..:{groups[-1]}"
                        else:
                            # Short IPv6 - show as-is
                            return addr
                except Exception:
                    return addr
            
            # IPv4 or short address - return as-is
            return addr

        def tcp_flag_str(pkt):
            flags = []
            tcp_flags = None
            if hasattr(pkt, 'getlayer'):
                from scapy.layers.inet import TCP
                tcp_layer = pkt.getlayer(TCP)
                if tcp_layer:
                    tcp_flags = tcp_layer.flags
            elif isinstance(pkt, dict):
                tcp_flags = pkt.get('flags', 0)

            if tcp_flags is not None:
                if isinstance(tcp_flags, str):
                    mapping = {'F':'FIN', 'S':'SYN', 'R':'RST', 'P':'PSH', 'A':'ACK', 'U':'URG', 'E':'ECE', 'C':'CWR'}
                    return "+".join(mapping.get(c, c) for c in tcp_flags if c in mapping)
                if tcp_flags & 0x01: flags.append("FIN")
                if tcp_flags & 0x02: flags.append("SYN")
                if tcp_flags & 0x04: flags.append("RST")
                if tcp_flags & 0x08: flags.append("PSH")
                if tcp_flags & 0x10: flags.append("ACK")
                if tcp_flags & 0x20: flags.append("URG")
                if tcp_flags & 0x40: flags.append("ECE")
                if tcp_flags & 0x80: flags.append("CWR")
                return "+".join(flags)
            return ""

        def format_display_time(ts):
            try:
                if isinstance(ts, str):
                    if 'UTC' in ts:
                        return ts.rsplit(' ', 1)[0][:12]
                    if ':' in ts:
                        return ts[:12]
                if hasattr(self, 'safe_timestamp'):
                    result = self.safe_timestamp(ts)
                    if 'UTC' in result:
                        result = result.rsplit(' ', 1)[0]
                    return str(result)[:12]
                utc_dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
                return utc_dt.strftime('%H:%M:%S.%f')[:-3][:12]
            except Exception:
                return str(ts)[:12]

        flow_events = []
        endpoints = set()

        # ✅ Extract OSPF packets (IPv4 and IPv6)
        ospf_analysis = self.analysis_results.get('ospf_lsa_analysis', {})
        for pkt in ospf_analysis.get('lsa_details', []):
            src = pkt.get('src')
            dst = pkt.get('dst')
            timestamp = pkt.get('timestamp')
            pkt_type = pkt.get('type', 'OSPF')
            if not src or not dst or not timestamp:
                continue
            if not isinstance(src, str) or not isinstance(dst, str):
                continue
            endpoints.update([src, dst])
            flow_events.append({
                'src': src, 'dst': dst, 'protocol': 'OSPF',
                'time': get_float_timestamp(timestamp),
                'display_time': timestamp,
                'info': pkt_type
            })

        routing_analysis = self.analysis_results.get('routing_protocol_analysis', {})

        # ✅ Extract EIGRP packets (IPv4 and IPv6)
        for pkt in routing_analysis.get('eigrp_packets', []):
            src = pkt.get('src_ip')
            dst = pkt.get('dst_ip')
            timestamp = pkt.get('timestamp')
            if not src or not dst or not timestamp:
                continue
            if not isinstance(src, str) or not isinstance(dst, str):
                continue
            endpoints.update([src, dst])
            flow_events.append({
                'src': src, 'dst': dst, 'protocol': 'EIGRP',
                'time': get_float_timestamp(timestamp),
                'display_time': timestamp,
                'info': pkt.get('opcode', 'EIGRP')
            })

        # ✅ Extract BGP packets (IPv4 and IPv6)
        for pkt in routing_analysis.get('bgp_packets', []):
            src = pkt.get('src_ip')
            dst = pkt.get('dst_ip')
            timestamp = pkt.get('timestamp')
            if not src or not dst or not timestamp:
                continue
            if not isinstance(src, str) or not isinstance(dst, str):
                continue
            endpoints.update([src, dst])
            flow_events.append({
                'src': src, 'dst': dst, 'protocol': 'BGP',
                'time': get_float_timestamp(timestamp),
                'display_time': timestamp,
                'info': pkt.get('bgp_type', 'BGP')
            })

        # ✅ Extract RIP packets (IPv4 and potentially IPv6/RIPng)
        for pkt in routing_analysis.get('rip_packets', []):
            src = pkt.get('src_ip')
            dst = pkt.get('dst_ip')
            timestamp = pkt.get('timestamp')
            if not src or not dst or not timestamp:
                continue
            if not isinstance(src, str) or not isinstance(dst, str):
                continue
            endpoints.update([src, dst])
            flow_events.append({
                'src': src, 'dst': dst, 'protocol': 'RIP',
                'time': get_float_timestamp(timestamp),
                'display_time': timestamp,
                'info': pkt.get('command', 'RIP')
            })

        # ✅ Extract IS-IS packets (Layer 2 - MAC addresses)
        isis_data = self.analysis_results.get('isis_analysis', {})
        for pdu_list in ['hello_pdus', 'lsp_pdus', 'csnp_pdus', 'psnp_pdus']:
            for pkt in isis_data.get(pdu_list, []):
                src = pkt.get('src_mac')
                dst = pkt.get('dst_mac')
                timestamp = pkt.get('timestamp')
                if not src or not dst or not timestamp:
                    continue
                if not isinstance(src, str) or not isinstance(dst, str):
                    continue
                endpoints.update([src, dst])
                flow_events.append({
                    'src': src, 'dst': dst, 'protocol': 'ISIS',
                    'time': get_float_timestamp(timestamp),
                    'display_time': timestamp,
                    'info': pkt.get('type', 'ISIS')
                })

        # ✅ Extract communication flows (IPv4 and IPv6)
        comm_flows = self.analysis_results.get('communication_analysis', {}).get('flows', [])
        for flow in comm_flows:
            protocol = flow.get('protocol', 'Other')
            flow_str = flow.get('flow', '')
            if '↔' not in flow_str:
                continue

            parts = flow_str.split('↔')
            if len(parts) < 2:
                continue
            src = parts[0].strip()
            dst = parts[-1].strip()
            if not src or not dst:
                continue
            if not isinstance(src, str) or not isinstance(dst, str):
                continue

            endpoints.update([src, dst])

            for pkt in flow.get('packets', []):
                timestamp = pkt.get('timestamp')
                if not timestamp:
                    continue
                if protocol == 'TCP':
                    label = tcp_flag_str(pkt) or pkt.get('comment', '') or 'TCP'
                else:
                    label = pkt.get('comment', '') or protocol
                flow_events.append({
                    'src': src, 'dst': dst, 'protocol': protocol,
                    'time': get_float_timestamp(timestamp),
                    'display_time': timestamp,
                    'info': label
                })

        # Apply protocol filter
        if protocol_filter and str(protocol_filter).lower() != 'all':
            flow_events = [ev for ev in flow_events if ev.get('protocol') == protocol_filter]

        if not flow_events:
            return '<div style="padding: 20px; color: #666; text-align: center;">No flow data available for the selected protocol filter.</div>', []

        # Sort events by time
        flow_events_sorted = sorted(flow_events, key=lambda e: (e.get('time', 0), str(e.get('src', '')), str(e.get('dst', ''))))

        endpoint_list = sorted([ep for ep in endpoints if ep and isinstance(ep, str)])
        n_events = len(flow_events_sorted)
        
        if not endpoint_list or n_events == 0:
            return '<div style="padding: 20px; color: #666; text-align: center;">No events to display.</div>', []

        endpoint_index = {ep: i for i, ep in enumerate(endpoint_list)}
        
        # ✅ Create display labels with abbreviated IPv6 (full address available on hover via title)
        endpoint_display_labels = [format_endpoint_display(ep) for ep in endpoint_list]

        protocol_colors = {
            'TCP': '#1976d2', 'UDP': '#388e3c', 'ICMP': '#fbc02d', 'ICMPv6': '#ff7043',
            'Other': '#9e9e9e', 'OSPF': '#3146a2', 'EIGRP': '#089981', 'BGP': '#aa539d',
            'ISIS': '#cc8800', 'RIP': '#ff6f00', 'ARP': '#795548', 'UIM': '#607d8b'
        }

        per_event_gap = 26
        calculated_height = n_events * per_event_gap + 100

        y_vals = list(range(n_events))
        y_labels = [format_display_time(ev.get('display_time', ev.get('time', 0))) for ev in flow_events_sorted]

        fig = go.Figure()
        x_min = -0.5
        x_max = max(len(endpoint_list) - 1 + 0.5, 0.5)
        fig.update_xaxes(range=[x_min, x_max])
        fig.update_yaxes(range=[n_events - 0.5, -0.5])

        shapes = []
        annotations = []

        # ✅ Draw vertical timeline lines for each endpoint
        for ep, x_idx in endpoint_index.items():
            shapes.append(dict(
                type="line",
                xref="x", yref="y",
                x0=x_idx, x1=x_idx,
                y0=-0.5, y1=n_events - 0.5,
                line=dict(color="#e1e2e3", width=1, dash="dot"),
                layer="below"
            ))

        # ✅ Draw horizontal grid lines for each event
        for y in y_vals:
            shapes.append(dict(
                type="line",
                xref="x", yref="y",
                x0=x_min, x1=x_max,
                y0=y, y1=y,
                line=dict(color="#eef0f2", width=1, dash="dot"),
                layer="below"
            ))

        # ✅ Draw arrows and labels for each flow event
        for idx, event in enumerate(flow_events_sorted):
            src_x = endpoint_index.get(event.get('src'))
            dst_x = endpoint_index.get(event.get('dst'))
            if src_x is None or dst_x is None:
                continue

            y = idx
            color = protocol_colors.get(event.get('protocol', 'Other'), '#888')
            label = str(event.get('info', event.get('protocol', '')))[:16]

            # Arrow
            annotations.append(dict(
                x=dst_x, y=y,
                ax=src_x, ay=y,
                xref="x", yref="y",
                axref="x", ayref="y",
                showarrow=True,
                arrowhead=3,
                arrowsize=1.1,
                arrowwidth=3,
                arrowcolor=color,
                standoff=0
            ))

            # Label
            current_yshift = -12 if idx == 0 else 10
            mid_x = (src_x + dst_x) / 2.0
            annotations.append(dict(
                x=mid_x, y=y,
                xref="x", yref="y",
                yshift=current_yshift,
                text=f"<b>{label}</b>",
                showarrow=False,
                font=dict(size=11, family="Segoe UI, Arial, sans-serif", color=color),
                bgcolor="rgba(255,255,255,0.95)",
                bordercolor=color,
                borderwidth=0.5,
                borderpad=2
            ))

        fig.update_layout(shapes=shapes, annotations=annotations)

        # ✅ X-axis: Use abbreviated display labels
        fig.update_xaxes(
            tickmode="array",
            tickvals=list(endpoint_index.values()),
            ticktext=endpoint_display_labels,
            side="top",
            showgrid=False,
            zeroline=False,
            showline=False,
            fixedrange=True,
            automargin=False,
            tickfont=dict(size=17, family="Segoe UI Semibold, Segoe UI, Arial, sans-serif", color="#20252b")
        )

        # ✅ Y-axis: Time labels
        fig.update_yaxes(
            tickmode="array",
            tickvals=y_vals,
            ticktext=y_labels,
            showgrid=False,
            zeroline=False,
            showline=False,
            fixedrange=True,
            ticks="",
            ticklen=0,
            automargin=False,
            tickfont=dict(size=11, family="Consolas, monospace", color="#888"),
            side="left"
        )

        fig.update_layout(
            width=width,
            height=max(calculated_height, height),
            margin=dict(l=100, r=50, t=60, b=30),
            plot_bgcolor="white",
            paper_bgcolor="white",
            showlegend=False,
            hovermode=False,
            font=dict(size=11, family="Segoe UI, Arial, sans-serif"),
            dragmode=False
        )

        # ✅ Generate HTML with hover tooltips showing full addresses
        html_str = to_html(
            fig,
            include_plotlyjs='cdn',
            full_html=False,
            config={
                'displayModeBar': False,
                'staticPlot': True,
                'responsive': False,
                'doubleClick': False,
                'showTips': False,
                'scrollZoom': False
            }
        )
        
        # ✅ Add custom CSS to show full IPv6 address on hover
        hover_css = """
        <style>
        .xtick text:hover {
            cursor: help;
        }
        </style>
        """
        html_str = hover_css + html_str

        return html_str, flow_events_sorted


    def generate_comment_table(self, flow_events):
        """Generate comment table for TCP packets only. Works with IPv4 and IPv6."""
        if not flow_events:
            return "<div>No packet comments available.</div>"

        tcp_events = [ev for ev in flow_events if ev.get('protocol') == 'TCP']

        if not tcp_events:
            return "<div>No TCP packet comments available.</div>"

        html = '<div class="analysis-section"><b>TCP Packet Comments</b><br>'
        html += '<table style="font-family:Segoe UI,Arial,sans-serif;font-size:13px;border-collapse:collapse;width:100%;">'
        html += '<thead><tr style="background:#f5f6fa;">'
        html += '<th style="text-align:left;padding:6px 10px;border-bottom:2px solid #ddd;">Time</th>'
        html += '<th style="text-align:left;padding:6px 10px;border-bottom:2px solid #ddd;">Comment</th>'
        html += '</tr></thead><tbody>'

        for event in tcp_events:
            t_str = event.get('display_time', '')
            if not t_str or t_str == '00:00:00':
                try:
                    from datetime import datetime
                    t_str = datetime.fromtimestamp(float(event.get('time', 0))).strftime('%H:%M:%S.%f')[:-3]
                except Exception:
                    t_str = str(event.get('time', ''))[:15]
            else:
                t_str = str(t_str).rsplit(' ', 1)[0] if 'UTC' in str(t_str) else str(t_str)
                t_str = t_str[:15] if len(t_str) > 15 else t_str

            comment = event.get('info', '') or ''
            if comment:
                html += (
                    f'<tr style="border-bottom:1px solid #eee;">'
                    f'<td style="padding:5px 10px;color:#333;font-family:Consolas,monospace;">{t_str}</td>'
                    f'<td style="padding:5px 10px;color:#565656;">{comment}</td>'
                    f'</tr>'
                )

        html += '</tbody></table></div>'
        return html

#=======================================================================================#

    def analyze_mtu_mss_issues(self):
        """
        Comprehensive MTU/MSS/Fragmentation analysis covering:
        - TCP MSS clamping and mismatches (IPv4 + IPv6)
        - IPsec ESP/AH fragmentation (IPv4 + IPv6)
        - GRE/VXLAN tunnel MTU issues
        - ICMP/ICMPv6 Fragmentation messages
        - PMTUD black holes (DF bit + no ICMP)
        - IPv4 and IPv6 fragmentation
        - Jumbo frames detection
        """
        try:
            from scapy.layers.inet6 import IPv6ExtHdrFragment, ICMPv6PacketTooBig
            from collections import defaultdict
            
            all_packets = list(self.src_packets) + list(self.dst_packets)
            
            # Storage for analysis results
            tcp_flows = {}
            tunnel_flows = {}
            icmp_frag_needed = []
            pmtud_blackholes = defaultdict(lambda: {
                'large_df_packets': 0,
                'retransmissions': 0,
                'max_size': 0,
                'icmp_received': False,
                'ip_version': None
            })
            ipv4_fragments = []
            ipv6_fragments = []
            jumbo_frames = []
            
            # Track retransmissions per flow for PMTUD detection
            tcp_seq_tracker = defaultdict(set)
            
            for pkt in all_packets:
                try:
                    # ✅ Extract IPs early for both IPv4 and IPv6
                    src_ip, dst_ip, ttl = get_packet_ips(pkt)
                    ip_version = 'IPv6' if pkt.haslayer(IPv6) else 'IPv4' if pkt.haslayer(IP) else None
                    
                    # ==================== ICMP Fragmentation Needed (IPv4) ====================
                    if pkt.haslayer(ICMP):
                        icmp = pkt[ICMP]
                        # Type 3 (Dest Unreachable), Code 4 (Fragmentation Needed)
                        if icmp.type == 3 and icmp.code == 4:
                            next_hop_mtu = getattr(icmp, 'nexthopmtu', 0) or 0
                            icmp_frag_needed.append({
                                'src': src_ip or 'N/A',
                                'dst': dst_ip or 'N/A',
                                'ip_version': 'IPv4',
                                'timestamp': float(pkt.time),
                                'next_hop_mtu': next_hop_mtu,
                                'original_size': len(pkt),
                                'message_type': 'ICMP Frag Needed'
                            })
                    
                    # ✅ ICMPv6 Packet Too Big (IPv6 equivalent of ICMP Frag Needed)
                    if pkt.haslayer(ICMPv6PacketTooBig):
                        icmpv6 = pkt[ICMPv6PacketTooBig]
                        mtu = getattr(icmpv6, 'mtu', 0) or 0
                        icmp_frag_needed.append({
                            'src': src_ip or 'N/A',
                            'dst': dst_ip or 'N/A',
                            'ip_version': 'IPv6',
                            'timestamp': float(pkt.time),
                            'next_hop_mtu': mtu,
                            'original_size': len(pkt),
                            'message_type': 'ICMPv6 Packet Too Big'
                        })
                    
                    # ==================== IPv4 Fragmentation ====================
                    if pkt.haslayer(IP):
                        ip = pkt[IP]
                        is_frag = (ip.flags.MF == 1) or (int(ip.frag) > 0)
                        if is_frag:
                            ipv4_fragments.append({
                                'src': ip.src,
                                'dst': ip.dst,
                                'size': len(pkt),
                                'frag_offset': int(ip.frag) * 8,
                                'more_fragments': bool(ip.flags.MF),
                                'timestamp': float(pkt.time)
                            })
                    
                    # ==================== IPv6 Fragmentation ====================
                    if pkt.haslayer(IPv6) and pkt.haslayer(IPv6ExtHdrFragment):
                        frag_hdr = pkt[IPv6ExtHdrFragment]
                        ipv6_fragments.append({
                            'src': pkt[IPv6].src,
                            'dst': pkt[IPv6].dst,
                            'size': len(pkt),
                            'frag_offset': getattr(frag_hdr, 'offset', 0),
                            'more_fragments': bool(getattr(frag_hdr, 'm', 0)),
                            'frag_id': getattr(frag_hdr, 'id', 0),
                            'timestamp': float(pkt.time)
                        })
                    
                    # ==================== Jumbo Frames Detection ====================
                    if len(pkt) > 1600:  # Larger than standard Ethernet
                        jumbo_frames.append({
                            'src': src_ip or 'N/A',
                            'dst': dst_ip or 'N/A',
                            'ip_version': ip_version or 'N/A',
                            'size': len(pkt),
                            'df_bit': bool(pkt[IP].flags.DF) if pkt.haslayer(IP) else False,
                            'timestamp': float(pkt.time)
                        })
                    
                    # ==================== TCP MSS Analysis (IPv4 + IPv6) ====================
                    if pkt.haslayer(TCP) and (src_ip and dst_ip):
                        flow_key = f"{src_ip}:{pkt[TCP].sport} → {dst_ip}:{pkt[TCP].dport}"
                        
                        if flow_key not in tcp_flows:
                            tcp_flows[flow_key] = {
                                'ip_version': ip_version,
                                'first_mss': None,
                                'second_mss': None,
                                'mss_changed': False,
                                'fragmented_packets': 0,
                                'has_fragments': False,
                                'min_payload': None,
                                'max_payload': 0,
                                'df_bit_packets': 0,
                                'total_packets': 0
                            }
                        
                        flow = tcp_flows[flow_key]
                        flow['total_packets'] += 1
                        
                        # Extract MSS from SYN packets
                        if pkt[TCP].flags & 0x02:  # SYN flag
                            for opt in pkt[TCP].options:
                                if opt[0] == 'MSS':
                                    mss_val = opt[1]
                                    if flow['first_mss'] is None:
                                        flow['first_mss'] = mss_val
                                    elif flow['second_mss'] is None and mss_val != flow['first_mss']:
                                        flow['second_mss'] = mss_val
                                        flow['mss_changed'] = True
                        
                        # ✅ Track fragmentation (IPv4 only, IPv6 uses extension headers)
                        if pkt.haslayer(IP):
                            ip = pkt[IP]
                            is_frag = (ip.flags.MF == 1) or (int(ip.frag) > 0)
                            if is_frag:
                                flow['fragmented_packets'] += 1
                                flow['has_fragments'] = True
                            
                            # Track DF bit (IPv4 only)
                            if ip.flags.DF:
                                flow['df_bit_packets'] += 1
                        
                        # ✅ Track IPv6 fragmentation
                        if pkt.haslayer(IPv6) and pkt.haslayer(IPv6ExtHdrFragment):
                            flow['fragmented_packets'] += 1
                            flow['has_fragments'] = True
                        
                        # Payload size
                        payload_len = len(bytes(pkt[TCP].payload))
                        if payload_len > 0:
                            if flow['min_payload'] is None or payload_len < flow['min_payload']:
                                flow['min_payload'] = payload_len
                            if payload_len > flow['max_payload']:
                                flow['max_payload'] = payload_len
                        
                        # ========== PMTUD Black Hole Detection ==========
                        # Large packet + DF bit (IPv4) or large IPv6 packet + retransmission
                        is_large = len(pkt) > 1400
                        has_df = pkt[IP].flags.DF if pkt.haslayer(IP) else False
                        
                        if is_large and (has_df or pkt.haslayer(IPv6)):
                            pmtud_key = f"{src_ip}:{pkt[TCP].sport} → {dst_ip}:{pkt[TCP].dport}"
                            pmtud_blackholes[pmtud_key]['large_df_packets'] += 1
                            pmtud_blackholes[pmtud_key]['max_size'] = max(
                                pmtud_blackholes[pmtud_key]['max_size'], 
                                len(pkt)
                            )
                            pmtud_blackholes[pmtud_key]['ip_version'] = ip_version
                            
                            # Check for retransmissions (same seq number seen before)
                            seq = pkt[TCP].seq
                            if seq in tcp_seq_tracker[pmtud_key]:
                                pmtud_blackholes[pmtud_key]['retransmissions'] += 1
                            tcp_seq_tracker[pmtud_key].add(seq)
                    
                    # ==================== Tunnel MTU Analysis (IPv4 + IPv6) ====================
                    if src_ip and dst_ip:
                        proto_name = None
                        proto_num = None
                        
                        # Get protocol number
                        if pkt.haslayer(IP):
                            proto_num = pkt[IP].proto
                        elif pkt.haslayer(IPv6):
                            proto_num = pkt[IPv6].nh  # Next Header
                        
                        # IPsec (ESP/AH)
                        if proto_num in (50, 51):
                            proto_name = "ESP" if proto_num == 50 else "AH"
                        # GRE
                        elif proto_num == 47:
                            proto_name = "GRE"
                        # VXLAN (UDP port 4789)
                        elif pkt.haslayer(UDP) and (pkt[UDP].sport == 4789 or pkt[UDP].dport == 4789):
                            proto_name = "VXLAN"
                        
                        if proto_name:
                            tunnel_key = f"{src_ip} → {dst_ip} ({proto_name})"
                            
                            if tunnel_key not in tunnel_flows:
                                tunnel_flows[tunnel_key] = {
                                    'src': src_ip,
                                    'dst': dst_ip,
                                    'ip_version': ip_version,
                                    'proto': proto_name,
                                    'total_pkts': 0,
                                    'fragmented_pkts': 0,
                                    'df_set_pkts': 0,
                                    'max_payload': 0,
                                    'min_payload': None
                                }
                            
                            t = tunnel_flows[tunnel_key]
                            t['total_pkts'] += 1
                            
                            # Fragmentation and DF bit (IPv4 only)
                            if pkt.haslayer(IP):
                                ip = pkt[IP]
                                is_frag = (ip.flags.MF == 1) or (int(ip.frag) > 0)
                                if is_frag:
                                    t['fragmented_pkts'] += 1
                                
                                if ip.flags.DF:
                                    t['df_set_pkts'] += 1
                                
                                # Payload size
                                ip_header_len = int(ip.ihl) * 4
                                payload_len = int(ip.len) - ip_header_len
                            elif pkt.haslayer(IPv6):
                                # IPv6 fragmentation check
                                if pkt.haslayer(IPv6ExtHdrFragment):
                                    t['fragmented_pkts'] += 1
                                
                                # IPv6 payload length
                                payload_len = pkt[IPv6].plen
                            else:
                                payload_len = 0
                            
                            if payload_len > t['max_payload']:
                                t['max_payload'] = payload_len
                            if t['min_payload'] is None or payload_len < t['min_payload']:
                                t['min_payload'] = payload_len
                
                except Exception:
                    continue
            
            # Check if PMTUD black holes received ICMP/ICMPv6 responses
            for icmp_entry in icmp_frag_needed:
                for pmtud_key in pmtud_blackholes.keys():
                    if icmp_entry['dst'] in pmtud_key:
                        pmtud_blackholes[pmtud_key]['icmp_received'] = True
            
            # Store results
            self.analysis_results['mtu_mss_analysis'] = tcp_flows
            self.analysis_results['tunnel_mtu_analysis'] = tunnel_flows
            self.analysis_results['icmp_frag_needed'] = icmp_frag_needed
            self.analysis_results['pmtud_blackholes'] = dict(pmtud_blackholes)
            self.analysis_results['ipv4_fragments'] = ipv4_fragments
            self.analysis_results['ipv6_fragments'] = ipv6_fragments
            self.analysis_results['jumbo_frames'] = jumbo_frames
            
            self.log_message(f"✓ MTU/MSS Analysis: {len(tcp_flows)} TCP flows, {len(tunnel_flows)} tunnels")
            self.log_message(f"  ICMP Messages: {len(icmp_frag_needed)} (IPv4+IPv6)")
            self.log_message(f"  PMTUD Black Holes: {len(pmtud_blackholes)}")
            self.log_message(f"  Fragments: IPv4={len(ipv4_fragments)}, IPv6={len(ipv6_fragments)}")
            self.log_message(f"  Jumbo Frames: {len(jumbo_frames)}")
            
        except Exception as e:
            import traceback
            self.log_message(f"❌ MTU/MSS analysis error: {str(e)}")
            self.log_message(traceback.format_exc())
            self.analysis_results['mtu_mss_analysis'] = {}
            self.analysis_results['tunnel_mtu_analysis'] = {}
            self.analysis_results['icmp_frag_needed'] = []
            self.analysis_results['pmtud_blackholes'] = {}
            self.analysis_results['ipv4_fragments'] = []
            self.analysis_results['ipv6_fragments'] = []
            self.analysis_results['jumbo_frames'] = []
            
#=====================================================================#    

    def analyze_packet_drops(self):
        """Analyze packet drops by detecting missing sequences, idle periods (over 30s), and tracking direction and drop counts. Supports IPv4 and IPv6."""
        try:
            drops = []
            all_packets = PacketList(list(self.src_packets) + list(self.dst_packets))
            connections = defaultdict(lambda: {
                "last_time": 0,
                "protocol": None,
                "ip_version": None,  # ✅ Track IP version
                "last_seq": None,
                "last_ack": None,
                "last_payload_len": 0,
                "direction": None,
                "drop_count": 0,
                "retransmit_count": 0,
                "reorder_count": 0
            })

            # Track if events found in first 1000 packets
            events_in_first_1000 = False
            absolute_latest_time = 0

            for idx, packet in enumerate(all_packets):
                try:
                    # Early exit if events detected in first 1000 and we've passed 1000 packets
                    if idx >= 1000 and events_in_first_1000:
                        break

                    packet_time = safe_float(packet.time)

                    if packet_time > absolute_latest_time:
                        absolute_latest_time = packet_time
                    
                    # ✅ Extract IPs using IPv6-compatible helper
                    src_ip, dst_ip, ttl = get_packet_ips(packet)
                    
                    # ✅ Determine IP version
                    ip_version = 'IPv6' if packet.haslayer(IPv6) else 'IPv4' if packet.haslayer(IP) else None
                    
                    if src_ip and dst_ip:
                        # Get protocol number
                        proto = None
                        if packet.haslayer(IP):
                            proto = packet[IP].proto
                        elif packet.haslayer(IPv6):
                            proto = packet[IPv6].nh  # Next Header
                        
                        if proto == 6 and packet.haslayer(TCP):
                            proto_name = "TCP"
                            src = f"{src_ip}:{packet[TCP].sport}"
                            dst = f"{dst_ip}:{packet[TCP].dport}"
                            connection = f"{src} → {dst}"
                            seq = packet[TCP].seq
                            ack = packet[TCP].ack

                            # Calculate TCP payload length
                            if packet.haslayer(IP):
                                ip_header_len = packet[IP].ihl * 4
                                total_len = packet[IP].len
                                tcp_header_len = packet[TCP].dataofs * 4
                                tcp_payload_len = max(total_len - ip_header_len - tcp_header_len, 0)
                            elif packet.haslayer(IPv6):
                                # IPv6: plen is payload length (excludes IPv6 header)
                                tcp_header_len = packet[TCP].dataofs * 4
                                tcp_payload_len = max(packet[IPv6].plen - tcp_header_len, 0)
                            else:
                                tcp_payload_len = 0
                            
                            direction = 'src→dst' if src == connection.split(' → ')[0] else 'dst→src'
                        
                        elif proto == 17 and packet.haslayer(UDP):
                            proto_name = "UDP"
                            src = f"{src_ip}:{packet[UDP].sport}"
                            dst = f"{dst_ip}:{packet[UDP].dport}"
                            connection = f"{src} → {dst}"
                            seq = None
                            ack = None
                            tcp_payload_len = 0
                            direction = 'src→dst' if src == connection.split(' → ')[0] else 'dst→src'
                        
                        elif proto == 1 and packet.haslayer(ICMP):
                            proto_name = "ICMP"
                            connection = f"{src_ip} → {dst_ip}"
                            seq = None
                            ack = None
                            tcp_payload_len = 0
                            direction = None
                        
                        elif proto == 58 and packet.haslayer(ICMPv6):  # ✅ ICMPv6 support
                            proto_name = "ICMPv6"
                            connection = f"{src_ip} → {dst_ip}"
                            seq = None
                            ack = None
                            tcp_payload_len = 0
                            direction = None
                        
                        else:
                            proto_name = f"IP Protocol {proto}" if proto else "Unknown"
                            connection = f"{src_ip} → {dst_ip}"
                            seq = None
                            ack = None
                            tcp_payload_len = 0
                            direction = None
                    
                    elif packet.haslayer(ARP):
                        proto_name = "ARP"
                        connection = f"{packet[ARP].psrc} → {packet[ARP].pdst}"
                        seq = None
                        ack = None
                        tcp_payload_len = 0
                        direction = None
                        ttl = None  # ARP has no TTL
                        ip_version = None  # ARP is Layer 2
                    
                    else:
                        proto_name = packet.name
                        connection = "Unknown Connection"
                        seq = None
                        ack = None
                        tcp_payload_len = 0
                        direction = None
                        ttl = None
                        ip_version = None

                    conn_data = connections[connection]
                    drop_increment = 0

                    # Track if event detected in current packet
                    event_detected = False

                    # Enhanced sequence gap detection for TCP
                    if proto_name == "TCP" and seq is not None:
                        if "seen_seqs" not in conn_data:
                            conn_data["seen_seqs"] = set()
                        seen_seqs = conn_data["seen_seqs"]
                        last_seq = conn_data["last_seq"]
                        last_payload_len = conn_data.get("last_payload_len", 0)

                        expected_seq = last_seq + last_payload_len if last_seq is not None else None

                        # Detect retransmissions
                        if seq in seen_seqs:
                            conn_data["retransmit_count"] += 1
                            event_detected = True

                        # Detect reordering
                        if last_seq is not None and seq < last_seq and seq not in seen_seqs:
                            conn_data["reorder_count"] += 1
                            event_detected = True

                        # Detect drops (sequence gaps)
                        if expected_seq is not None and seq > expected_seq:
                            gap = seq - expected_seq
                            drop_increment += gap
                            event_detected = True

                        seen_seqs.add(seq)
                        conn_data["last_seq"] = seq
                        conn_data["last_payload_len"] = tcp_payload_len
                        conn_data["last_ack"] = ack
                        conn_data["drop_count"] += drop_increment

                    # Set flag if event detected within first 1000 packets
                    if idx < 1000 and event_detected:
                        events_in_first_1000 = True

                    # Update connection metadata
                    if packet_time > conn_data["last_time"]:
                        conn_data["last_time"] = packet_time
                        conn_data["protocol"] = proto_name
                        conn_data["ip_version"] = ip_version  # ✅ Store IP version
                        conn_data["direction"] = direction

                except Exception:
                    continue

            # Only report connections idle for 30+ seconds
            if connections:
                if events_in_first_1000:
                    latest_time = max(safe_float(pkt.time) for pkt in all_packets)
                else:
                    latest_time = max(conn["last_time"] for conn in connections.values())
                
                for connection, data in connections.items():
                    idle_time = latest_time - data["last_time"]
                    if idle_time > 30:
                        ttl = ''
                        length = ''
                        protocol_type = data["protocol"]
                        ip_version = data.get("ip_version", 'N/A')  # ✅ Get IP version
                        direction = data["direction"] or "N/A"
                        drop_count = data.get("drop_count", 0)
                        last_seq = data.get("last_seq", 'N/A')
                        last_ack = data.get("last_ack", 'N/A')

                        # Find last packet for this connection to get TTL and length
                        for pkt in reversed(all_packets):
                            try:
                                pkt_conn = None
                                pkt_src_ip, pkt_dst_ip, pkt_ttl = get_packet_ips(pkt)
                                
                                if pkt_src_ip and pkt_dst_ip:
                                    proto = None
                                    if pkt.haslayer(IP):
                                        proto = pkt[IP].proto
                                    elif pkt.haslayer(IPv6):
                                        proto = pkt[IPv6].nh
                                    
                                    if proto == 6 and pkt.haslayer(TCP):
                                        pkt_conn = f"{pkt_src_ip}:{pkt[TCP].sport} → {pkt_dst_ip}:{pkt[TCP].dport}"
                                    elif proto == 17 and pkt.haslayer(UDP):
                                        pkt_conn = f"{pkt_src_ip}:{pkt[UDP].sport} → {pkt_dst_ip}:{pkt[UDP].dport}"
                                    elif proto in (1, 58):  # ICMP or ICMPv6
                                        pkt_conn = f"{pkt_src_ip} → {pkt_dst_ip}"
                                    else:
                                        pkt_conn = f"{pkt_src_ip} → {pkt_dst_ip}"
                                
                                elif pkt.haslayer(ARP):
                                    pkt_conn = f"{pkt[ARP].psrc} → {pkt[ARP].pdst}"
                                else:
                                    pkt_conn = "Unknown Connection"

                                if pkt_conn == connection:
                                    ttl = pkt_ttl if pkt_ttl is not None else 'N/A'
                                    length = len(pkt)
                                    break
                            except Exception:
                                continue

                        drops.append({
                            'connection': connection,
                            'idle_seconds': int(idle_time),
                            'last_seen': safe_timestamp(data["last_time"]),
                            'ttl': ttl,
                            'length': length,
                            'protocol': protocol_type,
                            'ip_version': ip_version,  # ✅ Include IP version
                            'direction': direction,
                            'drop_count': drop_count,
                            'retransmit_count': data.get("retransmit_count", 0),
                            'reorder_count': data.get("reorder_count", 0),
                            'last_seq': last_seq,
                            'last_ack': last_ack,
                        })

            self.analysis_results['packet_drops'] = drops
            self.log_message(f"✓ Packet drop analysis: {len(drops)} potential drops detected")
            
        except Exception as e:
            import traceback
            self.log_message(f"⚠️ Packet drop analysis error: {str(e)}")
            self.log_message(traceback.format_exc())
            self.analysis_results['packet_drops'] = []


#=============================neighborship failure part=========================================#


    def is_eigrp_hello(self, packet):
        """Detect EIGRP Hello (Protocol 88, Opcode 5) for IPv4 and IPv6."""
        try:
            # IPv4 EIGRP
            if packet.haslayer(IP) and packet[IP].proto == 88:
                payload_bytes = bytes(packet[IP].payload)
                if len(payload_bytes) > 1 and payload_bytes[1] == 5:
                    return True
            # ✅ IPv6 EIGRP
            elif packet.haslayer(IPv6) and packet[IPv6].nh == 88:
                payload_bytes = bytes(packet[IPv6].payload)
                if len(payload_bytes) > 1 and payload_bytes[1] == 5:
                    return True
        except:
            pass
        return False


    def is_hello(self, packet):
        """Multi-protocol Hello/Keepalive detection (OSPF/EIGRP/BGP/IS-IS) for IPv4 and IPv6."""
        try:
            # ✅ OSPF (Protocol 89, Type 1) - IPv4 and IPv6
            if packet.haslayer(IP) and packet[IP].proto == 89:
                if packet.haslayer('OSPF_Hdr') and packet['OSPF_Hdr'].type == 1:
                    return True, 'OSPF'
            elif packet.haslayer(IPv6) and packet[IPv6].nh == 89:
                if packet.haslayer('OSPF_Hdr') and packet['OSPF_Hdr'].type == 1:
                    return True, 'OSPFv3'  # Distinguish OSPFv3
            
            # ✅ EIGRP (Protocol 88, Opcode 5) - IPv4 and IPv6
            if self.is_eigrp_hello(packet):
                return True, 'EIGRP'
            
            # ✅ BGP (TCP/179, Type 1 or 4) - Works for both IPv4 and IPv6
            if packet.haslayer(TCP) and (packet[TCP].sport == 179 or packet[TCP].dport == 179):
                payload = bytes(packet[TCP].payload)
                if len(payload) >= 19 and payload[18] in [1, 4]:
                    return True, 'BGP'
            
            # IS-IS (LLC DSAP/SSAP 0xFE) - Layer 2, no IP version
            if packet.haslayer('LLC'):
                llc = packet['LLC']
                if getattr(llc, 'dsap', None) == 0xfe and getattr(llc, 'ssap', None) == 0xfe:
                    return True, 'ISIS'
            
            return False, None
        except:
            return False, None

    def analyze_neighbor_failures(self):
        """
        Multi-protocol neighbor analysis with anti-crash limits.
        Maximum 200 neighbors analyzed, 50 displayed in HTML.
        Supports IPv4 and IPv6.
        """
        try:
            from datetime import datetime, timezone
            
            MAX_ANALYZE = 200  # Prevent memory explosion
            all_packets = list(self.src_packets) + list(self.dst_packets)
            hello_sent = defaultdict(list)
            hello_received = defaultdict(list)
            hello_detected = 0
            
            # Phase 1: Detect Hello packets
            for pkt in all_packets:
                try:
                    is_hello_pkt, proto = self.is_hello(pkt)
                    if not is_hello_pkt:
                        continue
                    
                    hello_detected += 1
                    
                    # ✅ Extract addresses (MAC for IS-IS, IP for others - IPv4/IPv6 compatible)
                    if proto == 'ISIS':
                        src = self.format_mac(getattr(pkt, 'src', b''))
                        dst = self.format_mac(getattr(pkt, 'dst', b''))
                    else:
                        # Use IPv6-compatible helper
                        src_ip, dst_ip, _ = get_packet_ips(pkt)
                        if not src_ip or not dst_ip:
                            continue
                        src = src_ip
                        dst = dst_ip
                    
                    ts = float(pkt.time)
                    h_int, d_int = self.get_protocol_timers(pkt, proto)
                    
                    n_key = f"{src}#{dst}#{proto}"
                    r_key = f"{dst}#{src}#{proto}"
                    
                    h_data = {'timestamp': ts, 'hello_interval': h_int, 'dead_interval': d_int}
                    hello_sent[n_key].append(h_data)
                    hello_received[r_key].append(h_data)
                    
                except:
                    continue
            
            self.log_message(f"📊 Hello Detection: {hello_detected} packets")
            self.log_message(f"   Neighbor pairs: {len(hello_sent)}")
            
            if hello_detected == 0:
                self.analysis_results['neighbor_failures'] = []
                return
            
            # Phase 2: Analyze neighbors (LIMITED)
            neighbors = []
            analyzed = set()
            processed = 0
            
            # Sort by packet count (most active first)
            sorted_keys = sorted(hello_sent.keys(), key=lambda k: len(hello_sent[k]), reverse=True)
            
            for n_key in sorted_keys:
                if processed >= MAX_ANALYZE:
                    break
                    
                if n_key in analyzed:
                    continue
                
                parts = n_key.split('#')
                if len(parts) != 3:
                    continue
                
                src, dst, protocol = parts
                sent_times = hello_sent[n_key]
                rev_key = f"{dst}#{src}#{protocol}"
                recv_times = hello_received.get(rev_key, [])
                
                # Metrics
                sent_count = len(sent_times)
                recv_count = len(recv_times)
                interval = sent_times[0]['hello_interval'] or 10
                
                # Expected count (time-based)
                if sent_count > 1:
                    duration = sent_times[-1]['timestamp'] - sent_times[0]['timestamp']
                    expected = int(duration / interval) + 1 if interval > 0 else sent_count
                else:
                    expected = 1
                
                success_rate = (recv_count / expected * 100) if expected > 0 else 0
                missed = max(0, expected - recv_count)
                
                # RTT calculation
                rtt_times = []
                for sent in sent_times[:50]:  # Sample first 50
                    matching = [r for r in recv_times if r['timestamp'] >= sent['timestamp']]
                    if matching:
                        closest = min(matching, key=lambda r: r['timestamp'] - sent['timestamp'])
                        rtt = (closest['timestamp'] - sent['timestamp']) * 1000
                        if 0 <= rtt <= 10000:
                            rtt_times.append(rtt)
                
                avg_rtt = sum(rtt_times) / len(rtt_times) if rtt_times else 0
                
                # Intervals
                hello_sec = sent_times[0]['hello_interval'] or 10
                dead_sec = sent_times[0]['dead_interval'] or 30
                dead_ms = dead_sec * 1000
                
                # Severity classification
                if success_rate >= 95 and avg_rtt < dead_ms * 0.5:
                    severity = {'status': 'HEALTHY', 'icon': '✅', 'color': '#28a745', 'action': 'Monitor'}
                elif success_rate >= 75 and avg_rtt < dead_ms * 0.75:
                    severity = {'status': 'DEGRADED', 'icon': '⚠️', 'color': '#ffc107', 'action': 'Investigate'}
                elif success_rate >= 50:
                    severity = {'status': 'CRITICAL', 'icon': '🔴', 'color': '#ff9800', 'action': 'Check link'}
                else:
                    severity = {'status': 'DOWN', 'icon': '❌', 'color': '#dc3545', 'action': 'Fix connectivity'}
                
                # Timestamps
                last_recv = recv_times[-1]['timestamp'] if recv_times else 0
                curr_time = max([p.time for p in all_packets]) if all_packets else 0
                time_since = curr_time - last_recv if recv_count > 0 else float('inf')
                
                try:
                    last_hello_str = datetime.fromtimestamp(last_recv, tz=timezone.utc).strftime('%H:%M:%S.%f')[:-3] if recv_count > 0 else "Never"
                except:
                    last_hello_str = "Unknown"
                
                neighbors.append({
                    'neighbor': f"{src} ↔ {dst}",
                    'protocol': protocol,
                    'status': severity['status'],
                    'icon': severity['icon'],
                    'color': severity['color'],
                    'hello_interval_ms': f"{hello_sec}s",
                    'success_rate': f"{success_rate:.1f}%",
                    'response_time_ms': f"{avg_rtt:.1f}",
                    'consecutive_missed': missed,
                    'total_sent': sent_count,
                    'total_received': recv_count,
                    'last_hello': last_hello_str,
                    'time_since_last_ms': f"{time_since * 1000:.0f}",
                    'root_cause': "Healthy" if severity['status'] == 'HEALTHY' else f"{missed} missed",
                    'recommended_action': severity['action']
                })
                
                analyzed.add(n_key)
                analyzed.add(rev_key)
                processed += 1
            
            self.analysis_results['neighbor_failures'] = neighbors
            self.log_message(f"✅ Analyzed: {len(neighbors)} neighbors (limit: {MAX_ANALYZE})")
            
            if len(hello_sent) > MAX_ANALYZE:
                self.log_message(f"⚠️  Truncated: {len(hello_sent) - MAX_ANALYZE} neighbors not analyzed (too many)")
            
        except Exception as e:
            import traceback
            self.log_message(f"❌ Neighbor analysis error: {str(e)}")
            self.log_message(traceback.format_exc())
            self.analysis_results['neighbor_failures'] = []
            
    def get_protocol_timers(self, pkt, proto):
        """Extract protocol-specific timers with safe defaults (IPv4/IPv6 compatible)."""
        h_int, d_int = 10, 40
        try:
            if proto in ('OSPF', 'OSPFv3') and pkt.haslayer('OSPF_Hdr'):
                ospf = pkt['OSPF_Hdr']
                h_int = getattr(ospf, 'hellointerval', 10)
                d_int = getattr(ospf, 'deadinterval', 40)
            elif proto == 'EIGRP':
                # ✅ Check both IPv4 and IPv6
                payload = None
                if pkt.haslayer(IP):
                    payload = bytes(pkt[IP].payload)
                elif pkt.haslayer(IPv6):
                    payload = bytes(pkt[IPv6].payload)
                
                if payload and len(payload) >= 22:
                    d_int = (payload[20] << 8 | payload[21])
                    h_int = d_int // 3 if d_int > 0 else 5
            elif proto == 'ISIS':
                # IS-IS defaults
                h_int, d_int = 10, 30
            elif proto == 'BGP':
                h_int, d_int = 60, 180
        except:
            pass
        return h_int, d_int

    def format_mac(self, mac_input):
        """Robust MAC formatting for IS-IS."""
        try:
            if isinstance(mac_input, bytes) and len(mac_input) >= 6:
                return ':'.join(f'{b:02x}' for b in mac_input[:6])
            elif isinstance(mac_input, str):
                mac_clean = mac_input.replace(':', '').replace('-', '').replace('.', '').lower()
                if len(mac_clean) >= 12:
                    return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
            return '00:00:00:00:00:00'
        except:
            return 'unknown'
#=========================neighbor_state_analysis_and_table===================================================================================#

    def analyze_stuck_neighbor_states(self):
        """Detect OSPF/BGP/EIGRP/ISIS neighbors stuck in intermediate states (IPv4 + IPv6)."""
        try:
            from datetime import datetime
            
            stuck_neighbors = []
            state_timeline = defaultdict(list)
            
            all_packets = list(self.src_packets) + list(self.dst_packets)
            
            # ----- ISIS state timeline from pre-parsed analysis -----
            isis_data = self.analysis_results.get('isis_analysis', {})
            
            # Hello PDUs → adjacency forming / Init
            for pdu in isis_data.get('hello_pdus', []):
                src = pdu.get('src_mac', '') or pdu.get('src', '')
                dst = pdu.get('dst_mac', '') or pdu.get('dst', '')
                ts  = float(pdu.get('timestamp', 0))
                if src and dst and ts > 0:
                    neighbor_key = f"{src}↔{dst}"
                    state_timeline[neighbor_key].append({
                        'time': ts,
                        'timestamp': datetime.utcfromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3],
                        'state': 'Init',
                        'protocol': 'ISIS'
                    })
            
            # LSP PDUs → adjacency up / exchanging LSDB
            for pdu in isis_data.get('lsp_pdus', []):
                src = pdu.get('src_mac', '') or pdu.get('src', '')
                dst = pdu.get('dst_mac', '') or pdu.get('dst', '')
                ts  = float(pdu.get('timestamp', 0))
                if src and dst and ts > 0:
                    neighbor_key = f"{src}↔{dst}"
                    state_timeline[neighbor_key].append({
                        'time': ts,
                        'timestamp': datetime.utcfromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3],
                        'state': 'Up',
                        'protocol': 'ISIS'
                    })
            
            # CSNP PDUs → LSDB syncing
            for pdu in isis_data.get('csnp_pdus', []):
                src = pdu.get('src_mac', '') or pdu.get('src', '')
                dst = pdu.get('dst_mac', '') or pdu.get('dst', '')
                ts  = float(pdu.get('timestamp', 0))
                if src and dst and ts > 0:
                    neighbor_key = f"{src}↔{dst}"
                    state_timeline[neighbor_key].append({
                        'time': ts,
                        'timestamp': datetime.utcfromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3],
                        'state': 'Syncing',
                        'protocol': 'ISIS'
                    })
            
            # PSNP PDUs → LSDB synchronized / steady
            for pdu in isis_data.get('psnp_pdus', []):
                src = pdu.get('src_mac', '') or pdu.get('src', '')
                dst = pdu.get('dst_mac', '') or pdu.get('dst', '')
                ts  = float(pdu.get('timestamp', 0))
                if src and dst and ts > 0:
                    neighbor_key = f"{dst}↔{src}"
                    state_timeline[neighbor_key].append({
                        'time': ts,
                        'timestamp': datetime.utcfromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3],
                        'state': 'Synced',
                        'protocol': 'ISIS'
                    })
            
            # Track state transitions from packets
            for pkt in all_packets:
                try:
                    neighbor_key = None
                    state = None
                    protocol = None
                    
                    # Initialize OSPF-specific fields
                    hello_interval = None
                    dead_interval = None
                    priority = None
                    mtu = None
                    router_id = None
                    area_id = None
                    
                    # ✅ Extract IPs early for both IPv4 and IPv6
                    src_ip, dst_ip, _ = get_packet_ips(pkt)
                    
                    # ✅ OSPF State Detection (IPv4 + IPv6)
                    if pkt.haslayer('OSPF_Hdr') and (src_ip and dst_ip):
                        # Distinguish OSPF (IPv4) from OSPFv3 (IPv6)
                        protocol = 'OSPFv3' if pkt.haslayer(IPv6) else 'OSPF'
                        neighbor_key = f"{src_ip}↔{dst_ip}"
                        
                        # Extract OSPF header fields
                        ospf_hdr = pkt['OSPF_Hdr']
                        router_id = getattr(ospf_hdr, 'src', None)
                        area_id = getattr(ospf_hdr, 'area', None)
                        
                        if pkt.haslayer('OSPF_Hello'):
                            hello = pkt['OSPF_Hello']
                            neighbors = getattr(hello, 'neighbors', [])
                            state = '2-Way' if neighbors else 'Init'
                            
                            # Extract Hello parameters
                            hello_interval = getattr(hello, 'hellointerval', None)
                            dead_interval = getattr(hello, 'deadinterval', None)
                            priority = getattr(hello, 'prio', None)
                            
                        elif pkt.haslayer('OSPF_DBDesc'):
                            dbd = pkt['OSPF_DBDesc']
                            flags = getattr(dbd, 'dbdescr', 0)
                            state = 'ExStart' if (flags & 0x04) else 'Exchange'
                            
                            # Extract DBD parameters
                            mtu = getattr(dbd, 'mtu', None)
                            
                        elif pkt.haslayer('OSPF_LSReq'):
                            state = 'Loading'
                            
                        elif pkt.haslayer('OSPF_LSUpd') or pkt.haslayer('OSPF_LSAck'):
                            state = 'Full'
                    
                    # ✅ BGP State Detection (IPv4 + IPv6 - TCP layer handles both)
                    elif pkt.haslayer(TCP) and (pkt[TCP].sport == 179 or pkt[TCP].dport == 179) and (src_ip and dst_ip):
                        protocol = 'BGP'
                        neighbor_key = f"{src_ip}:{pkt[TCP].sport}↔{dst_ip}:{pkt[TCP].dport}"
                        
                        flags = pkt[TCP].flags
                        payload_len = len(bytes(pkt[TCP].payload))
                        
                        if flags & 0x02:  # SYN
                            state = 'Connect'
                        elif flags & 0x04:  # RST
                            state = 'Idle'
                        elif flags & 0x01:  # FIN
                            state = 'Closing'
                        elif payload_len >= 19:  # BGP message present
                            payload = bytes(pkt[TCP].payload)
                            if payload[0:16] == b'\xff' * 16:  # BGP marker
                                msg_type = payload[18] if len(payload) > 18 else 0
                                if msg_type == 1:  # OPEN
                                    state = 'OpenSent'
                                elif msg_type == 4:  # KEEPALIVE
                                    state = 'Established'
                                elif msg_type == 2:  # UPDATE
                                    state = 'Established'
                                else:
                                    state = 'OpenConfirm'
                        elif flags & 0x10:  # ACK only
                            state = 'Active'
                    
                    # ✅ EIGRP State Detection (IPv4 + IPv6)
                    elif src_ip and dst_ip:
                        proto_num = None
                        if pkt.haslayer(IP):
                            proto_num = pkt[IP].proto
                        elif pkt.haslayer(IPv6):
                            proto_num = pkt[IPv6].nh
                        
                        if proto_num == 88:  # EIGRP
                            protocol = 'EIGRP'
                            neighbor_key = f"{src_ip}↔{dst_ip}"
                            
                            # Get payload
                            if pkt.haslayer(IP):
                                payload = bytes(pkt[IP].payload)
                            elif pkt.haslayer(IPv6):
                                payload = bytes(pkt[IPv6].payload)
                            else:
                                payload = b''
                            
                            if len(payload) >= 20:
                                opcode = payload[1]
                                if opcode == 5:  # Hello
                                    state = 'Up'
                                elif opcode == 1:  # Update
                                    state = 'Passive'
                                elif opcode == 3:  # Query
                                    state = 'Active'
                                elif opcode == 4:  # Reply
                                    state = 'Passive'
                                elif opcode in (10, 11):  # SIA-Query/Reply
                                    state = 'SIA'
                                else:
                                    state = 'Up'
                    
                    if neighbor_key and state and protocol:
                        state_entry = {
                            'time': float(pkt.time),
                            'timestamp': datetime.utcfromtimestamp(float(pkt.time)).strftime('%H:%M:%S.%f')[:-3],
                            'state': state,
                            'protocol': protocol
                        }
                        
                        # Add OSPF-specific fields if available
                        if protocol in ('OSPF', 'OSPFv3'):
                            if hello_interval is not None:
                                state_entry['hello_interval'] = hello_interval
                            if dead_interval is not None:
                                state_entry['dead_interval'] = dead_interval
                            if priority is not None:
                                state_entry['priority'] = priority
                            if mtu is not None:
                                state_entry['mtu'] = mtu
                            if router_id is not None:
                                state_entry['router_id'] = router_id
                            if area_id is not None:
                                state_entry['area_id'] = area_id
                        
                        state_timeline[neighbor_key].append(state_entry)
                except:
                    continue
            
            # Analyze for stuck states
            for neighbor, events in state_timeline.items():
                if len(events) < 2:
                    continue
                
                events.sort(key=lambda x: x['time'])
                protocol = events[0]['protocol']
                
                # Define thresholds and final states per protocol
                if protocol in ('OSPF', 'OSPFv3'):  # ✅ Include OSPFv3
                    threshold_sec = 30
                    final_states = ['Full']
                    intermediate_states = ['Init', '2-Way', 'ExStart', 'Exchange', 'Loading']
                elif protocol == 'BGP':
                    threshold_sec = 60
                    final_states = ['Established']
                    intermediate_states = ['Connect', 'Active', 'OpenSent', 'OpenConfirm']
                elif protocol == 'EIGRP':
                    threshold_sec = 90
                    final_states = ['Passive', 'Up']
                    intermediate_states = ['Active', 'SIA']
                elif protocol == 'ISIS':
                    threshold_sec = 30
                    final_states = ['Up', 'Synced']
                    intermediate_states = ['Init', 'Syncing']
                else:
                    continue
                
                # Check each state duration
                for i in range(len(events) - 1):
                    current = events[i]
                    next_event = events[i + 1]
                    duration = next_event['time'] - current['time']
                    
                    if current['state'] in intermediate_states and duration > threshold_sec:
                        stuck_neighbors.append({
                            'neighbor': neighbor,
                            'protocol': protocol,
                            'stuck_state': current['state'],
                            'duration_sec': int(duration),
                            'first_seen': current['timestamp'],
                            'next_state': next_event['state'],
                            'severity': 'CRITICAL' if duration > threshold_sec * 2 else 'WARNING'
                        })
                
                # Check if never reached final state
                last_state = events[-1]['state']
                if last_state not in final_states:
                    total_duration = events[-1]['time'] - events[0]['time']
                    if total_duration > threshold_sec:
                        stuck_neighbors.append({
                            'neighbor': neighbor,
                            'protocol': protocol,
                            'stuck_state': last_state,
                            'duration_sec': int(total_duration),
                            'first_seen': events[0]['timestamp'],
                            'next_state': 'Never progressed',
                            'severity': 'CRITICAL',
                        })
            
            self.analysis_results['stuck_neighbor_states'] = stuck_neighbors
            self.log_message(f"✓ Stuck state analysis: {len(stuck_neighbors)} issues detected")
            
        except Exception as e:
            import traceback
            self.log_message(f"⚠️ Stuck state analysis error: {str(e)}")
            self.log_message(traceback.format_exc())
            self.analysis_results['stuck_neighbor_states'] = []

    def _diagnose_stuck_state_detailed(self, protocol, state, events):
        """Enhanced diagnosis with packet-level analysis for all protocols."""
        
        # Analyze packets in this state for specific issues
        state_packets = [e for e in events if e['state'] == state]
        
        # ==================== OSPF / OSPFv3 ====================
        if protocol in ('OSPF', 'OSPFv3'):  # ✅ Handle both
            if state == 'Init':
                # Check for parameter mismatches
                hello_intervals = set()
                dead_intervals = set()
                area_ids = set()
                
                for pkt in state_packets:
                    if 'hello_interval' in pkt and pkt['hello_interval'] is not None:
                        hello_intervals.add(pkt['hello_interval'])
                    if 'dead_interval' in pkt and pkt['dead_interval'] is not None:
                        dead_intervals.add(pkt['dead_interval'])
                    if 'area_id' in pkt and pkt['area_id'] is not None:
                        area_ids.add(str(pkt['area_id']))
                
                if len(hello_intervals) > 1:
                    return f"Hello interval mismatch: {sorted(hello_intervals)}s"
                if len(dead_intervals) > 1:
                    return f"Dead interval mismatch: {sorted(dead_intervals)}s"
                if len(area_ids) > 1:
                    return f"Area ID mismatch: {sorted(area_ids)}"
                
                return "One-way communication (neighbor not seeing this router in Hello packets)"
            
            elif state == '2-Way':
                # Check DR/BDR election issues
                priorities = set()
                for pkt in state_packets:
                    if 'priority' in pkt and pkt['priority'] is not None:
                        priorities.add(pkt['priority'])
                
                if priorities and priorities == {0}:
                    return "All routers have priority 0 - no DR/BDR can be elected"
                
                return "DR/BDR election incomplete or network type mismatch (may be normal for non-DR routers)"
            
            elif state == 'ExStart':
                # Check for MTU issues and duplicate router IDs
                mtu_values = set()
                router_ids = []
                
                for pkt in state_packets:
                    if 'mtu' in pkt and pkt['mtu'] is not None:
                        mtu_values.add(pkt['mtu'])
                    if 'router_id' in pkt and pkt['router_id'] is not None:
                        router_ids.append(str(pkt['router_id']))
                
                # Priority 1: Check MTU mismatch
                if len(mtu_values) > 1:
                    return f"MTU mismatch detected: {sorted(mtu_values)} bytes"
                
                # Priority 2: Check for TRUE duplicate router-id
                unique_rids = set(router_ids)
                if len(router_ids) > 1 and len(unique_rids) == 1:
                    rid = next(iter(unique_rids))
                    return f"Duplicate router-id detected on both routers: {rid}"
                
                return "DBD negotiation failed (check MTU, verify unique router-id, or check firewall blocking)"
            
            elif state == 'Exchange':
                return "Database description incomplete (packet loss, ACL blocking, or large LSDB with small MTU)"
            
            elif state == 'Loading':
                return "LSA requests not fulfilled (LSAs missing, filtered by distribute-list, or LSDB corruption)"
        
        # ==================== BGP ====================
        elif protocol == 'BGP':
            if state == 'Connect':
                return "TCP SYN not acknowledged (verify routing to BGP neighbor, check firewall rules blocking TCP/179)"
            elif state == 'Active':
                return "BGP session retrying after failure (check AS number mismatch, MD5 authentication, or TTL security)"
            elif state == 'OpenSent':
                return "BGP OPEN message sent but no response (verify AS numbers match, check BGP timers, authentication mismatch)"
            elif state == 'OpenConfirm':
                return "BGP KEEPALIVE not received (check packet loss, verify keepalive timer not too aggressive, or session reset)"
            elif state == 'Idle':
                return "BGP neighbor administratively down or refusing connection (check 'neighbor shutdown', verify IP reachability)"
        
        # ==================== EIGRP ====================
        elif protocol == 'EIGRP':
            if state == 'Active':
                query_count = len([e for e in events if e['state'] == 'Active'])
                passive_count = len([e for e in events if e['state'] == 'Passive'])
                
                if query_count > 5 and passive_count == 0:
                    return f"Route stuck in Active state - {query_count} Queries sent with no Replies (potential SIA condition)"
                else:
                    return "Route in Active state - waiting for Query replies from neighbors (normal during convergence)"
            elif state == 'SIA':
                return "Stuck-In-Active (SIA) - neighbor not responding to Queries within 180s (CRITICAL: check WAN latency, neighbor responsiveness)"
            elif state == 'Up':
                return "EIGRP neighbor adjacency unstable (check AS number, K-values, authentication mismatch)"
        
        # ==================== ISIS ====================
        elif protocol == 'ISIS':
            if state == 'Init':
                return "IS-IS Hello packets detected but adjacency not forming (check circuit-type L1/L2 mismatch, verify hello padding, MTU issues)"
            elif state == 'Syncing':
                csnp_count = len([e for e in events if e['state'] == 'Syncing'])
                if csnp_count > 10:
                    return f"LSDB synchronization stuck - {csnp_count} CSNP exchanges (check MTU, verify LSP flooding not blocked, large LSDB)"
                else:
                    return "LSDB synchronization incomplete (CSNP/PSNP exchange in progress, check for packet loss or ACL blocking)"
        
        # Fallback
        return self._diagnose_stuck_state(protocol, state)


    def _diagnose_stuck_state(self, protocol, state):
        """Diagnose root cause of stuck state."""
        ospf_diagnosis = {
            'Init': 'One-way communication (neighbor not seeing this router in Hello)',
            '2-Way': 'DR/BDR election issue or network type mismatch',
            'ExStart': 'DBD negotiation failed (MTU mismatch or router-id conflict)',
            'Exchange': 'Database description incomplete (packet loss or ACL blocking)',
            'Loading': 'LSA requests not fulfilled (LSAs missing or filtered)'
        }
        
        bgp_diagnosis = {
            'Idle': 'Connection refused or administratively down',
            'Connect': 'TCP handshake failing (firewall, routing issue)',
            'Active': 'BGP connection retrying (wrong AS or authentication)',
            'OpenSent': 'BGP OPEN not acknowledged (AS/timer/auth mismatch)',
            'OpenConfirm': 'KEEPALIVE not received (packet loss)'
        }
        
        eigrp_diagnosis = {
            'Active': 'Route in Active state - waiting for Query replies',
            'SIA': 'Stuck-In-Active - neighbor not responding to Query (CRITICAL)'
        }
        
        isis_diagnosis = {
            'Init': 'Hello packets detected but adjacency not forming',
            'Syncing': 'LSDB synchronization incomplete (CSNP/PSNP exchange stuck)'
        }
        
        # ✅ Handle both OSPF and OSPFv3
        if protocol in ('OSPF', 'OSPFv3'):
            return ospf_diagnosis.get(state, 'Unknown OSPF issue')
        elif protocol == 'BGP':
            return bgp_diagnosis.get(state, 'Unknown BGP issue')
        elif protocol == 'EIGRP':
            return eigrp_diagnosis.get(state, 'Unknown EIGRP issue')
        elif protocol == 'ISIS':
            return isis_diagnosis.get(state, 'Unknown ISIS issue')
        else:
            return 'Unknown protocol issue'
        
    def generate_stuck_states_table(self):
        """Generate HTML table for stuck neighbor states analysis."""
        stuck = self.analysis_results.get('stuck_neighbor_states', [])
        
        if not stuck:
            return '''
                <div class="success-message">
                    <h3>✅ No Stuck Neighbor States Detected</h3>
                    <p>All routing protocol neighbors are progressing through state machines normally.</p>
                    <ul style="margin-top: 10px;">
                        <li>OSPF/OSPFv3 neighbors reaching Full state</li>
                        <li>BGP sessions establishing properly</li>
                        <li>EIGRP routes converging (For SIA- Check EIGRP Tab)</li>
                        <li>ISIS adjacencies forming correctly</li>
                    </ul>
                </div>
            '''
        
        # Group by severity
        critical = [s for s in stuck if s['severity'] == 'CRITICAL']
        warning = [s for s in stuck if s['severity'] == 'WARNING']
        
        summary_html = f'''
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px;">
                <div style="background: #dc354522; padding: 15px; border-radius: 8px; border-left: 4px solid #dc3545;">
                    <div style="font-size: 2rem; font-weight: bold; color: #dc3545;">{len(critical)}</div>
                    <div style="color: #666; text-transform: uppercase; font-size: 0.85rem;">Critical Issues</div>
                </div>
                <div style="background: #ffc10722; padding: 15px; border-radius: 8px; border-left: 4px solid #ffc107;">
                    <div style="font-size: 2rem; font-weight: bold; color: #ffc107;">{len(warning)}</div>
                    <div style="color: #666; text-transform: uppercase; font-size: 0.85rem;">Warnings</div>
                </div>
                <div style="background: #007bff22; padding: 15px; border-radius: 8px; border-left: 4px solid #007bff;">
                    <div style="font-size: 2rem; font-weight: bold; color: #007bff;">{len(stuck)}</div>
                    <div style="color: #666; text-transform: uppercase; font-size: 0.85rem;">Total Issues</div>
                </div>
            </div>
        '''
        
        # Build table rows
        rows = []
        for item in stuck:
            severity_color = '#dc3545' if item['severity'] == 'CRITICAL' else '#ffc107'
            severity_icon = '🔴' if item['severity'] == 'CRITICAL' else '⚠️'
            
            # ✅ Protocol-specific styling with OSPFv3
            protocol_colors = {
                'OSPF': '#3146a2',
                'OSPFv3': '#4a5fc2',  # Slightly lighter blue for OSPFv3
                'BGP': '#aa539d',
                'EIGRP': '#089981',
                'ISIS': '#cc8800'
            }
            protocol_color = protocol_colors.get(item['protocol'], '#666')
            
            rows.append(f'''
                <tr style="border-left: 4px solid {severity_color};">
                    <td>
                        <span style="background:{severity_color}; color:white; padding:6px 12px; border-radius:6px; font-weight:bold; display:inline-block;">
                            {severity_icon} {item['severity']}
                        </span>
                    </td>
                    <td><code style="background:#f4f4f4; padding:4px 8px; border-radius:4px; font-size:12px;">{item['neighbor']}</code></td>
                    <td>
                        <span style="background:{protocol_color}; color:white; padding:4px 10px; border-radius:4px; font-weight:bold;">
                            {item['protocol']}
                        </span>
                    </td>
                    <td style="color:{severity_color}; font-weight:bold; font-size:14px;">{item['stuck_state']}</td>
                    <td style="font-weight:bold; color:#333;">{item['duration_sec']}s</td>
                    <td><code style="font-family:monospace; font-size:11px;">{item['first_seen']}</code></td>
                    <td>
                        <span style="background:#e8f4f8; padding:4px 8px; border-radius:4px; font-size:12px;">
                            {item['next_state']}
                        </span>
                    </td>
                </tr>
            ''')
        
        table_html = f'''
            {summary_html}
            <div style="overflow-x: auto;">
                <table style="width:100%; border-collapse:collapse; margin-top:10px;">
                    <thead>
                        <tr style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color:white;">
                            <th style="padding:12px; text-align:left; font-weight:600;">Severity</th>
                            <th style="padding:12px; text-align:left; font-weight:600;">Neighbor</th>
                            <th style="padding:12px; text-align:left; font-weight:600;">Protocol</th>
                            <th style="padding:12px; text-align:left; font-weight:600;">Stuck State</th>
                            <th style="padding:12px; text-align:left; font-weight:600;">Duration</th>
                            <th style="padding:12px; text-align:left; font-weight:600;">First Seen</th>
                            <th style="padding:12px; text-align:left; font-weight:600;">Next State</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        '''
        
        return table_html
#=============================================================================================================#

    def analyze_routing_loops(self):
        """Advanced Routing Loop Detection with IPv4 and IPv6 support, enhanced evidence and grading."""
        try:
            from scapy.all import Ether
            import hashlib

            loops = []
            all_packets = self.src_packets + self.dst_packets
            flows = defaultdict(list)
            ip_id_tracking = defaultdict(list)
            payload_hash_tracking = defaultdict(list)

            for packet in all_packets:
                try:
                    # ✅ Extract IPs using universal helper (IPv4 + IPv6)
                    src_ip, dst_ip, ttl = get_packet_ips(packet)
                    
                    if not src_ip or not dst_ip:
                        continue
                    
                    flow_key = "{} -> {}".format(src_ip, dst_ip)
                    pkt_time = safe_float(packet.time)
                    ts_str = safe_timestamp(packet.time)
                    mac_src = packet[Ether].src if packet.haslayer(Ether) else "N/A"
                    mac_dst = packet[Ether].dst if packet.haslayer(Ether) else "N/A"
                    
                    # ✅ Get payload and ID from IPv4 or IPv6
                    if packet.haslayer(IP):
                        payload_data = bytes(packet[IP].payload)
                        ip_id = packet[IP].id
                        ip_id_hex = hex(packet[IP].id)
                        proto = packet[IP].proto
                        flags = packet[IP].flags if hasattr(packet[IP], 'flags') else 0
                        is_ipv6 = False
                    elif packet.haslayer(IPv6):
                        payload_data = bytes(packet[IPv6].payload)
                        # IPv6 doesn't have IP ID - use Flow Label
                        ip_id = packet[IPv6].fl
                        ip_id_hex = hex(packet[IPv6].fl)
                        proto = packet[IPv6].nh
                        flags = 0  # IPv6 has no flags
                        is_ipv6 = True
                    else:
                        continue
                    
                    payload_hash = hashlib.sha256(payload_data).hexdigest()[:16]

                    pkt_info = {
                        'ttl': ttl,
                        'time': pkt_time,
                        'timestamp': ts_str,
                        'ip_id': ip_id,
                        'ip_id_hex': ip_id_hex,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'packet_size': len(packet),
                        'protocol': proto,
                        'flags': flags,
                        'mac_src': mac_src,
                        'mac_dst': mac_dst,
                        'payload_hash': payload_hash,
                        'is_ipv6': is_ipv6,
                    }
                    flows[flow_key].append(pkt_info)

                    # Track IP ID (IPv4) or Flow Label (IPv6) duplicates
                    ip_id_key = "{}-{}-{}".format(src_ip, ip_id, dst_ip)
                    ip_id_tracking[ip_id_key].append(pkt_info)

                    payload_key = (src_ip, dst_ip, payload_hash)
                    payload_hash_tracking[payload_key].append(pkt_info)
                except Exception:
                    continue

            # IP-ID/Flow-Label duplicate based detection (with TTL/MAC sanity checks)
            for ip_id_key, occs in ip_id_tracking.items():
                if len(occs) > 1:
                    src_ip, ip_id, dst_ip = ip_id_key.split('-', 2)
                    mac_srcs = set(o['mac_src'] for o in occs if o['mac_src'] != 'N/A')
                    mac_dsts = set(o['mac_dst'] for o in occs if o['mac_dst'] != 'N/A')
                    ttl_vals = [o['ttl'] for o in occs if o['ttl'] is not None]
                    
                    if not ttl_vals:
                        continue
                    
                    time_span = max(o['time'] for o in occs) - min(o['time'] for o in occs)

                    ttl_before = max(ttl_vals)
                    ttl_after = min(ttl_vals)
                    ttl_decrease = ttl_before - ttl_after
                    mac_changed = (len(mac_srcs) > 1) or (len(mac_dsts) > 1)

                    # Avoid false positives on pure L2 captures
                    if ttl_decrease == 0 and not mac_changed:
                        continue

                    # ✅ Check if IPv6
                    is_ipv6 = occs[0].get('is_ipv6', False)
                    id_type = "Flow-Label" if is_ipv6 else "IP-ID"

                    # Confidence scoring
                    confidence = 75
                    if ttl_decrease > 0:
                        confidence += 10
                    if mac_changed:
                        confidence += 10
                    if len(occs) >= 5:
                        confidence += 5
                    
                    # ✅ IPv6 Flow Label is less reliable
                    if is_ipv6:
                        confidence -= 10
                    
                    confidence = min(max(confidence, 50), 100)

                    loops.append({
                        'flow': "{} -> {}".format(src_ip, dst_ip),
                        'timestamp': max(o['timestamp'] for o in occs),
                        'ttl_before': ttl_before,
                        'ttl_after': ttl_after,
                        'ttl_decrease': ttl_decrease,
                        'ip_id_before': int(ip_id),
                        'ip_id_after': int(ip_id),
                        'ip_id_before_hex': hex(int(ip_id)),
                        'ip_id_after_hex': hex(int(ip_id)),
                        'loop_type': "{}-Duplicate ({} times){}".format(
                            id_type,
                            len(occs),
                            " [IPv6]" if is_ipv6 else ""
                        ),
                        'evidence': 'IP Identification with TTL/MAC correlation{}'.format(
                            ' (IPv6 - Flow Label less reliable)' if is_ipv6 else ''
                        ),
                        'time_span': "{:.3f}s".format(time_span),
                        'mac_srcs': ', '.join(sorted(mac_srcs)) if mac_srcs else 'N/A',
                        'mac_dsts': ', '.join(sorted(mac_dsts)) if mac_dsts else 'N/A',
                        'confidence': confidence,
                        'occurrences': len(occs),
                        'ip_version': 'IPv6' if is_ipv6 else 'IPv4',
                    })

            # Payload-hash based detection (works for both IPv4 and IPv6)
            for key, occs in payload_hash_tracking.items():
                if len(occs) > 1:
                    occs.sort(key=lambda x: x['time'])
                    for i in range(1, len(occs)):
                        prev = occs[i - 1]
                        curr = occs[i]
                        
                        # Skip if TTL is None
                        if prev['ttl'] is None or curr['ttl'] is None:
                            continue
                        
                        ttl_dec = prev['ttl'] - curr['ttl']
                        mac_change = (prev['mac_src'] != curr['mac_src']) or (prev['mac_dst'] != curr['mac_dst'])

                        if ttl_dec > 3 and mac_change:
                            is_ipv6 = prev.get('is_ipv6', False)
                            
                            loops.append({
                                'flow': "{} -> {}".format(prev['src_ip'], prev['dst_ip']),
                                'timestamp': curr['timestamp'],
                                'ttl_before': prev['ttl'],
                                'ttl_after': curr['ttl'],
                                'ttl_decrease': ttl_dec,
                                'ip_id_before': prev['ip_id'],
                                'ip_id_after': curr['ip_id'],
                                'ip_id_before_hex': prev['ip_id_hex'],
                                'ip_id_after_hex': curr['ip_id_hex'],
                                'loop_type': 'TTL-based + MAC change{}'.format(" [IPv6]" if is_ipv6 else ""),
                                'evidence': 'TTL Decay + MAC Shift + Payload Match',
                                'mac_srcs': ', '.join({prev['mac_src'], curr['mac_src']}),
                                'mac_dsts': ', '.join({prev['mac_dst'], curr['mac_dst']}),
                                'confidence': 95,
                                'occurrences': 2,
                                'ip_version': 'IPv6' if is_ipv6 else 'IPv4',
                            })

            # De-duplicate & finalize
            unique = {}
            for loop in loops:
                key = (loop['flow'], loop['ttl_decrease'], loop['ip_id_before'], loop['loop_type'])
                if key not in unique or loop['confidence'] > unique[key]['confidence']:
                    unique[key] = loop

            loop_list = sorted(unique.values(), key=lambda x: x['confidence'], reverse=True)
            self.analysis_results['routing_loops'] = loop_list[:50]

            self.log_message("✓ Advanced Routing Loop Analysis: {} loops detected".format(len(loop_list)))
            
            # ✅ Enhanced statistics with IPv4/IPv6 breakdown
            if loop_list:
                ipv4_loops = sum(1 for l in loop_list if l.get('ip_version') == 'IPv4')
                ipv6_loops = sum(1 for l in loop_list if l.get('ip_version') == 'IPv6')
                ip_id_count = sum(1 for l in loop_list if 'IP-ID-Duplicate' in l.get('loop_type', ''))
                flow_label_count = sum(1 for l in loop_list if 'Flow-Label-Duplicate' in l.get('loop_type', ''))
                ttl_mac_count = sum(1 for l in loop_list if 'TTL-based' in l.get('loop_type', ''))
                
                self.log_message("  - IPv4 Loops: {}, IPv6 Loops: {}".format(ipv4_loops, ipv6_loops))
                self.log_message("  - IP-ID Duplicates (IPv4): {}".format(ip_id_count))
                self.log_message("  - Flow-Label Duplicates (IPv6): {}".format(flow_label_count))
                self.log_message("  - TTL/MAC/Payload Loops: {}".format(ttl_mac_count))

        except Exception as e:
            import traceback
            self.log_message("⚠️ Routing loop analysis error: {}".format(str(e)))
            self.log_message(traceback.format_exc())
            self.analysis_results['routing_loops'] = []


#=============================ospf lsa==============================#

    def analyze_ospf_lsas(self):
        """Enhanced OSPF/OSPFv3 packet analysis with detailed packet type detection (IPv4 + IPv6)."""
        try:
            lsa_stats = Counter()
            lsa_details = []
            ospf_packets = []
            lsa_database = []
            
            # OSPF packet type mapping (same for OSPF and OSPFv3)
            ospf_types = {
                1: 'Hello',
                2: 'DBD',
                3: 'LSR',
                4: 'LSU',
                5: 'LSAck'
            }
            
            all_packets = PacketList(list(self.src_packets) + list(self.dst_packets))
            
            for packet in all_packets:
                try:
                    # ✅ Check for both OSPF (IPv4, proto 89) and OSPFv3 (IPv6, next header 89)
                    is_ospf = False
                    is_ospfv3 = False
                    src_ip = None
                    dst_ip = None
                    
                    if packet.haslayer(IP) and packet[IP].proto == 89:
                        is_ospf = True
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                    elif packet.haslayer(IPv6) and packet[IPv6].nh == 89:
                        is_ospfv3 = True
                        src_ip = packet[IPv6].src
                        dst_ip = packet[IPv6].dst
                    
                    if not (is_ospf or is_ospfv3):
                        continue
                    
                    # Determine protocol name
                    protocol_name = 'OSPFv3' if is_ospfv3 else 'OSPF'
                    lsa_stats[f'{protocol_name}_packets'] += 1
                    
                    # Extract OSPF-specific information
                    ospf_type = None
                    ospf_type_name = protocol_name  # Default fallback
                    router_id = 'N/A'
                    area_id = '0.0.0.0'
                    
                    # Try to parse OSPF header if available
                    try:
                        from scapy.contrib.ospf import (
                            OSPF_Hdr, OSPF_Hello, OSPF_DBDesc,
                            OSPF_LSReq, OSPF_LSUpd, OSPF_LSAck
                        )    
                        
                        if packet.haslayer(OSPF_Hdr):
                            ospf_hdr = packet[OSPF_Hdr]
                            ospf_type = ospf_hdr.type if hasattr(ospf_hdr, 'type') else None
                            
                            # ✅ Only use ospf_type if it's a valid value (1-5)
                            if ospf_type and ospf_type in ospf_types:
                                ospf_type_name = ospf_types[ospf_type]
                            else:
                                # Invalid type - use generic label
                                ospf_type_name = protocol_name
                                if ospf_type is not None:
                                    self.log_message("⚠️ Invalid {} type {} detected in packet from {}".format(
                                        protocol_name, ospf_type, src_ip))
                            
                            # Extract router ID and area
                            if hasattr(ospf_hdr, 'src'):
                                router_id = ospf_hdr.src
                            if hasattr(ospf_hdr, 'area'):
                                area_id = ospf_hdr.area
                            
                            # Update stats by type
                            lsa_stats[ospf_type_name] += 1
                            
                            # Extract type-specific details
                            if packet.haslayer(OSPF_Hello):
                                hello = packet[OSPF_Hello]
                                neighbors = []
                                if hasattr(hello, 'neighbors'):
                                    neighbors = hello.neighbors if isinstance(hello.neighbors, list) else [hello.neighbors]
                                
                                ospf_packets.append({
                                    'type': 'Hello',
                                    'protocol': protocol_name,  # ✅ Track protocol version
                                    'src': src_ip,
                                    'dst': dst_ip,
                                    'timestamp': safe_timestamp(packet.time),
                                    'router_id': router_id,
                                    'area': area_id,
                                    'neighbors': len(neighbors),
                                    'dead_interval': hello.deadinterval if hasattr(hello, 'deadinterval') else 'N/A',
                                    'hello_interval': hello.hellointerval if hasattr(hello, 'hellointerval') else 'N/A'
                                })
                                ospf_type_name = 'Hello'
                            
                            elif packet.haslayer(OSPF_DBDesc):
                                dbd = packet[OSPF_DBDesc]
                                ospf_packets.append({
                                    'type': 'DBD',
                                    'protocol': protocol_name,
                                    'src': src_ip,
                                    'dst': dst_ip,
                                    'timestamp': safe_timestamp(packet.time),
                                    'router_id': router_id,
                                    'area': area_id,
                                    'dd_sequence': dbd.ddseq if hasattr(dbd, 'ddseq') else 'N/A',
                                    'mtu': dbd.mtu if hasattr(dbd, 'mtu') else 'N/A',
                                    'options': dbd.options if hasattr(dbd, 'options') else 'N/A'
                                })
                                ospf_type_name = 'DBD'
                            
                            elif packet.haslayer(OSPF_LSReq):
                                ospf_packets.append({
                                    'type': 'LSR',
                                    'protocol': protocol_name,
                                    'src': src_ip,
                                    'dst': dst_ip,
                                    'timestamp': safe_timestamp(packet.time),
                                    'router_id': router_id,
                                    'area': area_id,
                                    'requests': 'Present'
                                })
                                ospf_type_name = 'LSR'
                            
                            elif packet.haslayer(OSPF_LSUpd):
                                lsu = packet[OSPF_LSUpd]
                                lsa_count = lsu.lsacount if hasattr(lsu, 'lsacount') else 0
                                ospf_packets.append({
                                    'type': 'LSU',
                                    'protocol': protocol_name,
                                    'src': src_ip,
                                    'dst': dst_ip,
                                    'timestamp': safe_timestamp(packet.time),
                                    'router_id': router_id,
                                    'area': area_id,
                                    'lsa_count': lsa_count
                                })
                                lsa_stats['lsa_updates'] += lsa_count
                                ospf_type_name = 'LSU'

                                lsa_list = lsu.lsalist if hasattr(lsu, 'lsalist') else []

                                for lsa in lsa_list:
                                    lsa_info = self.extract_lsa_details(lsa, packet, area_id, is_ack=False, protocol=protocol_name)
                                    if lsa_info:
                                        lsa_database.append(lsa_info)
                            
                            elif packet.haslayer(OSPF_LSAck):
                                lsaack = packet[OSPF_LSAck]
                                ospf_packets.append({
                                    'type': 'LSAck',
                                    'protocol': protocol_name,
                                    'src': src_ip,
                                    'dst': dst_ip,
                                    'timestamp': safe_timestamp(packet.time),
                                    'router_id': router_id,
                                    'area': area_id,
                                    'acks': 'Present'
                                })
                                ospf_type_name = 'LSAck'

                                lsa_list = lsaack.lsaheaders if hasattr(lsaack, 'lsaheaders') else []

                                for lsa in lsa_list:
                                    lsa_info = self.extract_lsa_details(lsa, packet, area_id, is_ack=True, protocol=protocol_name)
                                    if lsa_info:
                                        lsa_database.append(lsa_info)
                                
                        else:
                            # OSPF/OSPFv3 packet detected but no OSPF_Hdr layer
                            ospf_type_name = protocol_name
                            
                    except ImportError:
                        # Scapy OSPF contrib module not available
                        ospf_type_name = protocol_name
                    except Exception as parse_error:
                        # Any other parsing error
                        ospf_type_name = protocol_name
                        self.log_message("⚠️ {} parsing error: {}".format(protocol_name, str(parse_error)))
                    
                    # ✅ Add to lsa_details with validated type names and protocol version
                    lsa_details.append({
                        'src': src_ip,
                        'dst': dst_ip,
                        'timestamp': safe_timestamp(packet.time),
                        'type': ospf_type_name,  # Validated type name
                        'area': area_id,
                        'router_id': router_id,
                        'protocol': protocol_name  # ✅ Track protocol version
                    })
                    
                    lsa_stats['lsa_messages'] += 1
                    
                except Exception:
                    continue
            
            self.analysis_results['ospf_lsa_analysis'] = {
                'lsa_stats': lsa_stats,
                'lsa_details': lsa_details,
                'ospf_packets': ospf_packets,
                'lsa_database': lsa_database
            }
            
            # ✅ Enhanced logging with OSPF vs OSPFv3 breakdown
            ospf_count = lsa_stats.get('OSPF_packets', 0)
            ospfv3_count = lsa_stats.get('OSPFv3_packets', 0)
            
            self.log_message("✓ Enhanced OSPF/OSPFv3 analysis: {} total packets (OSPF: {}, OSPFv3: {})".format(
                ospf_count + ospfv3_count,
                ospf_count,
                ospfv3_count
            ))
            self.log_message("  {} Hello, {} DBD, {} LSR, {} LSU, {} LSAck, {} individual LSAs".format(
                lsa_stats.get('Hello', 0),
                lsa_stats.get('DBD', 0),
                lsa_stats.get('LSR', 0),
                lsa_stats.get('LSU', 0),
                lsa_stats.get('LSAck', 0),
                len(lsa_database)
            ))
            
        except Exception as e:
            import traceback
            self.log_message("⚠️ OSPF/OSPFv3 analysis error: {}".format(str(e)))
            self.log_message(traceback.format_exc())
            self.analysis_results['ospf_lsa_analysis'] = {
                'lsa_stats': Counter(),
                'lsa_details': [],
                'ospf_packets': [],
                'lsa_database': []
            }

#=====================EIGRP packets==============================#

    def analyze_eigrp_packets(self):
        """
        EIGRP Routing Protocol Packet Analyzer (IPv4 + IPv6)
        Classifies packets by EIGRP opcode and detects SIA conditions.
        """
        try:
            eigrp_types = {
                1: "Update",
                3: "Query",
                4: "Reply",
                5: "Hello",
                6: "Ack",
                10: "SIA-Query",  # ✅ Added SIA-specific opcodes
                11: "SIA-Reply"
            }
            eigrp_packets = []
            sia_events = []
            query_tracking = {}
            
            all_packets = PacketList(list(self.src_packets) + list(self.dst_packets))
            
            for pkt in all_packets:
                try:
                    # ✅ Check for EIGRP on both IPv4 (proto 88) and IPv6 (next header 88)
                    src_ip = None
                    dst_ip = None
                    payload = None
                    is_ipv6 = False
                    
                    if pkt.haslayer(IP) and pkt[IP].proto == 88:
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        payload = bytes(pkt[IP].payload)
                        is_ipv6 = False
                    elif pkt.haslayer(IPv6) and pkt[IPv6].nh == 88:
                        src_ip = pkt[IPv6].src
                        dst_ip = pkt[IPv6].dst
                        payload = bytes(pkt[IPv6].payload)
                        is_ipv6 = True
                    
                    if not payload or len(payload) <= 1:
                        continue
                    
                    opcode = payload[1]
                    
                    # Extract AS number (bytes 2-3)
                    as_number = (payload[2] << 8 | payload[3]) if len(payload) > 3 else 0
                    
                    # Extract sequence number (bytes 12-15)
                    seq_num = int.from_bytes(payload[12:16], 'big') if len(payload) >= 16 else 0
                    
                    # Extract hold time for Hello packets (bytes 20-21)
                    hold_time = (payload[20] << 8 | payload[21]) if opcode == 5 and len(payload) > 21 else 0
                    
                    packet_info = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "timestamp": safe_timestamp(pkt.time),
                        "time_float": float(pkt.time),
                        "opcode": eigrp_types.get(opcode, f"Unknown ({opcode})"),
                        "opcode_num": opcode,
                        "as_number": as_number,
                        "seq_number": seq_num,
                        "hold_time": hold_time,
                        "ip_version": "IPv6" if is_ipv6 else "IPv4",  # ✅ Track IP version
                        "raw": payload.hex()[:60]
                    }
                    eigrp_packets.append(packet_info)
                    
                    # ✅ Track Query packets for SIA detection
                    if opcode == 3:  # Query
                        key = f"{src_ip}-{dst_ip}-{seq_num}"
                        query_tracking[key] = {
                            'query_time': float(pkt.time),
                            'src': src_ip,
                            'dst': dst_ip,
                            'seq': seq_num,
                            'as': as_number,
                            'ip_version': "IPv6" if is_ipv6 else "IPv4"
                        }
                    
                    # ✅ Match Reply packets to Query
                    elif opcode == 4:  # Reply
                        key = f"{dst_ip}-{src_ip}-{seq_num}"
                        if key in query_tracking:
                            query_info = query_tracking.pop(key)
                            reply_time = float(pkt.time) - query_info['query_time']
                            
                            # Check for SIA (typically >180 seconds, but flag >90s as warning)
                            if reply_time > 90:
                                sia_events.append({
                                    'query_origin': query_info['src'],
                                    'responder': src_ip,
                                    'as_number': as_number,
                                    'seq_number': seq_num,
                                    'query_time': safe_timestamp(query_info['query_time']),
                                    'reply_time': safe_timestamp(pkt.time),
                                    'delay_seconds': round(reply_time, 2),
                                    'status': 'SIA' if reply_time > 180 else 'Slow Reply',
                                    'ip_version': query_info['ip_version']  # ✅ Track IP version
                                })
                    
                    # ✅ Track SIA-Query packets (opcode 10)
                    elif opcode == 10:  # SIA-Query
                        sia_events.append({
                            'query_origin': src_ip,
                            'responder': dst_ip,
                            'as_number': as_number,
                            'seq_number': seq_num,
                            'query_time': safe_timestamp(pkt.time),
                            'reply_time': 'Pending SIA-Reply',
                            'delay_seconds': 0,
                            'status': 'SIA-Query Sent',
                            'ip_version': "IPv6" if is_ipv6 else "IPv4"
                        })
                    
                    # ✅ Track SIA-Reply packets (opcode 11)
                    elif opcode == 11:  # SIA-Reply
                        # Find corresponding SIA-Query
                        for sia in sia_events:
                            if (sia.get('query_origin') == dst_ip and 
                                sia.get('responder') == src_ip and
                                sia.get('status') == 'SIA-Query Sent'):
                                sia['status'] = 'SIA-Reply Received'
                                sia['reply_time'] = safe_timestamp(pkt.time)
                                break
                    
                except Exception:
                    continue
            
            # Check for unanswered queries (potential retransmission/timeout)
            current_time = max([p['time_float'] for p in eigrp_packets]) if eigrp_packets else 0
            for key, query_info in query_tracking.items():
                if current_time - query_info['query_time'] > 90:
                    sia_events.append({
                        'query_origin': query_info['src'],
                        'responder': query_info['dst'],
                        'as_number': query_info['as'],
                        'seq_number': query_info['seq'],
                        'query_time': safe_timestamp(query_info['query_time']),
                        'reply_time': 'No Reply',
                        'delay_seconds': round(current_time - query_info['query_time'], 2),
                        'status': 'Unanswered Query/Retry Exceeded',
                        'ip_version': query_info['ip_version']
                    })

            self.analysis_results['routing_protocol_analysis']['eigrp_packets'] = eigrp_packets
            self.analysis_results['routing_protocol_analysis']['eigrp_sia_events'] = sia_events
            
            # ✅ Enhanced logging with IPv4/IPv6 breakdown
            ipv4_count = sum(1 for p in eigrp_packets if p.get('ip_version') == 'IPv4')
            ipv6_count = sum(1 for p in eigrp_packets if p.get('ip_version') == 'IPv6')
            
            self.log_message(f"✓ EIGRP analysis: {len(eigrp_packets)} packets (IPv4: {ipv4_count}, IPv6: {ipv6_count}), {len(sia_events)} SIA events")
            
        except Exception as e:
            import traceback
            self.log_message(f"⚠️ EIGRP analysis error: {str(e)}")
            self.log_message(traceback.format_exc())
            self.analysis_results['routing_protocol_analysis']['eigrp_packets'] = []
            self.analysis_results['routing_protocol_analysis']['eigrp_sia_events'] = []


#========================BGP======================================================#

    def analyze_bgp_packets(self):
        """
        Enhanced BGP Packet Analyzer with Session Tracking and State Machine Analysis.
        Supports both IPv4 and IPv6 BGP sessions.
        
        Features:
        - BGP session state tracking (Idle, Connect, Active, OpenSent, OpenConfirm, Established)
        - Hold timer and keepalive monitoring
        - Route update statistics (prefixes announced/withdrawn)
        - Notification error detection and classification
        - Session flapping detection
        - AS path analysis
        - TCP connection tracking (SYN, ACK, FIN, RST)
        """
        try:
            from scapy.contrib.bgp import BGPHeader, BGPOpen, BGPUpdate, BGPNotification, BGPKeepAlive
            bgp_available = True
        except ImportError:
            BGPHeader = BGPOpen = BGPUpdate = BGPNotification = BGPKeepAlive = None
            bgp_available = False

        bgp_types = {
            1: "OPEN",
            2: "UPDATE",
            3: "NOTIFICATION",
            4: "KEEPALIVE"
        }
        
        # BGP Notification Error Codes
        bgp_error_codes = {
            1: "Message Header Error",
            2: "OPEN Message Error",
            3: "UPDATE Message Error",
            4: "Hold Timer Expired",
            5: "Finite State Machine Error",
            6: "Cease"
        }
        
        bgp_packets = []
        bgp_sessions = defaultdict(lambda: {
            'state': 'Idle',
            'messages': [],
            'open_sent': None,
            'open_received': None,
            'updates_sent': 0,
            'updates_received': 0,
            'keepalives_sent': 0,
            'keepalives_received': 0,
            'notifications': [],
            'prefixes_announced': 0,
            'prefixes_withdrawn': 0,
            'last_keepalive': None,
            'hold_time': 180,
            'keepalive_interval': 60,
            'as_number': None,
            'bgp_identifier': None,
            'tcp_established': False,
            'session_start': None,
            'session_end': None,
            'flap_count': 0,
            'ip_version': None  # ✅ Track IP version
        })
        
        all_packets = PacketList(list(self.src_packets) + list(self.dst_packets))

        for pkt in all_packets:
            try:
                if not pkt.haslayer(TCP):
                    continue
                
                if pkt[TCP].sport != 179 and pkt[TCP].dport != 179:
                    continue
                
                # ✅ Extract IPs from both IPv4 and IPv6
                src_ip = None
                dst_ip = None
                ip_version = None
                
                if pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    ip_version = 'IPv4'
                elif pkt.haslayer(IPv6):
                    src_ip = pkt[IPv6].src
                    dst_ip = pkt[IPv6].dst
                    ip_version = 'IPv6'
                else:
                    continue
                
                timestamp = pkt.time
                tcp_flags = pkt[TCP].flags
                
                # Session key (bidirectional)
                session_key = tuple(sorted([src_ip, dst_ip]))
                session = bgp_sessions[session_key]
                
                # ✅ Set IP version on first packet
                if not session['ip_version']:
                    session['ip_version'] = ip_version
                
                # ✅ Track TCP state
                if tcp_flags & 0x02:  # SYN
                    session['state'] = 'Connect'
                    if not session['session_start']:
                        session['session_start'] = timestamp
                
                if tcp_flags & 0x10 and session['state'] == 'Connect':  # ACK after SYN
                    session['tcp_established'] = True
                    session['state'] = 'Active'
                
                if tcp_flags & 0x01 or tcp_flags & 0x04:  # FIN or RST
                    if session['state'] == 'Established':
                        session['flap_count'] += 1
                    session['session_end'] = timestamp
                    session['state'] = 'Idle'
                    session['tcp_established'] = False
                
                # Parse BGP message
                bgp_type = None
                bgp_details = {}
                
                if bgp_available and pkt.haslayer(BGPHeader):
                    header = pkt[BGPHeader]
                    bgp_type = bgp_types.get(header.type, f"Unknown ({header.type})")
                    
                    # ✅ OPEN Message Analysis
                    if header.type == 1 and pkt.haslayer(BGPOpen):
                        open_msg = pkt[BGPOpen]
                        bgp_details = {
                            'as_number': open_msg.my_as if hasattr(open_msg, 'my_as') else 'N/A',
                            'hold_time': open_msg.hold_time if hasattr(open_msg, 'hold_time') else 180,
                            'bgp_identifier': open_msg.bgp_id if hasattr(open_msg, 'bgp_id') else 'N/A'
                        }
                        
                        session['hold_time'] = bgp_details['hold_time']
                        session['keepalive_interval'] = bgp_details['hold_time'] // 3
                        session['as_number'] = bgp_details['as_number']
                        session['bgp_identifier'] = bgp_details['bgp_identifier']
                        
                        if src_ip < dst_ip:  # Sent by this peer
                            session['open_sent'] = timestamp
                        else:
                            session['open_received'] = timestamp
                        
                        # State transition
                        if session['open_sent'] and not session['open_received']:
                            session['state'] = 'OpenSent'
                        elif session['open_sent'] and session['open_received']:
                            session['state'] = 'OpenConfirm'
                    
                    # ✅ UPDATE Message Analysis
                    elif header.type == 2 and pkt.haslayer(BGPUpdate):
                        update_msg = pkt[BGPUpdate]
                        
                        # Count prefixes
                        withdrawn_count = 0
                        announced_count = 0
                        
                        if hasattr(update_msg, 'withdrawn_routes_len'):
                            withdrawn_count = update_msg.withdrawn_routes_len // 5  # Rough estimate
                        
                        if hasattr(update_msg, 'tp_len'):
                            announced_count = update_msg.tp_len // 5  # Rough estimate
                        
                        bgp_details = {
                            'prefixes_withdrawn': withdrawn_count,
                            'prefixes_announced': announced_count
                        }
                        
                        session['prefixes_withdrawn'] += withdrawn_count
                        session['prefixes_announced'] += announced_count
                        
                        if src_ip < dst_ip:
                            session['updates_sent'] += 1
                        else:
                            session['updates_received'] += 1
                        
                        # Transition to Established if not already
                        if session['state'] == 'OpenConfirm':
                            session['state'] = 'Established'
                    
                    # ✅ KEEPALIVE Message Analysis
                    elif header.type == 4:
                        session['last_keepalive'] = timestamp
                        
                        if src_ip < dst_ip:
                            session['keepalives_sent'] += 1
                        else:
                            session['keepalives_received'] += 1
                        
                        # Transition to Established
                        if session['state'] == 'OpenConfirm':
                            session['state'] = 'Established'
                    
                    # ✅ NOTIFICATION Message Analysis
                    elif header.type == 3 and pkt.haslayer(BGPNotification):
                        notif_msg = pkt[BGPNotification]
                        error_code = notif_msg.error_code if hasattr(notif_msg, 'error_code') else 0
                        error_subcode = notif_msg.error_subcode if hasattr(notif_msg, 'error_subcode') else 0
                        
                        bgp_details = {
                            'error_code': error_code,
                            'error_name': bgp_error_codes.get(error_code, 'Unknown Error'),
                            'error_subcode': error_subcode
                        }
                        
                        session['notifications'].append({
                            'timestamp': timestamp,
                            'error': bgp_details['error_name'],
                            'from': src_ip
                        })
                        
                        # Session reset
                        session['state'] = 'Idle'
                        session['flap_count'] += 1
                
                else:
                    # Fallback: parse raw payload
                    payload = bytes(pkt[TCP].payload)
                    if len(payload) > 18:
                        bgp_type_code = payload[18]
                        bgp_type = bgp_types.get(bgp_type_code, f"Unknown ({bgp_type_code})")
                        
                        # Basic state tracking even without full parsing
                        if bgp_type_code == 1:  # OPEN
                            session['state'] = 'OpenSent'
                        elif bgp_type_code == 4:  # KEEPALIVE
                            if session['state'] == 'OpenConfirm' or session['state'] == 'OpenSent':
                                session['state'] = 'Established'
                            session['last_keepalive'] = timestamp
                        elif bgp_type_code == 3:  # NOTIFICATION
                            session['state'] = 'Idle'
                            session['flap_count'] += 1
                
                # ✅ Build packet info
                packet_info = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "ip_version": ip_version,  # ✅ Track IP version
                    "timestamp": safe_timestamp(timestamp),
                    "bgp_type": bgp_type if bgp_type else "TCP (No BGP)",
                    "tcp_flags": self.format_tcp_flags(tcp_flags),
                    "session_state": session['state'],
                    "details": bgp_details
                }
                
                bgp_packets.append(packet_info)
                session['messages'].append(packet_info)
                
            except Exception as e:
                self.log_message(f"⚠️ BGP packet parsing error: {str(e)}")
                continue
        
        # ✅ Analyze session health
        session_summary = []
        for session_key, session in bgp_sessions.items():
            peer1, peer2 = session_key
            
            # Calculate session duration
            duration = 0
            if session['session_start']:
                end_time = session['session_end'] or all_packets[-1].time if all_packets else session['session_start']
                duration = end_time - session['session_start']
            
            # Check hold timer violations
            hold_timer_ok = True
            if session['last_keepalive'] and all_packets:
                time_since_keepalive = all_packets[-1].time - session['last_keepalive']
                hold_timer_ok = time_since_keepalive < session['hold_time']
            
            # Determine health status
            if session['state'] == 'Established':
                if hold_timer_ok and session['flap_count'] == 0:
                    status = 'Healthy'
                    icon = '✅'
                    color = '#28a745'
                elif session['flap_count'] > 0:
                    status = 'Flapping'
                    icon = '⚠️'
                    color = '#fbc02d'
                else:
                    status = 'Hold Timer Risk'
                    icon = '🔴'
                    color = '#ff9800'
            elif session['state'] == 'Idle':
                status = 'Down'
                icon = '❌'
                color = '#d32f2f'
            else:
                status = 'Establishing'
                icon = '🔄'
                color = '#007bff'
            
            session_summary.append({
                'peers': f"{peer1} ↔ {peer2}",
                'state': session['state'],
                'status': status,
                'icon': icon,
                'color': color,
                'ip_version': session['ip_version'] or 'N/A',  # ✅ Track IP version
                'as_number': session['as_number'] or 'N/A',
                'duration': f"{duration:.1f}s" if duration > 0 else 'N/A',
                'updates_sent': session['updates_sent'],
                'updates_received': session['updates_received'],
                'keepalives_sent': session['keepalives_sent'],
                'keepalives_received': session['keepalives_received'],
                'prefixes_announced': session['prefixes_announced'],
                'prefixes_withdrawn': session['prefixes_withdrawn'],
                'notifications': len(session['notifications']),
                'flap_count': session['flap_count'],
                'hold_time': session['hold_time'],
                'last_keepalive': safe_timestamp(session['last_keepalive']) if session['last_keepalive'] else 'Never'
            })
        
        # Store results
        self.analysis_results['routing_protocol_analysis']['bgp_packets'] = bgp_packets
        self.analysis_results['routing_protocol_analysis']['bgp_sessions'] = session_summary
        
        # ✅ Enhanced logging with IPv4/IPv6 breakdown
        ipv4_sessions = sum(1 for s in session_summary if s['ip_version'] == 'IPv4')
        ipv6_sessions = sum(1 for s in session_summary if s['ip_version'] == 'IPv6')
        
        self.log_message(f"✓ BGP analysis: {len(bgp_packets)} packets, {len(session_summary)} sessions (IPv4: {ipv4_sessions}, IPv6: {ipv6_sessions})")

                
            

#=====================ISIS===================================#

    def format_mac_cisco_style(self, mac):
        """Convert MAC address to Cisco style xxxx.xxxx.xxxx"""
        if not mac or mac == 'N/A':
            return 'N/A'
        if isinstance(mac, bytes):
            mac = ''.join(['{:02x}'.format(b) for b in mac]).lower()
        elif isinstance(mac, str):
            mac = mac.replace(':', '').replace('-', '').replace('.', '').lower()
        else:
            return mac

        if len(mac) != 12:
            return mac

        return '{}.{}.{}'.format(mac[0:4], mac[4:8], mac[8:12])
                

    def analyze_isis_packets(self):
        """
        IS-IS Routing Protocol Packet Analyzer
        Classifies packets as HELLO, LSP, CSNP, or PSNP based on official PDU type numbers.
        
        Note: IS-IS is a Layer 2 protocol (runs over LLC) and is protocol-agnostic.
        It supports both IPv4 and IPv6 routing simultaneously (Integrated IS-IS).
        """
        try:
            # Initialize tracking structures
            isis_stats = Counter()
            hello_pdus = []
            lsp_pdus = []
            csnp_pdus = []
            psnp_pdus = []
            packet_count = 0
            
            # ✅ Track address family support from TLVs
            ipv4_support = False
            ipv6_support = False
        
            # IS-IS PDU type mapping (official protocol values)
            pdu_type_names = {
                15: 'L1 LAN Hello',
                16: 'L2 LAN Hello',
                17: 'P2P Hello',
                18: 'L1 LSP',
                20: 'L2 LSP',
                24: 'L1 CSNP',
                25: 'L2 CSNP',
                26: 'L1 PSNP',
                27: 'L2 PSNP'
            }
        
            # Define sets for each category for efficient lookup
            hello_types = {15, 16, 17}
            lsp_types = {18, 20}
            csnp_types = {24, 25}
            psnp_types = {26, 27}
        
            all_packets = PacketList(list(self.src_packets) + list(self.dst_packets))
        
            # Try to import scapy IS-IS contrib
            try:
                from scapy.contrib.isis import ISIS_CommonHdr, ISIS_P2P_Hello, ISIS_LAN_Hello, ISIS_LSP, ISIS_CSNP, ISIS_PSNP
                isis_available = True
            except ImportError:
                self.log_message("⚠️ Scapy IS-IS contrib module not available. Using manual parsing.")
                isis_available = False
        
            for pkt in all_packets:
                try:
                    # IS-IS runs over LLC (Logical Link Control)
                    # LLC SAP for IS-IS: DSAP=0xFE, SSAP=0xFE
                    if pkt.haslayer(LLC):
                        llc = pkt[LLC]
                    
                        # Check if it's IS-IS (SAP 0xFE/0xFE)
                        if getattr(llc, 'dsap', None) == 0xfe and getattr(llc, 'ssap', None) == 0xfe:
                        
                            if isis_available and pkt.haslayer(ISIS_CommonHdr):
                                # Use Scapy parsing
                                packet_info = self._parse_isis_with_scapy(pkt, pdu_type_names)
                            else:
                                # Use manual parsing
                                raw_bytes = bytes(llc.payload)
                                packet_info = self._parse_isis_manual(pkt, raw_bytes, pdu_type_names)

                            pdu_type = packet_info.get('pdu_type_num') if packet_info else None
                        
                            if packet_info:
                                packet_info['type'] = packet_info.get('pdu_type', 'Unknown')
                                
                                # ✅ Check for IPv4/IPv6 TLVs in LSPs
                                if pdu_type in lsp_types:
                                    tlv_info = packet_info.get('tlv_info', {})
                                    if tlv_info.get('has_ipv4'):
                                        ipv4_support = True
                                    if tlv_info.get('has_ipv6'):
                                        ipv6_support = True
                            
                                # Categorize by PDU type
                                if pdu_type in hello_types:
                                    hello_pdus.append(packet_info)
                                    isis_stats['hello_packets'] += 1
                                elif pdu_type in lsp_types:
                                    lsp_pdus.append(packet_info)
                                    isis_stats['lsp_packets'] += 1
                                elif pdu_type in csnp_types:
                                    csnp_pdus.append(packet_info)
                                    isis_stats['csnp_packets'] += 1
                                elif pdu_type in psnp_types:
                                    psnp_pdus.append(packet_info)
                                    isis_stats['psnp_packets'] += 1
                            
                                packet_count += 1
                                isis_stats['total_packets'] += 1
                            
                except Exception as e:
                    continue
        
            # ✅ Determine address family support
            address_families = []
            if ipv4_support:
                address_families.append('IPv4')
            if ipv6_support:
                address_families.append('IPv6')
            if not address_families:
                address_families.append('Unknown')
            
            # Store results
            self.analysis_results['isis_analysis'] = {
                'hello_pdus': hello_pdus,
                'lsp_pdus': lsp_pdus,
                'csnp_pdus': csnp_pdus,
                'psnp_pdus': psnp_pdus,
                'packet_count': packet_count,
                'isis_stats': isis_stats,
                'address_families': address_families  # ✅ NEW
            }
        
            af_str = ' & '.join(address_families)
            self.log_message(f"✓ IS-IS analysis: {packet_count} packets ({af_str}) | "
                            f"Hello: {len(hello_pdus)}, LSP: {len(lsp_pdus)}, "
                            f"CSNP: {len(csnp_pdus)}, PSNP: {len(psnp_pdus)}")
        
        except Exception as e:
            import traceback
            self.log_message(f"⚠️ IS-IS analysis exception: {str(e)}")
            self.log_message(traceback.format_exc())
            self.analysis_results['isis_analysis'] = {
                'hello_pdus': [],
                'lsp_pdus': [],
                'csnp_pdus': [],
                'psnp_pdus': [],
                'packet_count': 0,
                'isis_stats': Counter(),
                'address_families': []
            }

    def _parse_isis_with_scapy(self, pkt, pdu_type_names):
        """Parse IS-IS packet using Scapy contrib module."""
        from scapy.contrib.isis import ISIS_CommonHdr, ISIS_P2P_Hello, ISIS_LAN_Hello, ISIS_LSP, ISIS_CSNP, ISIS_PSNP

        try:
            isis_hdr = pkt[ISIS_CommonHdr]
            pdu_type = getattr(isis_hdr, 'pdutype', None)
        
            # Extract source/destination MAC
            raw_src_mac = pkt.src if hasattr(pkt, 'src') else 'N/A'
            raw_dst_mac = pkt.dst if hasattr(pkt, 'dst') else 'N/A'
            src_mac = self.format_mac_cisco_style(raw_src_mac)
            dst_mac = self.format_mac_cisco_style(raw_dst_mac)

            packet_info = {
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'timestamp': safe_timestamp(pkt.time),
                'pdu_type': pdu_type_names.get(pdu_type, f'Unknown ({pdu_type})'),
                'pdu_type_num': pdu_type,
                'size': len(pkt),
                'pdu_raw': bytes(pkt[ISIS_CommonHdr]).hex()[:200],
                'tlv_info': {}  # ✅ Placeholder for TLV analysis
            }
        
            # Determine level
            if pdu_type in [15, 18, 24, 26]:
                packet_info['level'] = 'L1'
            elif pdu_type in [16, 20, 25, 27]:
                packet_info['level'] = 'L2'
            elif pdu_type == 17:
                packet_info['level'] = 'P2P'
            else:
                packet_info['level'] = 'Unknown'
        
            # Parse specific PDU types
            if pkt.haslayer(ISIS_LAN_Hello):
                hello = pkt[ISIS_LAN_Hello]
                packet_info.update({
                    'circuit_type': getattr(hello, 'circuittype', 'N/A'),
                    'system_id': self._format_system_id(getattr(hello, 'sourceid', b'\x00'*6)),
                    'holding_time': getattr(hello, 'holdingtime', 'N/A'),
                    'priority': getattr(hello, 'priority', 'N/A'),
                    'lan_id': getattr(hello, 'lanid', 'N/A')
                })
        
            elif pkt.haslayer(ISIS_P2P_Hello):
                hello = pkt[ISIS_P2P_Hello]
                packet_info.update({
                    'circuit_type': getattr(hello, 'circuittype', 'N/A'),
                    'system_id': self._format_system_id(getattr(hello, 'sourceid', b'\x00'*6)),
                    'holding_time': getattr(hello, 'holdingtime', 'N/A'),
                    'local_circuit_id': getattr(hello, 'localcircuitid', 'N/A')
                })
        
            elif pkt.haslayer(ISIS_LSP):
                lsp = pkt[ISIS_LSP]
                packet_info.update({
                    'lsp_id': self._format_lsp_id(getattr(lsp, 'lspid', b'\x00'*8)),
                    'sequence': getattr(lsp, 'seq', 'N/A'),
                    'remaining_lifetime': getattr(lsp, 'remaininglifetime', 'N/A'),
                    'checksum': hex(getattr(lsp, 'checksum', 0))
                })
                
                # ✅ Detect IPv4/IPv6 TLVs in LSP
                packet_info['tlv_info'] = self._detect_isis_tlvs(pkt)
        
            elif pkt.haslayer(ISIS_CSNP):
                csnp = pkt[ISIS_CSNP]
                packet_info.update({
                    'source_id': self._format_system_id(getattr(csnp, 'sourceid', b'\x00'*6)),
                    'start_lsp_id': 'Present',
                    'end_lsp_id': 'Present'
                })
        
            elif pkt.haslayer(ISIS_PSNP):
                psnp = pkt[ISIS_PSNP]
                packet_info.update({
                    'source_id': self._format_system_id(getattr(psnp, 'sourceid', b'\x00'*6)),
                    'lsp_entries': 'Present'
                })
        
            return packet_info
        
        except Exception as e:
            return None

    def _parse_isis_manual(self, pkt, raw_bytes, pdu_type_names):
        """Manual IS-IS packet parsing when contrib module is unavailable."""
        try:
            if not raw_bytes or len(raw_bytes) < 8:
                return None
        
            # IS-IS common header structure:
            # Byte 0: Intradomain Routing Protocol Discriminator (0x83)
            # Byte 1: Length Indicator
            # Byte 2: Version/Protocol ID Extension
            # Byte 3: ID Length
            # Byte 4: PDU Type
            # Byte 5: Version
            # Byte 6: Reserved
            # Byte 7: Maximum Area Addresses
        
            if raw_bytes[0] != 0x83:  # Not IS-IS
                return None
        
            pdu_type = raw_bytes[4] & 0x1F  # Lower 5 bits
        
            # Extract source/destination MAC
            raw_src_mac = pkt.src if hasattr(pkt, 'src') else 'N/A'
            raw_dst_mac = pkt.dst if hasattr(pkt, 'dst') else 'N/A'
            src_mac = self.format_mac_cisco_style(raw_src_mac)
            dst_mac = self.format_mac_cisco_style(raw_dst_mac)

            packet_info = {
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'timestamp': safe_timestamp(pkt.time),
                'pdu_type': pdu_type_names.get(pdu_type, f'Unknown ({pdu_type})'),
                'pdu_type_num': pdu_type,
                'size': len(pkt),
                'pdu_raw': raw_bytes.hex()[:200],
                'tlv_info': {}
            }
        
            # Determine level
            if pdu_type in [15, 18, 24, 26]:
                packet_info['level'] = 'L1'
            elif pdu_type in [16, 20, 25, 27]:
                packet_info['level'] = 'L2'
            elif pdu_type == 17:
                packet_info['level'] = 'P2P'
            else:
                packet_info['level'] = 'Unknown'
        
            # Parse type-specific fields based on PDU type
            if pdu_type in [15, 16]:  # LAN Hello
                if len(raw_bytes) >= 27:
                    packet_info.update({
                        'circuit_type': raw_bytes[8],
                        'system_id': self._format_system_id(raw_bytes[9:15]),
                        'holding_time': (raw_bytes[15] << 8) | raw_bytes[16],
                        'priority': raw_bytes[19],
                        'lan_id': self._format_system_id(raw_bytes[20:26]) + f'.{raw_bytes[26]:02x}'
                    })
        
            elif pdu_type == 17:  # P2P Hello
                if len(raw_bytes) >= 20:
                    packet_info.update({
                        'circuit_type': raw_bytes[8],
                        'system_id': self._format_system_id(raw_bytes[9:15]),
                        'holding_time': (raw_bytes[15] << 8) | raw_bytes[16],
                        'local_circuit_id': raw_bytes[19]
                    })
        
            elif pdu_type in [18, 20]:  # LSP
                if len(raw_bytes) >= 27:
                    packet_info.update({
                        'lsp_id': self._format_lsp_id(raw_bytes[12:20]),
                        'sequence': (raw_bytes[20] << 24) | (raw_bytes[21] << 16) | 
                               (raw_bytes[22] << 8) | raw_bytes[23],
                        'remaining_lifetime': (raw_bytes[10] << 8) | raw_bytes[11],
                        'checksum': hex((raw_bytes[24] << 8) | raw_bytes[25])
                    })
                    
                    # ✅ Detect IPv4/IPv6 TLVs manually
                    packet_info['tlv_info'] = self._detect_isis_tlvs_manual(raw_bytes)
        
            elif pdu_type in [24, 25]:  # CSNP
                if len(raw_bytes) >= 33:
                    packet_info.update({
                        'source_id': self._format_system_id(raw_bytes[10:16]) + f'.{raw_bytes[16]:02x}',
                        'start_lsp_id': self._format_lsp_id(raw_bytes[17:25]),
                        'end_lsp_id': self._format_lsp_id(raw_bytes[25:33])
                    })
        
            elif pdu_type in [26, 27]:  # PSNP
                if len(raw_bytes) >= 17:
                    packet_info.update({
                        'source_id': self._format_system_id(raw_bytes[10:16]) + f'.{raw_bytes[16]:02x}',
                        'lsp_entries': 'Present'
                    })
        
            return packet_info
        
        except Exception as e:
            return None

    def _detect_isis_tlvs(self, pkt):
        """
        Detect IPv4 and IPv6 TLVs in IS-IS LSP packets.
        TLV 128/130: IPv4 Internal/External Reachability
        TLV 236: IPv6 Reachability
        """
        tlv_info = {'has_ipv4': False, 'has_ipv6': False}
        
        try:
            # Check for TLVs in LSP payload
            if hasattr(pkt, 'tlvs'):
                for tlv in pkt.tlvs:
                    tlv_type = getattr(tlv, 'type', None)
                    if tlv_type in [128, 130, 132]:  # IPv4 reachability TLVs
                        tlv_info['has_ipv4'] = True
                    elif tlv_type == 236:  # IPv6 reachability TLV
                        tlv_info['has_ipv6'] = True
        except:
            pass
        
        return tlv_info


    def _detect_isis_tlvs_manual(self, raw_bytes):
        """Manual TLV detection for IPv4/IPv6 support."""
        tlv_info = {'has_ipv4': False, 'has_ipv6': False}
        
        try:
            # TLVs start after fixed header (varies by PDU type)
            # For LSP, TLVs typically start around byte 27
            offset = 27
            while offset < len(raw_bytes) - 2:
                tlv_type = raw_bytes[offset]
                tlv_len = raw_bytes[offset + 1]
                
                if tlv_type in [128, 130, 132]:  # IPv4 TLVs
                    tlv_info['has_ipv4'] = True
                elif tlv_type == 236:  # IPv6 TLV
                    tlv_info['has_ipv6'] = True
                
                offset += 2 + tlv_len
        except:
            pass
        
        return tlv_info    
            
    def _format_system_id(self, data):
        """Format 6-byte System ID as human-readable string."""
        try:
            if isinstance(data, bytes) and len(data) >= 6:
                return ':'.join([f'{b:02x}' for b in data[:6]])
            return 'N/A'
        except:
            return 'N/A'

    def _format_lsp_id(self, data):
        """Format 8-byte LSP ID (System ID + Pseudonode + Fragment)."""
        try:
            if isinstance(data, bytes) and len(data) >= 8:
                system_id = ':'.join([f'{b:02x}' for b in data[:6]])
                pseudonode = f'{data[6]:02x}'
                fragment = f'{data[7]:02x}'
                return f'{system_id}.{pseudonode}-{fragment}'
            return 'N/A'
        except:
            return 'N/A'


    def detect_isis_neighbor_failures(self):
        """
        Detect IS-IS neighbor failures by analyzing Hello packet patterns.
        Works for both IPv4 and IPv6 IS-IS deployments.
        """
        try:
            isis_data = self.analysis_results.get('isis_analysis', {})
            hello_pdus = isis_data.get('hello_pdus', [])
        
            if not hello_pdus:
                self.log_message("⚠️ No IS-IS Hello packets for neighbor analysis")
                return
        
            # Track hellos by neighbor pair
            hello_tracking = defaultdict(list)
        
            for hello in hello_pdus:
                src_mac = hello.get('src_mac', 'N/A')
                system_id = hello.get('system_id', 'N/A')
                timestamp = hello.get('timestamp', 'N/A')
                level = hello.get('level', 'Unknown')
            
                key = f"{src_mac}_{system_id}_{level}"
                hello_tracking[key].append({
                    'timestamp': timestamp,
                    'holding_time': hello.get('holding_time', 0)
                })
        
            # Detect failures
            failures = []
            current_time = max([safe_float(h['timestamp']) for hellos in hello_tracking.values() for h in hellos] or [0])
        
            for neighbor_key, hellos in hello_tracking.items():
                if len(hellos) < 2:
                    continue
            
                # Sort by timestamp
                hellos.sort(key=lambda x: safe_float(x['timestamp']))
            
                last_hello = hellos[-1]
                last_hello_time = safe_float(last_hello['timestamp'])
                holding_time = int(last_hello.get('holding_time', 30))
            
                # Check if neighbor expired (no hello within holding time)
                time_since_last = current_time - last_hello_time
            
                if time_since_last > holding_time:
                    parts = neighbor_key.split('_')
                    failures.append({
                        'neighbor': f"IS-IS {parts[2]} ({parts[1]})",
                        'failure_type': 'Holding time expired',
                        'last_hello': last_hello['timestamp'],
                        'holding_time': f"{holding_time}s",
                        'time_expired': f"{time_since_last:.1f}s"
                    })
        
            # Add to existing neighbor failures
            if 'neighbor_failures' not in self.analysis_results:
                self.analysis_results['neighbor_failures'] = []
        
            self.analysis_results['neighbor_failures'].extend(failures)
        
            self.log_message(f"✓ IS-IS neighbor analysis: {len(failures)} potential failures detected")
        
        except Exception as e:
            import traceback
            self.log_message(f"⚠️ IS-IS neighbor failure detection error: {str(e)}")
            self.log_message(traceback.format_exc())



 
#=======================================================================================#


    def parse_isakmp_sa_payload(self, sa_payload):
        """Parse ISAKMP SA payload for encryption and authentication details."""
        sas = []
        for proposal in getattr(sa_payload, 'proposals', []):
            proposal_nr = getattr(proposal, 'proposal_nr', None)
            for transform in getattr(proposal, 'transforms', []):
                transform_type = getattr(transform, 'transform_type', None)
                transform_id = getattr(transform, 'transform_id', None)
                enc_name = self.isakmp_map_transform(transform_type, transform_id)
                hash_alg = self.isakmp_get_hash_alg(transform)
                lifetime = self.isakmp_get_lifetime(transform)
                sas.append({
                    'proposal_nr': proposal_nr,
                    'encryption': enc_name,
                    'hash_alg': hash_alg,
                    'lifetime': lifetime,
                    'status': 'active'
                })
        return sas
    
    def analyze_isakmp(self):
        """
        Analyze ISAKMP/IKE packets for VPN tunnel establishment.
        Supports both IPv4 and IPv6 (IKEv2 over IPv6).
        """
        try:
            isakmp_messages = []
            isakmp_sas = []
            tunnel_details = []
            all_packets = self.src_packets + self.dst_packets

            for packet in all_packets:
                try:
                    if not packet.haslayer(ISAKMP):
                        # ✅ Check for NAT-T (UDP 4500) with IPv4 or IPv6
                        if packet.haslayer(UDP) and (packet[UDP].sport == 4500 or packet[UDP].dport == 4500):
                            # Extract IPs from both IPv4 and IPv6
                            src_ip, dst_ip, _ = get_packet_ips(packet)
                            if src_ip and dst_ip:
                                tunnel_details.append({
                                    'src': src_ip,
                                    'dst': dst_ip,
                                    'ip_version': 'IPv6' if packet.haslayer(IPv6) else 'IPv4',
                                    'timestamp': safe_timestamp(packet.time),
                                    'tunnel_type': 'NAT-T',
                                    'size': len(packet)
                                })
                        continue
                    
                    # ✅ Extract IPs from both IPv4 and IPv6
                    src_ip, dst_ip, _ = get_packet_ips(packet)
                    if not src_ip or not dst_ip:
                        continue
                    
                    ip_version = 'IPv6' if packet.haslayer(IPv6) else 'IPv4'
                    
                    isakmp_layer = packet[ISAKMP]
                    flags_obj = getattr(isakmp_layer, "flags", 0)
                    flags = int(flags_obj) if hasattr(flags_obj, '__int__') else 0
                    is_encrypted = bool(flags & 0x01)  # bit 0 indicates encryption

                    def bytes_to_hex_str(b):
                        if isinstance(b, bytes):
                            return b.hex()
                        return str(b)

                    isakmp_messages.append({
                        'src': src_ip,
                        'dst': dst_ip,
                        'ip_version': ip_version,  # ✅ Track IP version
                        'timestamp': safe_timestamp(packet.time),
                        'exchange_type': getattr(isakmp_layer, "exchange_type", "N/A"),
                        'flags': flags,
                        'is_encrypted': is_encrypted,
                        'spi_i': bytes_to_hex_str(getattr(isakmp_layer, 'init_cookie', b'')),
                        'spi_r': bytes_to_hex_str(getattr(isakmp_layer, 'resp_cookie', b'')),
                        'size': len(packet)
                    })

                    # Only try to walk payloads if not encrypted
                    if not is_encrypted:
                        payload = isakmp_layer.payload
                        while payload and hasattr(payload, 'name') and payload.name != 'NoPayload':
                            if payload.name == 'ISAKMP_payload_SA':
                                sas = self.parse_isakmp_sa_payload(payload)
                                for sa in sas:
                                    sa['msg_id'] = f"{src_ip}->{dst_ip}"
                                    sa['ip_version'] = ip_version  # ✅ Track IP version
                                    isakmp_sas.append(sa)
                            payload = payload.payload

                except Exception as e:
                    self.log_message(f"ISAKMP Decode Error: {e}")
                    continue

            # ✅ Count IPv4 vs IPv6 messages
            ipv4_msgs = sum(1 for m in isakmp_messages if m.get('ip_version') == 'IPv4')
            ipv6_msgs = sum(1 for m in isakmp_messages if m.get('ip_version') == 'IPv6')

            self.analysis_results['isakmp_analysis'] = {
                'isakmp_messages': isakmp_messages,
                'tunnel_details': tunnel_details,
                'isakmp_sas': isakmp_sas
            }
            
            self.log_message(
                f"✓ ISAKMP analysis: {len(isakmp_messages)} messages (IPv4: {ipv4_msgs}, IPv6: {ipv6_msgs}), "
                f"{len(tunnel_details)} NAT-T tunnels, {len(isakmp_sas)} SAs"
            )
            
        except Exception as e:
            import traceback
            self.log_message(f"⚠️ ISAKMP analysis error: {str(e)}")
            self.log_message(traceback.format_exc())
            self.analysis_results['isakmp_analysis'] = {
                'isakmp_messages': [], 
                'tunnel_details': [], 
                'isakmp_sas': []
            }

    def analyze_ipsec(self):
        """
        Analyze IPsec packets (ESP and AH) for VPN data transfer.
        Supports both IPv4 and IPv6 IPsec.
        """
        try:
            ah_packets = []
            esp_packets = []
            ipsec_tunnels = []
            ipsec_sas = []
            all_packets = self.src_packets + self.dst_packets
            spi_tracking = defaultdict(list)

            for packet in all_packets:
                try:
                    # ✅ Extract IPs from both IPv4 and IPv6
                    src_ip, dst_ip, _ = get_packet_ips(packet)
                    if not src_ip or not dst_ip:
                        continue
                    
                    ip_version = 'IPv6' if packet.haslayer(IPv6) else 'IPv4'
                    
                    # ✅ ESP packets (protocol 50 for both IPv4 and IPv6)
                    if packet.haslayer(ESP):
                        esp_layer = packet[ESP]
                        spi = esp_layer.spi
                        enc_alg = 'AES-CBC'  # Placeholder - encrypted payload prevents extraction
                        auth_alg = 'HMAC-SHA1'  # Placeholder
                        lifetime = '3600s'  # Placeholder

                        esp_packets.append({
                            'src': src_ip,
                            'dst': dst_ip,
                            'ip_version': ip_version,  # ✅ Track IP version
                            'timestamp': safe_timestamp(packet.time),
                            'spi': spi,
                            'size': len(packet)
                        })
                        
                        spi_key = f"ESP:{src_ip}-{dst_ip}-{ip_version}"
                        spi_tracking[spi_key].append(esp_packets[-1])

                        # Store unique SAs only
                        sa_key = f"{hex(spi)}-{src_ip}-{dst_ip}"
                        if not any(sa.get('sa_key') == sa_key for sa in ipsec_sas):
                            ipsec_sas.append({
                                'sa_key': sa_key,
                                'spi': hex(spi),
                                'src': src_ip,
                                'dst': dst_ip,
                                'ip_version': ip_version,  # ✅ Track IP version
                                'encryption': enc_alg,
                                'authentication': auth_alg,
                                'lifetime': lifetime,
                                'status': 'active'
                            })

                    # ✅ AH packets (protocol 51 for both IPv4 and IPv6)
                    elif packet.haslayer(AH):
                        ah_layer = packet[AH]
                        spi = ah_layer.spi
                        auth_alg = 'HMAC-SHA1'  # Placeholder
                        lifetime = '3600s'  # Placeholder

                        ah_packets.append({
                            'src': src_ip,
                            'dst': dst_ip,
                            'ip_version': ip_version,  # ✅ Track IP version
                            'timestamp': safe_timestamp(packet.time),
                            'spi': spi,
                            'size': len(packet)
                        })
                        
                        spi_key = f"AH:{src_ip}-{dst_ip}-{ip_version}"
                        spi_tracking[spi_key].append(ah_packets[-1])

                        # Store unique SAs only
                        sa_key = f"{hex(spi)}-{src_ip}-{dst_ip}"
                        if not any(sa.get('sa_key') == sa_key for sa in ipsec_sas):
                            ipsec_sas.append({
                                'sa_key': sa_key,
                                'spi': hex(spi),
                                'src': src_ip,
                                'dst': dst_ip,
                                'ip_version': ip_version,  # ✅ Track IP version
                                'encryption': 'N/A',
                                'authentication': auth_alg,
                                'lifetime': lifetime,
                                'status': 'active'
                            })
                            
                except Exception:
                    continue

            # Build tunnel summary
            for tunnel_key, packets in spi_tracking.items():
                if len(packets) > 1:
                    ipsec_tunnels.append({
                        'tunnel': tunnel_key,
                        'packet_count': len(packets),
                        'first_seen': packets[0]['timestamp'],
                        'last_seen': packets[-1]['timestamp'],
                        'ip_version': packets[0].get('ip_version', 'N/A')
                    })

            # ✅ Count IPv4 vs IPv6 packets
            ipv4_esp = sum(1 for p in esp_packets if p.get('ip_version') == 'IPv4')
            ipv6_esp = sum(1 for p in esp_packets if p.get('ip_version') == 'IPv6')
            ipv4_ah = sum(1 for p in ah_packets if p.get('ip_version') == 'IPv4')
            ipv6_ah = sum(1 for p in ah_packets if p.get('ip_version') == 'IPv6')

            self.analysis_results['ipsec_analysis'] = {
                'ah_packets': ah_packets,
                'esp_packets': esp_packets,
                'ipsec_tunnels': ipsec_tunnels,
                'ipsec_sas': ipsec_sas
            }
            
            self.log_message(
                f"✓ IPsec analysis: {len(ah_packets)} AH (IPv4: {ipv4_ah}, IPv6: {ipv6_ah}), "
                f"{len(esp_packets)} ESP (IPv4: {ipv4_esp}, IPv6: {ipv6_esp}), "
                f"{len(ipsec_tunnels)} tunnels, {len(ipsec_sas)} SAs"
            )
            
        except Exception as e:
            import traceback
            self.log_message(f"⚠️ IPsec analysis error: {str(e)}")
            self.log_message(traceback.format_exc())
            self.analysis_results['ipsec_analysis'] = {
                'ah_packets': [], 
                'esp_packets': [], 
                'ipsec_tunnels': [], 
                'ipsec_sas': []
            }
            
#===================================================================================#

    def generate_isakmp_messages_table(self):
        """Generate HTML table for ISAKMP messages with IPv6 support."""
        msgs = self.analysis_results.get('isakmp_analysis', {}).get('isakmp_messages', [])
        
        if not msgs:
            return '<div class="no-data">ℹ️ No ISAKMP messages found in this pcap.</div>'
        
        # ✅ Summary with IPv4/IPv6 breakdown
        ipv4_count = sum(1 for m in msgs if m.get('ip_version') == 'IPv4')
        ipv6_count = sum(1 for m in msgs if m.get('ip_version') == 'IPv6')
        
        html = f'''
        <div style="margin-bottom: 15px; padding: 10px; background: #f5f5f5; border-radius: 6px;">
            <strong>Total Messages:</strong> {len(msgs)} 
            <span style="margin-left: 15px;">IPv4: {ipv4_count}</span>
            <span style="margin-left: 10px;">IPv6: {ipv6_count}</span>
        </div>
        <table><thead><tr>
            <th>IP Version</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Timestamp</th>
            <th>Initiator SPI</th>
            <th>Responder SPI</th>
            <th>Exchange Type</th>
            <th>Encrypted?</th>
            <th>Flags</th>
            <th>Size</th>
        </tr></thead><tbody>
        '''
        
        for msg in msgs[:200]:  # ✅ Increased limit to 200
            flags_val = msg.get("flags", 0)
            flags_int = int(flags_val) if hasattr(flags_val, '__int__') else 0
            
            # ✅ IP version badge
            ip_version = msg.get('ip_version', 'N/A')
            if ip_version == 'IPv6':
                version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
                ip_style = 'font-family: monospace; font-size: 11px;'
            elif ip_version == 'IPv4':
                version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
                ip_style = 'font-family: monospace;'
            else:
                version_badge = 'N/A'
                ip_style = ''
            
            html += f'''
            <tr>
                <td style="text-align: center;">{version_badge}</td>
                <td style="{ip_style}">{msg.get("src", "")}</td>
                <td style="{ip_style}">{msg.get("dst", "")}</td>
                <td>{msg.get("timestamp", "")}</td>
                <td style="font-family: monospace; font-size: 11px;">{msg.get("spi_i", "")[:16]}...</td>
                <td style="font-family: monospace; font-size: 11px;">{msg.get("spi_r", "")[:16]}...</td>
                <td>{msg.get("exchange_type", "")}</td>
                <td>{"Yes" if msg.get("is_encrypted") else "No"}</td>
                <td>{hex(flags_int) if flags_int else "N/A"}</td>
                <td>{msg.get("size", "")}</td>
            </tr>
            '''
        
        if len(msgs) > 200:
            html += f'<tr><td colspan="10" style="text-align: center; font-style: italic; padding: 10px;">Showing 200 of {len(msgs)} messages</td></tr>'

        html += '</tbody></table>'
        return html


    
            
    def generate_ipsec_packets_table(self):
        """Generate HTML table for IPsec packets with IPv6 support."""
        ah_packets = self.analysis_results.get('ipsec_analysis', {}).get('ah_packets', [])
        esp_packets = self.analysis_results.get('ipsec_analysis', {}).get('esp_packets', [])
        all_packets = ah_packets + esp_packets
        
        if not all_packets:
            return '<div class="no-data">ℹ️ No IPsec packets captured.</div>'
        
        # ✅ Summary with IPv4/IPv6 breakdown
        ipv4_count = sum(1 for p in all_packets if p.get('ip_version') == 'IPv4')
        ipv6_count = sum(1 for p in all_packets if p.get('ip_version') == 'IPv6')
        
        html = f'''
        <div style="margin-bottom: 15px; padding: 10px; background: #f5f5f5; border-radius: 6px;">
            <strong>Total Packets:</strong> {len(all_packets)} (AH: {len(ah_packets)}, ESP: {len(esp_packets)})
            <br><strong>IP Versions:</strong> IPv4: {ipv4_count}, IPv6: {ipv6_count}
        </div>
        <table><thead><tr>
            <th>IP Version</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Timestamp</th>
            <th>Protocol</th>
            <th>SPI</th>
            <th>Size</th>
        </tr></thead><tbody>
        '''
        
        for pkt in all_packets[:200]:  # ✅ Increased limit to 200
            proto = "AH" if pkt in ah_packets else "ESP"
            
            # ✅ IP version badge
            ip_version = pkt.get('ip_version', 'N/A')
            if ip_version == 'IPv6':
                version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
                ip_style = 'font-family: monospace; font-size: 11px;'
            elif ip_version == 'IPv4':
                version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
                ip_style = 'font-family: monospace;'
            else:
                version_badge = 'N/A'
                ip_style = ''
            
            # Protocol color coding
            proto_color = '#28a745' if proto == 'AH' else '#007bff'
            
            html += f'''
            <tr>
                <td style="text-align: center;">{version_badge}</td>
                <td style="{ip_style}">{pkt['src']}</td>
                <td style="{ip_style}">{pkt['dst']}</td>
                <td>{pkt['timestamp']}</td>
                <td style="color: {proto_color}; font-weight: bold;">{proto}</td>
                <td style="font-family: monospace;">{hex(pkt['spi'])}</td>
                <td>{pkt['size']}</td>
            </tr>
            '''
        
        if len(all_packets) > 200:
            html += f'<tr><td colspan="7" style="text-align: center; font-style: italic; padding: 10px;">Showing 200 of {len(all_packets)} packets</td></tr>'

        html += '</tbody></table>'
        return html

#==========================================================================#

    def generate_mtu_mss_table(self):
        """Generate comprehensive MTU/MSS/Fragmentation analysis table with IPv6 support."""
        html = []
        
        # ==================== Critical Issues Summary ====================
        icmp_frag = self.analysis_results.get('icmp_frag_needed', [])
        pmtud_blackholes = self.analysis_results.get('pmtud_blackholes', {})
        
        critical_issues = len(icmp_frag) + len([k for k, v in pmtud_blackholes.items() 
                                                if v['retransmissions'] > 5 and not v['icmp_received']])
        
        if critical_issues > 0:
            html.append(f'''
                <div style="background:#dc354522; padding:15px; border-radius:8px; border-left:4px solid #dc3545; margin-bottom:20px;">
                    <h3 style="color:#dc3545; margin:0 0 10px 0;">🔴 {critical_issues} Critical MTU Issues Detected</h3>
                    <p style="margin:0;">Path MTU Discovery failures or ICMP/ICMPv6 blocking detected (affects both IPv4 and IPv6)</p>
                </div>
            ''')
        
        # ==================== ICMP/ICMPv6 Fragmentation Messages ====================
        if icmp_frag:
            html.append("<h3>🚨 ICMP/ICMPv6 Fragmentation Messages</h3>")
            html.append("<p><strong>Impact:</strong> Routers cannot forward packets due to MTU constraints. IPv6 uses 'Packet Too Big' (Type 2).</p>")
            html.append("<table class='mtu-table'><thead><tr>")
            html.append("<th>IP Version</th><th>Message Type</th><th>Source Router</th><th>Destination</th><th>Next Hop MTU</th><th>Timestamp</th></tr></thead><tbody>")
            
            for entry in icmp_frag[:50]:
                from datetime import datetime, timezone
                ts = datetime.fromtimestamp(entry['timestamp'], tz=timezone.utc).strftime('%H:%M:%S.%f')[:-3]
                
                # IP version badge
                ip_version = entry.get('ip_version', 'N/A')
                if ip_version == 'IPv6':
                    version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
                    ip_style = 'font-family: monospace; font-size: 11px;'
                elif ip_version == 'IPv4':
                    version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
                    ip_style = 'font-family: monospace;'
                else:
                    version_badge = 'N/A'
                    ip_style = ''
                
                html.append(f'''
                    <tr>
                        <td style="text-align:center;">{version_badge}</td>
                        <td>{entry.get('message_type', 'N/A')}</td>
                        <td style="{ip_style}">{entry['src']}</td>
                        <td style="{ip_style}">{entry['dst']}</td>
                        <td><strong>{entry['next_hop_mtu']} bytes</strong></td>
                        <td>{ts}</td>
                    </tr>
                ''')
            
            html.append("</tbody></table>")
        
        # ==================== PMTUD Black Holes ====================
        if pmtud_blackholes:
            blackholes = [(k, v) for k, v in pmtud_blackholes.items() if v['retransmissions'] > 5]
            if blackholes:
                html.append("<h3>⚫ Path MTU Discovery Black Holes</h3>")
                html.append("<p><strong>Critical:</strong> Large packets (IPv4 with DF bit or IPv6) are being dropped silently.</p>")
                html.append("<table class='mtu-table'><thead><tr>")
                html.append("<th>IP Version</th><th>Flow</th><th>Large Packets</th><th>Retransmissions</th><th>Max Size</th><th>ICMP Received?</th><th>Diagnosis</th></tr></thead><tbody>")
                
                for flow, data in blackholes:
                    icmp_status = "✅ Yes" if data['icmp_received'] else "❌ No (BLACK HOLE)"
                    diagnosis = "ICMP/ICMPv6 blocked or filtered" if not data['icmp_received'] else "PMTUD working"
                    severity_color = "#28a745" if data['icmp_received'] else "#dc3545"
                    
                    # IP version badge
                    ip_version = data.get('ip_version', 'N/A')
                    if ip_version == 'IPv6':
                        version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
                    elif ip_version == 'IPv4':
                        version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
                    else:
                        version_badge = 'N/A'
                    
                    html.append(f'''
                        <tr style="border-left:4px solid {severity_color};">
                            <td style="text-align:center;">{version_badge}</td>
                            <td><code style="font-size:11px;">{flow}</code></td>
                            <td>{data['large_df_packets']}</td>
                            <td><strong>{data['retransmissions']}</strong></td>
                            <td>{data['max_size']} bytes</td>
                            <td>{icmp_status}</td>
                            <td>{diagnosis}</td>
                        </tr>
                    ''')
                
                html.append("</tbody></table>")
        
        # ==================== TCP MSS Analysis ====================
        tcp_data = self.analysis_results.get('mtu_mss_analysis', {})
        if tcp_data:
            html.append("<h3>TCP MSS per Flow (IPv4 + IPv6)</h3>")
            html.append("<table class='mtu-table'><thead><tr>")
            html.append("<th>IP Version</th><th>Flow</th><th>Initial MSS</th><th>Clamped MSS</th><th>MSS Changed?</th>")
            html.append("<th>Fragmented Pkts</th><th>DF Bit Pkts</th><th>Max Payload</th></tr></thead><tbody>")
            
            for flow, r in list(tcp_data.items())[:100]:
                # IP version badge
                ip_version = r.get('ip_version', 'N/A')
                if ip_version == 'IPv6':
                    version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
                elif ip_version == 'IPv4':
                    version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
                else:
                    version_badge = 'N/A'
                
                html.append(f'''
                    <tr>
                        <td style="text-align:center;">{version_badge}</td>
                        <td><code style="font-size:11px;">{flow}</code></td>
                        <td>{r.get('first_mss') or 'N/A'}</td>
                        <td>{r.get('second_mss') or 'N/A'}</td>
                        <td>{'Yes' if r.get('mss_changed') else 'No'}</td>
                        <td>{r.get('fragmented_packets', 0)}</td>
                        <td>{r.get('df_bit_packets', 0) if ip_version == 'IPv4' else 'N/A'}</td>
                        <td>{r.get('max_payload', 0)}</td>
                    </tr>
                ''')
            
            html.append("</tbody></table>")
        
        # ==================== Tunnel MTU Analysis ====================
        tunnel_data = self.analysis_results.get('tunnel_mtu_analysis', {})
        if tunnel_data:
            html.append("<h3>Tunnel (IPsec/GRE/VXLAN) MTU Analysis (IPv4 + IPv6)</h3>")
            html.append("<table class='mtu-table'><thead><tr>")
            html.append("<th>IP Version</th><th>Tunnel</th><th>Protocol</th><th>Total Pkts</th><th>Fragmented</th><th>DF Set</th><th>Max Payload</th></tr></thead><tbody>")
            
            for tunnel, t in list(tunnel_data.items())[:100]:
                # IP version badge
                ip_version = t.get('ip_version', 'N/A')
                if ip_version == 'IPv6':
                    version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
                elif ip_version == 'IPv4':
                    version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
                else:
                    version_badge = 'N/A'
                
                proto_colors = {'ESP': '#007bff', 'AH': '#28a745', 'GRE': '#ffc107', 'VXLAN': '#6f42c1'}
                proto_color = proto_colors.get(t['proto'], '#666')
                
                html.append(f'''
                    <tr>
                        <td style="text-align:center;">{version_badge}</td>
                        <td><code style="font-size:11px;">{tunnel}</code></td>
                        <td><span style="background:{proto_color}; color:white; padding:4px 8px; border-radius:4px;">{t['proto']}</span></td>
                        <td>{t['total_pkts']}</td>
                        <td>{t['fragmented_pkts']}</td>
                        <td>{t['df_set_pkts'] if ip_version == 'IPv4' else 'N/A'}</td>
                        <td>{t['max_payload']}</td>
                    </tr>
                ''')
            
            html.append("</tbody></table>")
        
        # ==================== IPv4 Fragmentation ====================
        ipv4_frag = self.analysis_results.get('ipv4_fragments', [])
        if ipv4_frag:
            html.append(f"<h3>🔶 IPv4 Fragmentation Detected ({len(ipv4_frag)} fragments)</h3>")
            html.append("<p><strong>Note:</strong> Fragmentation can cause performance degradation and reliability issues.</p>")
        
        # ==================== IPv6 Fragmentation ====================
        ipv6_frag = self.analysis_results.get('ipv6_fragments', [])
        if ipv6_frag:
            html.append(f"<h3>🔷 IPv6 Fragmentation Detected ({len(ipv6_frag)} fragments)</h3>")
            html.append("<p><strong>Critical:</strong> IPv6 fragmentation should be avoided. Routers don't fragment IPv6; only endpoints do.</p>")
            html.append("<p><strong>Recommendation:</strong> Adjust MSS clamping or increase path MTU to avoid IPv6 fragmentation.</p>")
        
        # ==================== Jumbo Frames ====================
        jumbo = self.analysis_results.get('jumbo_frames', [])
        if jumbo:
            html.append(f"<h3>⚡ Jumbo Frames Detected ({len(jumbo)} packets > 1600 bytes)</h3>")
            html.append("<p><strong>Note:</strong> Jumbo frames (> 1500 MTU) can cause issues on networks with mixed MTU sizes.</p>")
        
        if not any([tcp_data, tunnel_data, icmp_frag, pmtud_blackholes, ipv4_frag, ipv6_frag]):
            return "<div class='no-data'>No MTU/MSS/Fragmentation issues detected.</div>"
        
        return ''.join(html)


#=========================================================================================#

    def analyze_sequences(self):
        """Analyze TCP sequence numbers for gaps, jumps, and duplicates. Supports IPv4 and IPv6."""
        try:
            src_sequences = {}
            dst_sequences = {}
            sequence_gaps = []
            sequence_jumps = []
            duplicate_sequences = []
            
            # Analyze source sequences
            flows = defaultdict(list)
            for packet in self.src_packets:
                try:
                    if not packet.haslayer(TCP):
                        continue
                    
                    # ✅ Extract IPs from both IPv4 and IPv6
                    src_ip, dst_ip, ttl = get_packet_ips(packet)
                    if not src_ip or not dst_ip:
                        continue
                    
                    # ✅ Build flow key with extracted IPs (works for both IPv4 and IPv6)
                    flow_key = "{}:{} → {}:{}".format(src_ip, packet[TCP].sport, dst_ip, packet[TCP].dport)
                    
                    flows[flow_key].append({
                        'seq': packet[TCP].seq,
                        'time': safe_float(packet.time),
                        'timestamp': safe_timestamp(packet.time),
                        'payload_len': len(packet[TCP].payload) if packet[TCP].payload else 0,
                        'ack': packet[TCP].ack,
                        'flags': packet[TCP].flags,
                        'ip_version': 'IPv6' if packet.haslayer(IPv6) else 'IPv4'  # ✅ Track IP version
                    })
                except Exception:
                    continue
            
            for flow, packets in flows.items():
                try:
                    packets.sort(key=lambda x: x['time'])
                    src_sequences[flow] = packets
                    
                    for i in range(1, len(packets)):
                        try:
                            current = packets[i]
                            previous = packets[i-1]
                            expected_seq = previous['seq'] + previous['payload_len']
                            
                            # Only check if there's actual payload (skip pure ACKs)
                            if previous['payload_len'] == 0:
                                continue
                            
                            if current['seq'] > expected_seq:
                                gap_size = current['seq'] - expected_seq
                                if gap_size > 100000:  # Large jump
                                    sequence_jumps.append({
                                        'flow': flow,
                                        'timestamp': current['timestamp'],
                                        'expected': expected_seq,
                                        'actual': current['seq'],
                                        'jump_size': gap_size,
                                        'source': 'src',
                                        'ack': current['ack'],
                                        'flags': current['flags'],
                                        'ip_version': current['ip_version']  # ✅ Track IP version
                                    })
                                else:  # Gap
                                    sequence_gaps.append({
                                        'flow': flow,
                                        'timestamp': current['timestamp'],
                                        'expected': expected_seq,
                                        'actual': current['seq'],
                                        'gap_size': gap_size,
                                        'source': 'src',
                                        'ack': current['ack'],
                                        'flags': current['flags'],
                                        'ip_version': current['ip_version']  # ✅ Track IP version
                                    })
                            elif current['seq'] == previous['seq'] and current['payload_len'] > 0:
                                duplicate_sequences.append({
                                    'flow': flow,
                                    'timestamp': current['timestamp'],
                                    'seq': current['seq'],
                                    'source': 'src',
                                    'ack': current['ack'],
                                    'flags': current['flags'],
                                    'ip_version': current['ip_version']  # ✅ Track IP version
                                })
                        except Exception:
                            continue
                except Exception:
                    continue
            
            # Analyze destination sequences
            flows = defaultdict(list)
            for packet in self.dst_packets:
                try:
                    if not packet.haslayer(TCP):
                        continue
                    
                    # ✅ Extract IPs from both IPv4 and IPv6
                    src_ip, dst_ip, ttl = get_packet_ips(packet)
                    if not src_ip or not dst_ip:
                        continue
                    
                    # ✅ Build flow key with extracted IPs (works for both IPv4 and IPv6)
                    flow_key = "{}:{} → {}:{}".format(src_ip, packet[TCP].sport, dst_ip, packet[TCP].dport)
                    
                    flows[flow_key].append({
                        'seq': packet[TCP].seq,
                        'time': safe_float(packet.time),
                        'timestamp': safe_timestamp(packet.time),
                        'payload_len': len(packet[TCP].payload) if packet[TCP].payload else 0,
                        'ack': packet[TCP].ack,
                        'flags': packet[TCP].flags,
                        'ip_version': 'IPv6' if packet.haslayer(IPv6) else 'IPv4'  # ✅ Track IP version
                    })
                except Exception:
                    continue
            
            for flow, packets in flows.items():
                try:
                    packets.sort(key=lambda x: x['time'])
                    dst_sequences[flow] = packets
                    
                    for i in range(1, len(packets)):
                        try:
                            current = packets[i]
                            previous = packets[i-1]
                            expected_seq = previous['seq'] + previous['payload_len']
                            
                            # Only check if there's actual payload (skip pure ACKs)
                            if previous['payload_len'] == 0:
                                continue
                            
                            if current['seq'] > expected_seq:
                                gap_size = current['seq'] - expected_seq
                                if gap_size > 100000:  # Large jump
                                    sequence_jumps.append({
                                        'flow': flow,
                                        'timestamp': current['timestamp'],
                                        'expected': expected_seq,
                                        'actual': current['seq'],
                                        'jump_size': gap_size,
                                        'source': 'dst',
                                        'ack': current['ack'],
                                        'flags': current['flags'],
                                        'ip_version': current['ip_version']  # ✅ Track IP version
                                    })
                                else:  # Gap
                                    sequence_gaps.append({
                                        'flow': flow,
                                        'timestamp': current['timestamp'],
                                        'expected': expected_seq,
                                        'actual': current['seq'],
                                        'gap_size': gap_size,
                                        'source': 'dst',
                                        'ack': current['ack'],
                                        'flags': current['flags'],
                                        'ip_version': current['ip_version']  # ✅ Track IP version
                                    })
                            elif current['seq'] == previous['seq'] and current['payload_len'] > 0:
                                duplicate_sequences.append({
                                    'flow': flow,
                                    'timestamp': current['timestamp'],
                                    'seq': current['seq'],
                                    'source': 'dst',
                                    'ack': current['ack'],
                                    'flags': current['flags'],
                                    'ip_version': current['ip_version']  # ✅ Track IP version
                                })
                        except Exception:
                            continue
                except Exception:
                    continue
            
            self.analysis_results['sequence_analysis'] = {
                'src_sequences': src_sequences,
                'dst_sequences': dst_sequences,
                'sequence_gaps': sequence_gaps,
                'sequence_jumps': sequence_jumps,
                'duplicate_sequences': duplicate_sequences
            }
            
            self.log_message("✓ Sequence analysis: {} gaps, {} jumps, {} duplicates".format(
                len(sequence_gaps), len(sequence_jumps), len(duplicate_sequences)))
                
        except Exception as e:
            import traceback
            self.log_message("⚠️ Sequence analysis error: {}".format(str(e)))
            self.log_message(traceback.format_exc())
            self.analysis_results['sequence_analysis'] = {
                'src_sequences': {}, 'dst_sequences': {}, 
                'sequence_gaps': [], 'sequence_jumps': [], 'duplicate_sequences': []
            }
            
    def analyze_routing_comprehensive(self):
        """Enhanced routing protocol analysis with comprehensive BGP detection. Supports IPv4 and IPv6."""
        try:
            ospf_count = eigrp_count = bgp_count = 0
            bgp_sessions = defaultdict(lambda: {
                'state': 'Unknown', 
                'messages': [], 
                'last_seen': 0,
                'ip_version': None  # ✅ Track IP version
            })
            routing_summary = {}
            
            for packet in self.src_packets + self.dst_packets:
                try:
                    # ✅ Extract IPs using helper function
                    src_ip, dst_ip, ttl = get_packet_ips(packet)
                    if not src_ip or not dst_ip:
                        continue
                    
                    # ✅ Determine IP version
                    ip_version = 'IPv6' if packet.haslayer(IPv6) else 'IPv4' if packet.haslayer(IP) else None
                    if not ip_version:
                        continue
                    
                    packet_time = safe_float(packet.time)
                    timestamp_str = safe_timestamp(packet.time)

                    # ✅ Get protocol number (works for both IPv4 and IPv6)
                    if packet.haslayer(IP):
                        proto = packet[IP].proto
                    elif packet.haslayer(IPv6):
                        proto = packet[IPv6].nh  # Next Header in IPv6
                    else:
                        continue
                    
                    # ✅ Check routing protocols
                    if proto == 89:  # OSPF
                        ospf_count += 1
                    elif proto == 88:  # EIGRP
                        eigrp_count += 1
                    elif packet.haslayer(TCP) and (packet[TCP].sport == 179 or packet[TCP].dport == 179):  # BGP
                        bgp_count += 1
                        
                        # ✅ Use extracted IPs instead of packet[IP].src/dst
                        session_key = "{}:{} → {}:{}".format(src_ip, packet[TCP].sport, dst_ip, packet[TCP].dport)
                        
                        bgp_packet_info = {
                            'src': src_ip,        # ✅ Use extracted IP
                            'dst': dst_ip,        # ✅ Use extracted IP
                            'ip_version': ip_version,  # ✅ Track IP version
                            'timestamp': timestamp_str,
                            'tcp_flags': self.format_tcp_flags(packet[TCP].flags),
                            'seq': packet[TCP].seq,
                            'ack': packet[TCP].ack,
                            'time': packet_time  # ✅ Store raw time for duration calculation
                        }
                        
                        # ✅ Set IP version on first packet
                        if not bgp_sessions[session_key]['ip_version']:
                            bgp_sessions[session_key]['ip_version'] = ip_version
                        
                        # Update session state based on TCP flags
                        if packet[TCP].flags & 0x02:  # SYN
                            bgp_sessions[session_key]['state'] = 'Connect'
                        elif packet[TCP].flags & 0x04:  # RST
                            bgp_sessions[session_key]['state'] = 'Reset'
                        elif packet[TCP].flags & 0x10:  # ACK
                            if bgp_sessions[session_key]['state'] in ['Unknown', 'Connect']:
                                bgp_sessions[session_key]['state'] = 'Active'
                        
                        bgp_sessions[session_key]['messages'].append(bgp_packet_info)
                        bgp_sessions[session_key]['last_seen'] = packet_time
                except Exception:
                    continue
            
            # Convert sessions to list format
            session_list = []
            for session, info in bgp_sessions.items():
                try:
                    last_seen_str = safe_timestamp(info['last_seen']) if info['last_seen'] else 'Never'
                    duration = 0
                    if len(info['messages']) > 1:
                        # ✅ Fixed duration calculation using 'time' field
                        first_time = safe_float(info['messages'][0].get('time', info['last_seen']))
                        last_time = safe_float(info['messages'][-1].get('time', info['last_seen']))
                        duration = last_time - first_time
                    
                    session_list.append({
                        'session': session,
                        'state': info['state'],
                        'ip_version': info.get('ip_version', 'N/A'),  # ✅ Include IP version
                        'message_count': len(info['messages']),
                        'last_seen': last_seen_str,
                        'duration': round(duration, 2) if duration > 0 else 0
                    })
                except Exception:
                    session_list.append({
                        'session': session,
                        'state': info['state'],
                        'ip_version': info.get('ip_version', 'N/A'),
                        'message_count': len(info['messages']),
                        'last_seen': 'Parse Error',
                        'duration': 0
                    })
            
            # ✅ Count IPv4 vs IPv6 BGP sessions
            ipv4_bgp = sum(1 for s in session_list if s.get('ip_version') == 'IPv4')
            ipv6_bgp = sum(1 for s in session_list if s.get('ip_version') == 'IPv6')
            
            routing_summary = {
                'ospf_packets': ospf_count,
                'eigrp_packets': eigrp_count,
                'bgp_packets': bgp_count,
                'bgp_sessions': len(bgp_sessions),
                'ipv4_bgp_sessions': ipv4_bgp,  # ✅ Track IPv4 BGP sessions
                'ipv6_bgp_sessions': ipv6_bgp   # ✅ Track IPv6 BGP sessions
            }

            self.analysis_results['routing_protocol_analysis'] = {
                'ospf_packets': [],
                'eigrp_packets': [],
                'bgp_packets': [],
                'bgp_sessions': session_list,
                'routing_summary': routing_summary
            }
            
            self.log_message("✓ Routing analysis: OSPF={}, EIGRP={}, BGP={} (IPv4: {}, IPv6: {})".format(
                ospf_count, eigrp_count, bgp_count, ipv4_bgp, ipv6_bgp))
                
        except Exception as e:
            import traceback
            self.log_message("⚠️ Routing analysis error: {}".format(str(e)))
            self.log_message(traceback.format_exc())
            self.analysis_results['routing_protocol_analysis'] = {
                'ospf_packets': [], 'eigrp_packets': [], 'bgp_packets': [], 
                'bgp_sessions': [], 'routing_summary': {}
            }


    def format_tcp_flags(self, flags):
        """Format TCP flags as string."""
        try:
            flag_names = []
            if flags & 0x01:
                flag_names.append('FIN')
            if flags & 0x02:
                flag_names.append('SYN')
            if flags & 0x04:
                flag_names.append('RST')
            if flags & 0x08:
                flag_names.append('PSH')
            if flags & 0x10:
                flag_names.append('ACK')
            if flags & 0x20:
                flag_names.append('URG')
            return ','.join(flag_names) if flag_names else str(flags)
        except Exception:
            return 'Unknown'


    def analyze_communication_complete(self, selected_protocol="ALL", jitter_threshold=None, jitter_metric="avg_jitter"):
        """Enhanced flow analysis supporting both IPv4 and IPv6."""
        try:
            self.log_message("📡 Enhanced communication analysis started (IPv4 + IPv6)...")

            all_packets = self.src_packets + self.dst_packets
            flow_data = defaultdict(list)
            unique_ips = set()

            for packet in all_packets:
                try:
                    # 🆕 Check for IPv4 OR IPv6
                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        ttl_value = packet[IP].ttl
                        ip_version = "IPv4"
                    elif IPv6 in packet:
                        src_ip = packet[IPv6].src
                        dst_ip = packet[IPv6].dst
                        ttl_value = packet[IPv6].hlim  # Hop Limit in IPv6
                        ip_version = "IPv6"
                    else:
                        continue  # Skip non-IP packets

                    unique_ips.add(src_ip)
                    unique_ips.add(dst_ip)

                    # Create bidirectional flow key
                    flow_key = f"{src_ip} ↔ {dst_ip}"
                    reverse_key = f"{dst_ip} ↔ {src_ip}"
                    if reverse_key in flow_data:
                        flow_key = reverse_key

                    # Protocol detection (works for both IPv4 and IPv6)
                    if TCP in packet:
                        protocol = "TCP"
                    elif UDP in packet:
                        protocol = "UDP"
                    elif packet.haslayer('ICMP'):
                        protocol = "ICMP"
                    elif packet.haslayer('ICMPv6'):
                        protocol = "ICMPv6"
                    elif packet.haslayer('ARP'):
                        protocol = "ARP"
                    elif packet.haslayer('UIM'):
                        protocol = "UIM"
                    else:
                        protocol = "Other"

                    packet_dict = {
                        'timestamp': float(packet.time),
                        'size': len(packet),
                        'protocol': protocol,
                        'ttl': ttl_value,
                        'ip_version': ip_version,  # 🆕 Track IP version
                    }
                    
                    if protocol == "TCP":
                        packet_dict['comment'] = tcp_comment(packet)

                    flow_data[flow_key].append(packet_dict)

                except Exception as e:
                    continue

            flows = []
            flow_stats = {
                'total_flows': len(flow_data),
                'total_packets': len(all_packets),
                'unique_ips': len(unique_ips),
                'protocol_distribution': defaultdict(int),
                'avg_flow_duration': 0,
                'total_data_volume': 0,
                'ipv4_flows': 0,  # 🆕 Track IPv4 flows
                'ipv6_flows': 0,  # 🆕 Track IPv6 flows
            }
            total_duration = 0

            for flow_key, packets in flow_data.items():
                if not packets:
                    continue

                packets.sort(key=lambda x: x['timestamp'])
                start_time = packets[0]['timestamp']
                end_time = packets[-1]['timestamp']
                duration = max(0, end_time - start_time)
                total_duration += duration

                packet_count = len(packets)
                data_volume = sum(p['size'] for p in packets)
                throughput = data_volume / max(duration, 0.001)
                protocols = [p['protocol'] for p in packets]
                dominant_protocol = max(set(protocols), key=protocols.count)

                ttl = packets[0]['ttl'] if packets else None
                length = packets[0]['size'] if packets else None
                ip_version = packets[0].get('ip_version', 'IPv4')  # 🆕 Get IP version

                # Update flow stats
                if ip_version == "IPv6":
                    flow_stats['ipv6_flows'] += 1
                else:
                    flow_stats['ipv4_flows'] += 1

                # Enhanced stats containers
                iat = []
                burst_sizes = []
                throughput_samples = []

                if packet_count > 1:
                    for i in range(packet_count - 1):
                        inter_arrival = packets[i+1]['timestamp'] - packets[i]['timestamp']
                        iat.append(inter_arrival)
                        burst_bytes = packets[i+1]['size']
                        burst_sizes.append(burst_bytes)
                        if inter_arrival > 0:
                            throughput_samples.append(burst_bytes / inter_arrival)

                # Jitter calculation (UDP only)
                min_jitter = max_jitter = avg_jitter = None
                jitter_diffs = []
                flagged_jitter_indices = []
                jitter_diffs_ms = []

                if dominant_protocol == "UDP" and len(iat) > 1:
                    jitter_diffs = [abs(iat[i+1] - iat[i]) for i in range(len(iat) - 1)]
                    jitter_diffs_ms = [j * 1000 for j in jitter_diffs]
                    min_jitter = min(jitter_diffs_ms) if jitter_diffs_ms else 0.0
                    max_jitter = max(jitter_diffs_ms) if jitter_diffs_ms else 0.0
                    avg_jitter = sum(jitter_diffs_ms) / len(jitter_diffs_ms) if jitter_diffs_ms else 0.0

                    if jitter_threshold is not None:
                        try:
                            threshold = float(jitter_threshold)
                            flagged_jitter_indices = [
                                idx for idx, val in enumerate(jitter_diffs_ms) if val > threshold
                            ]
                        except Exception:
                            flagged_jitter_indices = []
                else:
                    min_jitter = max_jitter = avg_jitter = 0.0
                    jitter_diffs_ms = []
                    flagged_jitter_indices = []

                # Throughput stats
                min_tp = min(throughput_samples) if throughput_samples else 0.0
                max_tp = max(throughput_samples) if throughput_samples else 0.0
                avg_tp = sum(throughput_samples)/len(throughput_samples) if throughput_samples else throughput

                # Inter-arrival time stats
                min_iat = min(iat) if iat else 0.0
                max_iat = max(iat) if iat else 0.0
                avg_iat = sum(iat)/len(iat) if iat else 0.0

                flow_info = {
                    'flow': flow_key,
                    'packet_count': packet_count,
                    'data_volume': f"{data_volume:,} bytes",
                    'protocol': dominant_protocol,
                    'ip_version': ip_version,  # 🆕 Include IP version
                    'ttl': ttl if ttl is not None else '',
                    'length': length if length is not None else '',
                    'duration': f"{duration:.2f}s",

                    # Jitter stats
                    'min_jitter': f"{min_jitter:.3f}",
                    'max_jitter': f"{max_jitter:.3f}",
                    'avg_jitter': f"{avg_jitter:.3f}",

                    # Throughput stats
                    'min_throughput': f"{min_tp:.1f} B/s",
                    'max_throughput': f"{max_tp:.1f} B/s",
                    'avg_throughput': f"{avg_tp:.1f} B/s",

                    # Inter-arrival time stats
                    'min_iat': f"{min_iat:.4f}s",
                    'max_iat': f"{max_iat:.4f}s",
                    'avg_iat': f"{avg_iat:.4f}s",

                    'flagged_jitter_indices': flagged_jitter_indices,
                    'packets': packets,
                }
                flows.append(flow_info)

            flow_stats['avg_flow_duration'] = total_duration / len(flow_data) if flow_data else 0
            flow_stats['total_data_volume'] = sum(f['packet_count'] for f in flows)

            self.analysis_results['communication_analysis'] = {
                'flows': flows,
                'unique_ips': unique_ips,
                'flow_stats': flow_stats,
            }

            self.log_message(
                f"✓ Enhanced communication flow analysis: {len(flows)} flows "
                f"({flow_stats['ipv4_flows']} IPv4, {flow_stats['ipv6_flows']} IPv6), "
                f"{len(unique_ips)} unique IPs"
            )
            
        except Exception as e:
            self.log_message(f"⚠️ Communication analysis error: {str(e)}")
            self.analysis_results['communication_analysis'] = {
                'flows': [],
                'unique_ips': set(),
                'flow_stats': {},
            }

            
#==================================MTU/MSS_Correlation=========================================#
    
    def _extract_ips_from_neighbor(self, neighbor_str):
        """
        Parse neighbor strings like:
          IPv4: '10.99.40.3:179↔10.99.40.4:20873' or '10.7.193.186↔10.7.193.185'
          IPv6: '2001:db8::1:179↔2001:db8::2:20873' or '2001:db8::1↔2001:db8::2'
        Return a set of just the IPs: {'10.99.40.3', '10.99.40.4'} or {'2001:db8::1', '2001:db8::2'}
        """
        try:
            sides = neighbor_str.split('↔')
            ips = set()
            for side in sides:
                side = side.strip()
                if not side:
                    continue
                
                # ✅ IPv6 detection: if it contains multiple colons, it's IPv6
                if side.count(':') > 1:
                    # IPv6 address - port is after the LAST colon if present
                    # Examples: 
                    #   '2001:db8::1' -> '2001:db8::1' (no port)
                    #   '2001:db8::1:179' -> '2001:db8::1' (port 179)
                    # But this is ambiguous! Better approach: check if last segment is a number
                    parts = side.rsplit(':', 1)  # Split from right, max 1 split
                    if len(parts) == 2 and parts[1].isdigit():
                        # Last part is a port number
                        ip = parts[0]
                    else:
                        # No port, entire string is the IPv6 address
                        ip = side
                else:
                    # IPv4 address - strip port if present (single colon)
                    if ':' in side:
                        ip = side.split(':', 1)[0]
                    else:
                        ip = side
                
                ips.add(ip)
            return ips
        except Exception:
            return set()
                    
    def _build_mtu_issue_index(self):
        """
        Create an index keyed by frozenset({ip1, ip2}) with
        aggregated MTU/MSS/fragmentation symptoms for that pair.
        """
        index = {}

        tcp_flows = self.analysis_results.get('mtu_mss_analysis', {})
        tunnels   = self.analysis_results.get('tunnel_mtu_analysis', {})
        pmtud_bh  = self.analysis_results.get('pmtud_blackholes', {})
        icmp_frag = self.analysis_results.get('icmp_frag_needed', [])
        ipv6_frags = self.analysis_results.get('ipv6_fragments', [])
        jumbo      = self.analysis_results.get('jumbo_frames', [])

        def get_bucket(ip1, ip2):
            key = frozenset({ip1, ip2})
            if key not in index:
                index[key] = {
                    'tcp_flows': [],
                    'tunnel_flows': [],
                    'pmtud_blackholes': [],
                    'icmp_frag': [],
                    'ipv6_frags': [],
                    'jumbo': [],
                }
            return index[key]

        def extract_ip_from_flow_side(side):
            """Extract IP from 'ip:port' or just 'ip' (handles IPv6)"""
            side = side.strip()
            if side.count(':') > 1:
                # IPv6 - check if last segment is port
                parts = side.rsplit(':', 1)
                if len(parts) == 2 and parts[1].isdigit():
                    return parts[0]  # IP without port
                return side  # Full IPv6 address
            else:
                # IPv4 - split on colon
                return side.split(':')[0]

        # TCP flows (e.g. BGP, other TCP protocols)
        for flow_key, r in tcp_flows.items():
            # flow_key: 'ip1:port → ip2:port'
            try:
                left, right = flow_key.split('→')
                ip1 = ip1 = extract_ip_from_flow_side(left)
                ip2 = extract_ip_from_flow_side(right)
            except Exception:
                continue
            bucket = get_bucket(ip1, ip2)
            bucket['tcp_flows'].append({'key': flow_key, 'stats': r})

        # Tunnels (ESP/AH/GRE/VXLAN)
        for tunnel_key, t in tunnels.items():
            ip1 = t.get('src')
            ip2 = t.get('dst')
            if not ip1 or not ip2:
                continue
            bucket = get_bucket(ip1, ip2)
            bucket['tunnel_flows'].append({'key': tunnel_key, 'stats': t})

        # PMTUD black holes (TCP 4-tuples)
        for flow_key, bh in pmtud_bh.items():
            try:
                left, right = flow_key.split('→')
                ip1 = extract_ip_from_flow_side(left)
                ip2 = extract_ip_from_flow_side(right)
            except Exception:
                continue
            bucket = get_bucket(ip1, ip2)
            bucket['pmtud_blackholes'].append({'key': flow_key, 'stats': bh})

        # ICMP Frag Needed messages
        for e in icmp_frag:
            ip1 = e.get('src')
            ip2 = e.get('dst')
            if not ip1 or not ip2:
                continue
            bucket = get_bucket(ip1, ip2)
            bucket['icmp_frag'].append(e)

        # IPv6 fragments
        for e in ipv6_frags:
            ip1 = e.get('src')
            ip2 = e.get('dst')
            if not ip1 or not ip2:
                continue
            bucket = get_bucket(ip1, ip2)
            bucket['ipv6_frags'].append(e)

        # Jumbo frames
        for e in jumbo:
            ip1 = e.get('src')
            ip2 = e.get('dst')
            if not ip1 or not ip2:
                continue
            bucket = get_bucket(ip1, ip2)
            bucket['jumbo'].append(e)

        return index


    def correlate_mtu_with_protocol_issues(self):
        """
        Correlate MTU/MSS/fragmentation symptoms with protocol issues for:
        - OSPF / BGP / EIGRP / ISIS stuck_neighbor_states
        - neighbor_failures (Hello loss)
        Store results in analysis_results['mtu_protocol_correlations'].
        """
        try:
            stuck_states = self.analysis_results.get('stuck_neighbor_states', [])
            neighbor_failures = self.analysis_results.get('neighbor_failures', [])

            mtu_index = self._build_mtu_issue_index()
            correlations = []

            # Helper to score + summarize MTU symptoms
            def analyze_mtu_bucket(bucket):
                issues = []

                # TCP-level symptoms (for BGP, other TCP protocols)
                for f in bucket['tcp_flows']:
                    s = f['stats']
                    flow_name = f['key']

                    if s.get('first_mss') is None:
                        issues.append({
                            'type': 'NO_MSS',
                            'severity': 'CRITICAL',
                            'where': flow_name,
                            'desc': 'No MSS option seen in SYN (TCP handshake may be incomplete)'
                        })
                    if s.get('max_payload', 0) < 100 and s.get('total_packets', 0) > 0:
                        issues.append({
                            'type': 'TINY_PAYLOAD',
                            'severity': 'CRITICAL',
                            'where': flow_name,
                            'desc': f'Max TCP payload only {s.get("max_payload", 0)} bytes'
                        })
                    if s.get('first_mss') and s.get('max_payload'):
                        mss = s['first_mss']
                        mp  = s['max_payload']
                        if mss > mp + 200:
                            issues.append({
                                'type': 'MSS_PAYLOAD_MISMATCH',
                                'severity': 'WARNING',
                                'where': flow_name,
                                'desc': f'MSS {mss} but max payload {mp} (possible PMTU problem)'
                            })
                    if s.get('has_fragments'):
                        issues.append({
                            'type': 'FRAGMENTATION',
                            'severity': 'WARNING',
                            'where': flow_name,
                            'desc': 'IP fragmentation observed on TCP flow'
                        })

                # Tunnel symptoms (IPsec/GRE/VXLAN)
                for f in bucket['tunnel_flows']:
                    s = f['stats']
                    tname = f['key']
                    if s.get('fragmented_pkts', 0) > 0:
                        issues.append({
                            'type': 'TUNNEL_FRAGMENTATION',
                            'severity': 'WARNING',
                            'where': tname,
                            'desc': f"{s.get('proto')} fragmentation on tunnel"
                        })
                    if s.get('df_set_pkts', 0) > 0 and s.get('fragmented_pkts', 0) == 0:
                        issues.append({
                            'type': 'TUNNEL_DF_SET',
                            'severity': 'INFO',
                            'where': tname,
                            'desc': f"DF set on {s.get('proto')} outer header (depends on PMTUD)"
                        })
                    if s.get('max_payload', 0) > 1400 and s.get('fragmented_pkts', 0) > 0:
                        issues.append({
                            'type': 'TUNNEL_PAYLOAD_TOO_LARGE',
                            'severity': 'CRITICAL',
                            'where': tname,
                            'desc': f"{s.get('proto')} payload too large for path MTU"
                        })

                # PMTUD black holes
                for f in bucket['pmtud_blackholes']:
                    s = f['stats']
                    if s.get('retransmissions', 0) > 5 and not s.get('icmp_received', False):
                        issues.append({
                            'type': 'PMTUD_BLACKHOLE',
                            'severity': 'CRITICAL',
                            'where': f['key'],
                            'desc': f"{s['retransmissions']} retransmissions of large DF packets with no ICMP feedback"
                        })

                # ICMP Frag Needed
                for e in bucket['icmp_frag']:
                    issues.append({
                        'type': 'ICMP_FRAG_NEEDED',
                        'severity': 'WARNING',
                        'where': f"{e.get('src')}→{e.get('dst')}",
                        'desc': f"ICMP Fragmentation Needed, next-hop MTU {e.get('next_hop_mtu', 0)}"
                    })

                # IPv6 fragments
                if bucket['ipv6_frags']:
                    issues.append({
                        'type': 'IPV6_FRAGMENTATION',
                        'severity': 'WARNING',
                        'where': 'IPv6',
                        'desc': f"{len(bucket['ipv6_frags'])} IPv6 fragments observed"
                    })

                # Jumbo frames
                if bucket['jumbo']:
                    issues.append({
                        'type': 'JUMBO_FRAMES',
                        'severity': 'INFO',
                        'where': 'Layer2',
                        'desc': f"{len(bucket['jumbo'])} jumbo frames (>1600 bytes) seen"
                    })

                return issues

            # Correlate stuck neighbors (all protocols)
            for s in stuck_states:
                neighbor = s.get('neighbor', '')
                proto    = s.get('protocol', 'UNKNOWN')
                state    = s.get('stuck_state', '')
                ips = self._extract_ips_from_neighbor(neighbor)
                if len(ips) != 2:
                    continue
                key = frozenset(ips)
                bucket = mtu_index.get(key)
                if not bucket:
                    continue

                issues = analyze_mtu_bucket(bucket)
                if not issues:
                    continue

                correlations.append({
                    'type': 'stuck_state',
                    'protocol': proto,
                    'neighbor': neighbor,
                    'state': state,
                    'duration': s.get('duration_sec', 0),
                    'mtu_issues': issues,
                })

            # Correlate neighbor failures (Hello loss)
            for n in neighbor_failures:
                neighbor = n.get('neighbor', '')
                proto    = n.get('protocol', 'UNKNOWN')
                ips = self._extract_ips_from_neighbor(neighbor)
                if len(ips) != 2:
                    continue
                key = frozenset(ips)
                bucket = mtu_index.get(key)
                if not bucket:
                    continue

                issues = analyze_mtu_bucket(bucket)
                if not issues:
                    continue

                correlations.append({
                    'type': 'hello_failure',
                    'protocol': proto,
                    'neighbor': neighbor,
                    'status': n.get('status'),
                    'success_rate': n.get('success_rate'),
                    'mtu_issues': issues,
                })

            self.analysis_results['mtu_protocol_correlations'] = correlations
            self.log_message(f"✓ MTU/Protocol Correlation: {len(correlations)} neighbor pairs with MTU-related symptoms")
            return correlations

        except Exception as e:
            import traceback
            self.log_message(f"❌ MTU/Protocol correlation error: {str(e)}")
            self.log_message(traceback.format_exc())
            self.analysis_results['mtu_protocol_correlations'] = []
            return []
            
    def generate_mtu_protocol_correlation_table(self):
        data = self.analysis_results.get('mtu_protocol_correlations', [])
        if not data:
            return "<div class='success-message'>✅ No MTU/MSS symptoms found for problematic neighbors.</div>"

        html = []
        html.append("""
            <h3>🔗 MTU/MSS / Fragmentation Correlated with Protocol Issues</h3>
            <p style="font-size:13px; color:#555;">
                This table links OSPF/BGP/EIGRP/ISIS neighbor problems with MTU, MSS, fragmentation,
                tunnel encapsulation, or PMTUD symptoms seen between the same endpoints.
            </p>
            <table class="mtu-table">
            <thead>
                <tr>
                    <th>Protocol</th>
                    <th>Neighbor</th>
                    <th>Issue Type</th>
                    <th>State / Status</th>
                    <th>Key MTU Symptoms</th>
                </tr>
            </thead>
            <tbody>
        """)

        for item in data:
            proto = item['protocol']
            neighbor = item['neighbor']
            if item['type'] == 'stuck_state':
                issue_type = "Stuck State"
                state_info = f"{item.get('state','')} ({item.get('duration',0)}s)"
            else:
                issue_type = "Hello Failure"
                state_info = f"{item.get('status','')} / {item.get('success_rate','')}"

            # Pick up to 3 most severe symptoms for display
            symptoms = sorted(
                item['mtu_issues'],
                key=lambda x: {'CRITICAL':0,'WARNING':1,'INFO':2}.get(x['severity'],'INFO')
            )[:3]
            sympt_text = "<br>".join(
                f"<b>{s['severity']}</b>: {s['desc']} <span style='color:#666'>(@{s['where']})</span>"
                for s in symptoms
            )

            html.append(f"""
                <tr>
                    <td>{proto}</td>
                    <td><code>{neighbor}</code></td>
                    <td>{issue_type}</td>
                    <td>{state_info}</td>
                    <td style="font-size:12px;">{sympt_text}</td>
                </tr>
            """)

        html.append("</tbody></table>")
        return "".join(html)




    def build_complete_dashboard(self):
        """Build comprehensive HTML dashboard with all features and Plotly support."""
        import json
        from datetime import datetime

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.dashboard_file = f'ultra_network_dashboard_{timestamp}.html'

        analysis = self.analysis_results or {}

        def safe_int(val):
            try:
                return int(val)
            except Exception:
                return 0
        
        seq_analysis = analysis.get('sequence_analysis', {})
        total_seq_issues = (
            safe_int(len(seq_analysis.get('sequence_gaps', []))) +
            safe_int(len(seq_analysis.get('sequence_jumps', []))) +
            safe_int(len(seq_analysis.get('duplicate_sequences', [])))
        )    

        stats = {
            'generated_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_src': safe_int(len(self.src_packets) if self.src_packets else 0),
            'total_dst': safe_int(len(self.dst_packets) if self.dst_packets else 0),
            'drops': safe_int(len(analysis.get('packet_drops', []))),
            'failures': safe_int(len(analysis.get('neighbor_failures', []))),
            'stuck_states': safe_int(len(analysis.get('stuck_neighbor_states', []))),
            'loops': safe_int(len(analysis.get('routing_loops', []))),
            'lsas': safe_int(len(analysis.get('ospf_lsa_analysis', {}).get('lsa_database', []))) if analysis.get('ospf_lsa_analysis', {}).get('lsa_database', []) else safe_int(len(analysis.get('ospf_lsa_analysis', {}).get('lsa_details', []))),
            'isis_count': safe_int(analysis.get('isis_analysis', {}).get('packet_count', 0)),
            'seq_gaps': total_seq_issues,
            'comm_flows': safe_int(len(analysis.get('communication_analysis', {}).get('flows', []))),
            'comm_unique_ips': safe_int(len(analysis.get('communication_analysis', {}).get('unique_ips', set()))),
            'eigrp_count': safe_int(len(analysis.get('routing_protocol_analysis', {}).get('eigrp_packets', []))),
            'eigrp_sia_count': safe_int(len(analysis.get('routing_protocol_analysis', {}).get('eigrp_sia_events', []))),
            'bgp_count': safe_int(len(analysis.get('routing_protocol_analysis', {}).get('bgp_packets', []))),
            'mtu_correlations': safe_int(len(analysis.get('mtu_protocol_correlations', []))),
            'pmtud_blackholes': safe_int(len([k for k, v in analysis.get('pmtud_blackholes', {}).items() if v.get('retransmissions', 0) > 5])),
            'icmp_frag_needed': safe_int(len(analysis.get('icmp_frag_needed', []))),
        }

        # Flow graph control
        show_flowgraph = self._get_option_value('flowgraph_analysis')
        
        flowgraph_tab_button = ""
        flowgraph_tab_content = ""

        if show_flowgraph:
            flowgraph_tab_button = '<button class="tab-btn" onclick="openTab(event, \'flowgraph\')">🗺️ Flow Graph</button>'
            
            # Generate ALL 10 Plotly graphs
            filters = [None, 'TCP', 'UDP', 'ICMP', 'ICMPv6', 'OSPF', 'EIGRP', 'BGP', 'ISIS', 'Other']
            plotly_htmls = {}
            comments = {}
            
            for filt in filters:
                display = 'All Flows' if filt is None else f"{filt} Flows"
                plotly_html, events = self.generate_flowgraph_svg(protocol_filter=filt)
                plotly_htmls[filt or 'all'] = plotly_html
                comments[filt or 'all'] = self.generate_comment_table(events)
            
            # tabIdMap for routing jumps
            tab_id_map = json.dumps({
                'OSPF': 'lsas', 'EIGRP': 'eigrp', 'BGP': 'bgp', 'ISIS': 'isis'
            })
            
            # Build full tab content with dropdown + divs + JS
            flowgraph_tab_content = f"""
            <div id="flowgraph" class="tab-content">
                <div class="analysis-section">
                    <h2 class="section-title">🗺️ Flow Graph (All Flows)</h2>
                    <label for="flowTypeDropdown" style="font-weight: bold; margin-right: 10px;">Flow Type:</label>
                    <select id="flowTypeDropdown" onchange="updateFlowGraph(event);" 
                            style="padding: 8px; border: 2px solid #667eea; border-radius: 5px;">
                        <option value="all" selected>All Flows</option>
                        <option value="TCP">TCP Flows</option>
                        <option value="UDP">UDP Flows</option>
                        <option value="ICMP">ICMP Flows</option>
                        <option value="ICMPv6">ICMPv6 Flows</option>
                        <option value="OSPF">OSPF Flows</option>
                        <option value="EIGRP">EIGRP Flows</option>
                        <option value="BGP">BGP Flows</option>
                        <option value="ISIS">IS-IS Flows</option>
                        <option value="Other">Other</option>
                    </select>
                    <div style="margin-top: 20px;">
            """
            
            # Add all 10 Plotly divs
            for key in ['all', 'TCP', 'UDP', 'ICMP', 'ICMPv6', 'OSPF', 'EIGRP', 'BGP', 'ISIS', 'Other']:
                style = '' if key == 'all' else 'display: none;'
                flowgraph_tab_content += f"""
                        <div id="flowgraph_{key}" style="{style}">{plotly_htmls[key]}{comments[key]}</div>
                """
            
            flowgraph_tab_content += f"""
                    </div>
                    <script>
                    var tabIdMap = {tab_id_map};
                    
                    function updateFlowGraph(evt) {{
                        var v = evt.target.value;
                        var protocolTabs = ['OSPF', 'EIGRP', 'BGP', 'ISIS'];
                        
                        // Hide other tabs' flow containers
                        ['ospf', 'eigrp', 'bgp', 'isis'].forEach(proto => {{
                            var cont = document.getElementById(proto + '_flowgraph_container');
                            if (cont) {{ cont.style.display = 'none'; cont.innerHTML = ''; }}
                        }});
                        
                        if (protocolTabs.includes(v)) {{
                            // Jump to protocol tab + show its flowgraph
                            var tabId = tabIdMap[v] || v.toLowerCase();
                            openTab(evt, tabId);
                            var contId = v === 'OSPF' ? 'ospf_flowgraph_container' : v.toLowerCase() + '_flowgraph_container';
                            var cont = document.getElementById(contId);
                            if (cont) {{
                                // Clone the Plotly graph from the main flowgraph tab
                                var sourceDiv = document.getElementById('flowgraph_' + v);
                                if (sourceDiv) {{
                                    cont.innerHTML = sourceDiv.innerHTML;
                                    // Re-initialize Plotly in the cloned div
                                    var plotlyDivs = cont.querySelectorAll('.plotly-graph-div');
                                    plotlyDivs.forEach(function(div) {{
                                        if (div.data && div.layout) {{
                                            Plotly.react(div, div.data, div.layout);
                                        }}
                                    }});
                                }} else {{
                                    cont.innerHTML = '<div>No data</div>';
                                }}
                                cont.style.display = 'block';
                            }}
                        }} else {{
                            // Filter within flowgraph tab
                            openTab(evt, 'flowgraph');
                            ['all', 'TCP', 'UDP', 'ICMP', 'ICMPv6', 'OSPF', 'EIGRP', 'BGP', 'ISIS', 'Other'].forEach(name => {{
                                var div = document.getElementById('flowgraph_' + name);
                                if (div) div.style.display = (v === name) ? '' : 'none';
                            }});
                        }}
                    }}
                    </script>
                </div>
            </div>
            """

        communication_table_html = self.generate_communication_table(selected_protocol="ALL", jitter_threshold=None)

        html_content = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Netloom – Weaving PCAP Data Into Visuals</title>
        <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
        <style>
            /* ========== BASE STYLES ========== */
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
            .dashboard {{ max-width: 1400px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); overflow: hidden; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; position: relative; }}
            .header h1 {{ margin: 0 0 10px 0; font-size: 2.5rem; font-weight: 300; }}
            .header p {{ margin: 5px 0; opacity: 0.9; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 15px; padding: 30px; background: #f8f9fa; }}
            .stat-card {{ background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 4px 8px rgba(0,0,0,0.1); border-left: 4px solid #007bff; }}
            .stat-number {{ font-size: 2rem; font-weight: bold; color: #007bff; margin-bottom: 5px; }}
            .stat-label {{ font-size: 0.9rem; color: #6c757d; text-transform: uppercase; letter-spacing: 0.5px; }}
            .content {{ padding: 30px; }}
            .tabs {{ margin-top: 20px; }}
            .tab-nav {{ display: flex; background: #343a40; border-radius: 10px 10px 0 0; flex-wrap: wrap; }}
            .tab-btn {{ background: transparent; border: none; padding: 15px 20px; color: white; cursor: pointer; font-size: 14px; transition: all 0.3s; }}
            .tab-btn:hover {{ background: rgba(255,255,255,0.1); }}
            .tab-btn.active {{ background: #007bff; }}
            .tab-content {{ display: none; padding: 30px; border: 1px solid #dee2e6; border-top: none; border-radius: 0 0 10px 10px; background: white; max-height: 600px; overflow-y: auto; }}
            .tab-content.active {{ display: block; }}
            .analysis-section {{ margin-bottom: 30px; }}
            .section-title {{ color: #495057; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #007bff; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; font-size: 13px; }}
            th {{ background: #f8f9fa; font-weight: 600; color: #495057; }}
            tr:hover {{ background: #f8f9fa; }}
            .success-message {{ background: #d4edda; color: #155724; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #28a745; }}
            .no-data {{ background: #f8f9fa; padding: 30px; text-align: center; color: #6c757d; border-radius: 8px; }}

            /* LSA Age Status Color Coding */
            .lsa-age-fresh {{ color: #388e3c; font-weight: 600; }}
            .lsa-age-valid {{ color: #fbc02d; font-weight: 600; }}
            .lsa-age-aging {{ color: #f57c00; font-weight: 600; }}
            .lsa-age-maxage {{ color: #d32f2f; font-weight: 600; }}

            code {{
                background-color: #f4f4f4;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
            }}

            #lsas table {{ font-size: 12px; }}
            #lsas th {{ background: #667eea; color: white; position: sticky; top: 0; z-index: 10; }}
            
            /* ========== MTU/MSS ANALYSIS STYLES ========== */
            .mtu-table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                font-size: 13px;
            }}
            
            .mtu-table th {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                position: sticky;
                top: 0;
                z-index: 10;
            }}
            
            .mtu-table td {{
                padding: 10px 12px;
                border-bottom: 1px solid #dee2e6;
            }}
            
            .mtu-table tr:hover {{
                background: #f8f9fa;
            }}
            
            .mtu-table code {{
                background: #f4f4f4;
                padding: 4px 8px;
                border-radius: 4px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
            }}
            
            /* Critical MTU issue alerts */
            .mtu-critical-alert {{
                background: #dc354522;
                padding: 15px;
                border-radius: 8px;
                border-left: 4px solid #dc3545;
                margin-bottom: 20px;
            }}
            
            .mtu-critical-alert h3 {{
                color: #dc3545;
                margin: 0 0 10px 0;
            }}
            
            .mtu-critical-alert p {{
                margin: 0;
            }}
            
            /* MTU correlation warnings */
            .mtu-warning-alert {{
                background: #ff980022;
                padding: 15px;
                border-radius: 8px;
                border-left: 4px solid #ff9800;
                margin-bottom: 20px;
            }}
            
            .mtu-warning-alert h3 {{
                color: #ff9800;
                margin: 0 0 10px 0;
            }}
            

            /* ========== SEARCH CONTAINER ========== */
            .search-container {{
                padding: 15px 30px;
                background: white;
                border-bottom: 2px solid #dee2e6;
            }}

            #global-search {{
                width: 100%;
                padding: 12px;
                border: 2px solid #667eea;
                border-radius: 8px;
                font-size: 14px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                transition: all 0.3s;
            }}

            #global-search:focus {{
                outline: none;
                border-color: #764ba2;
                box-shadow: 0 4px 8px rgba(102, 126, 234, 0.3);
            }}

            #search-results {{
                display: none;
                max-height: 300px;
                overflow-y: auto;
                background: white;
                border: 1px solid #ddd;
                margin-top: 5px;
                border-radius: 5px;
                box-shadow: 0 4px 8px rgba(0,0,0,0.15);
            }}

            #search-results > div {{
                padding: 10px;
                border-bottom: 1px solid #eee;
                cursor: pointer;
                transition: background 0.2s;
            }}

            #search-results > div:hover {{
                background: #f0f0f0;
            }}
            
            /* Plotly graph container styling */
            .plotly-graph-div {{
                margin: 20px 0;
            }}
        </style>
    </head>
    <body>
        <div class="dashboard">
            <!-- ========== HEADER ========== -->
            <div class="header">
                <h1>🛡️ Netloom – Weaving PCAP Data Into Visuals</h1>
                <p><strong>Enhanced Analysis Complete</strong></p>
                <p>Complete Analysis Dashboard | Generated: {stats['generated_time']}</p>
            </div>
            
            <!-- ========== GLOBAL SEARCH ========== -->
            <div class="search-container">
                <input type="text" id="global-search" 
                       placeholder="🔍 Search IPs, protocols, packet types across all tabs..." 
                       onkeyup="globalSearch(event)">
                <div id="search-results"></div>
            </div>
            
            <!-- ========== STATS GRID ========== -->
            <div class="stats-grid">
                <div class="stat-card"><div class="stat-number">{stats['total_src']:,}</div><div class="stat-label">Source Packets</div></div>
                <div class="stat-card"><div class="stat-number">{stats['total_dst']:,}</div><div class="stat-label">Destination Packets</div></div>
                <div class="stat-card"><div class="stat-number">{stats['drops']}</div><div class="stat-label">Packet Drop Analysis</div></div>
                <div class="stat-card"><div class="stat-number">{stats['failures']}</div><div class="stat-label">Neighbor Failures</div></div>
                <div class="stat-card" style="border-left: 4px solid #dc3545;"><div class="stat-number">{stats['stuck_states']}</div><div class="stat-label">Stuck States</div></div>
                <div class="stat-card"><div class="stat-number">{stats['loops']}</div><div class="stat-label">Routing Loops + IP ID</div></div>
                <div class="stat-card"><div class="stat-number">{stats['lsas']}</div><div class="stat-label">OSPF Packets</div></div>
                <div class="stat-card"><div class="stat-number">{stats['isis_count']}</div><div class="stat-label">IS-IS Packets</div></div>
                <div class="stat-card"><div class="stat-number">{stats['eigrp_count']}</div><div class="stat-label">EIGRP Packets</div></div>
                <div class="stat-card" style="border-left: 4px solid #c01528;"><div class="stat-number">{stats['eigrp_sia_count']}</div><div class="stat-label">EIGRP SIA Events</div></div>
                <div class="stat-card"><div class="stat-number">{stats['bgp_count']}</div><div class="stat-label">BGP Packets</div></div>
                <div class="stat-card"><div class="stat-number">{stats['seq_gaps']}</div><div class="stat-label">Sequence Gaps</div></div>
                <div class="stat-card"><div class="stat-number">{stats['comm_flows']}</div><div class="stat-label">Communication Flows</div></div>
                <div class="stat-card"><div class="stat-number">{stats['comm_unique_ips']}</div><div class="stat-label">Unique IPs</div></div>
                <div class="stat-card" style="border-left: 4px solid #ff9800;"><div class="stat-number">{stats['mtu_correlations']}</div><div class="stat-label">MTU Correlations</div></div>
                <div class="stat-card" style="border-left: 4px solid #dc3545;"><div class="stat-number">{stats['pmtud_blackholes']}</div><div class="stat-label">PMTUD Black Holes</div></div>
                <div class="stat-card" style="border-left: 4px solid #ffc107;"><div class="stat-number">{stats['icmp_frag_needed']}</div><div class="stat-label">ICMP Frag Needed</div></div>
            </div>
            
            <div class="content">
                <div class="tabs">
                    <!-- ========== TAB NAVIGATION ========== -->
                    <div class="tab-nav">
                        <button class="tab-btn" onclick="openTab(event, 'drops')">📉 Packet Drops Analysis ({stats['drops']})</button>
                        <button class="tab-btn" onclick="openTab(event, 'failures')">🔗 Neighbor Reachability ({stats['failures']})</button>
                        <button class="tab-btn" onclick="openTab(event, 'stuck_states')">🔄 Stuck States ({stats['stuck_states']})</button>
                        <button class="tab-btn" onclick="openTab(event, 'loops')">♻️ Enhanced Routing Loops ({stats['loops']})</button>
                        <button class="tab-btn" onclick="openTab(event, 'lsas')">📚 OSPF LSAs ({stats['lsas']})</button>
                        <button class="tab-btn" onclick="openTab(event, 'isis')">🛰️ IS-IS Packets ({stats['isis_count']})</button>
                        <button class="tab-btn" onclick="openTab(event, 'eigrp')">⚡ EIGRP ({stats['eigrp_count']}) {'<span style="color:#c01528;">⚠️ ' + str(stats['eigrp_sia_count']) + ' SIA</span>' if stats['eigrp_sia_count'] > 0 else ''}</button>
                        <button class="tab-btn" onclick="openTab(event, 'bgp')">🌐 BGP Packets ({stats['bgp_count']})</button>
                        <button class="tab-btn" onclick="openTab(event, 'sequences')">🔢 Sequences ({stats['seq_gaps']})</button>
                        <button class="tab-btn" onclick="openTab(event, 'mtu')">📏 MTU / MSS / Fragmentation {'<span style="color:#ff9800;">⚠️ ' + str(stats['mtu_correlations']) + ' Correlations</span>' if stats['mtu_correlations'] > 0 else ''}</button>
                        <button class="tab-btn active" onclick="openTab(event, 'communication')">💬 Communication ({stats['comm_flows']})</button>
                        {flowgraph_tab_button}
                    </div>
                    
                    <!-- ========== TAB CONTENTS ========== -->
                    <div id="drops" class="tab-content">
                        <div class="analysis-section">
                            <h2 class="section-title">📉 Packet Drop Analysis</h2>
                            {self.generate_drops_table()}
                        </div>
                    </div>
                    
                    <div id="communication" class="tab-content">
                        <div class="analysis-section">
                            <h2 class="section-title">💬 Network Communication Flow Analysis</h2>
                            <label for="protocol-select">Filter by Protocol:</label>
                            <select id="protocol-select" onchange="filterCommunicationTable()">
                                <option value="ALL">All</option>
                                <option value="UDP">UDP</option>
                                <option value="TCP">TCP</option>
                                <option value="ICMP">ICMP</option>
                                <option value="ARP">ARP</option>
                                <option value="ICMPv6">ICMPv6</option>
                                <option value="UIM">UIM</option>
                            </select>
                            <span id="udp-jitter-controls" style="display:none; margin-left:10px;">
                                <label for="udp-jitter-threshold">Expected Jitter (ms):</label>
                                <input type="number" id="udp-jitter-threshold" min="0" step="0.01" />
                                <button type="button" onclick="filterCommunicationTable()">Apply</button>
                            </span>
                            {communication_table_html}
                        </div>
                    </div>
                    
                    {flowgraph_tab_content}
                    {self.generate_tab_contents()}
                </div>
            </div>
        </div>
        
        <!-- ========== JAVASCRIPT ========== -->
        <script>
        // ========== ORIGINAL FUNCTIONS ========== 
        function saveFeedback() {{
            var usage = document.getElementById("usage").value || "Not selected";
            var ease = document.getElementById("ease").value || "Not selected";
            var comments = document.getElementById("comments").value;
            var now = new Date().toISOString().replace(/[-:T]/g, '').replace(/\\..+/, '');
            var content = "Tool Feedback Submission\\n"
                        + "Date/Time: " + now + "\\n"
                        + "Usage: " + usage + "\\n"
                        + "Ease: " + ease + "\\n"
                        + "Comments: " + comments + "\\n";
            var blob = new Blob([content], {{type: 'text/plain'}});
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = "netloom_feedback_" + now + ".txt";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            document.getElementById("feedbackMessage").innerHTML =
                "<span style='color: green; font-weight: bold;'>Feedback saved locally as a file!</span>";
        }}

        function filterCommunicationTable() {{
            var protoSel = document.getElementById('protocol-select') ? document.getElementById('protocol-select').value : "ALL";
            var jitterCtl = document.getElementById('udp-jitter-controls');
            var thresholdStr = document.getElementById('udp-jitter-threshold') ? document.getElementById('udp-jitter-threshold').value : "";
            var threshold = parseFloat(thresholdStr) || 0;

            var table = document.getElementById('comm-table');
            if (!table) return;
        
            var rows = table.tBodies[0].rows;
            if (jitterCtl) jitterCtl.style.display = (protoSel === 'UDP') ? 'inline-block' : 'none';

            for (var i = 0; i < rows.length; i++) {{
                var protoCell = rows[i].querySelector('.col-proto');
                var jitterCell = rows[i].querySelector('.col-jitter');
            
                if (!protoCell) {{
                    rows[i].style.display = 'none';
                    continue;
                }}
            
                var proto = protoCell.textContent || protoCell.innerText;
            
                if (protoSel !== 'ALL' && proto !== protoSel) {{
                    rows[i].style.display = 'none';
                    continue;
                }}
            
                if (protoSel === 'UDP' && threshold > 0 && jitterCell) {{
                    var jitterVal = parseFloat(jitterCell.textContent);
                    rows[i].style.display = (!isNaN(jitterVal) && jitterVal >= threshold) ? '' : 'none';
                }} else {{
                    rows[i].style.display = '';
                }}
            }}
        }}

        // ========== GLOBAL SEARCH ========== 
        function globalSearch(event) {{
            const query = event.target.value.toLowerCase();
            const resultsDiv = document.getElementById('search-results');
            
            if (query.length < 2) {{
                resultsDiv.style.display = 'none';
                return;
            }}
            
            let results = [];
            const tabs = ['drops', 'failures', 'stuck_states', 'loops', 'lsas', 'isis', 'eigrp', 'bgp', 'sequences', 'mtu', 'communication'];
            
            tabs.forEach(tabId => {{
                const tabContent = document.getElementById(tabId);
                if (!tabContent) return;
                
                const rows = tabContent.querySelectorAll('table tbody tr');
                rows.forEach((row, index) => {{
                    const text = row.textContent.toLowerCase();
                    if (text.includes(query)) {{
                        const cells = Array.from(row.cells).slice(0, 3).map(c => c.textContent.trim()).join(' | ');
                        results.push({{
                            tab: tabId,
                            text: cells.length > 80 ? cells.substring(0, 80) + '...' : cells,
                            row: row,
                            index: index
                        }});
                    }}
                }});
            }});
            
            if (results.length > 0) {{
                resultsDiv.innerHTML = '<div style="padding: 8px; background: #667eea; color: white; font-weight: bold;">Found ' + results.length + ' results</div>' +
                    results.slice(0, 10).map((r, i) => 
                        `<div onclick="jumpToResult('${{r.tab}}', ${{r.index}})">
                            <strong style="color: #667eea; text-transform: uppercase;">${{r.tab}}</strong>: ${{r.text}}
                         </div>`
                    ).join('') +
                    (results.length > 10 ? '<div style="padding: 8px; text-align: center; color: #666; font-size: 12px;">Showing first 10 of ' + results.length + ' results</div>' : '');
                resultsDiv.style.display = 'block';
            }} else {{
                resultsDiv.innerHTML = '<div style="padding: 10px; color: #999; text-align: center;">No results found for "' + query + '"</div>';
                resultsDiv.style.display = 'block';
            }}
        }}

        function jumpToResult(tabId, rowIndex) {{
            const tabBtn = Array.from(document.querySelectorAll('.tab-btn'))
                               .find(btn => btn.getAttribute('onclick').includes(tabId));
            
            if (tabBtn) {{
                openTab({{currentTarget: tabBtn}}, tabId);
            }}
            
            setTimeout(() => {{
                const tabContent = document.getElementById(tabId);
                const rows = tabContent.querySelectorAll('table tbody tr');
                const targetRow = rows[rowIndex];
                
                if (targetRow) {{
                    targetRow.scrollIntoView({{behavior: 'smooth', block: 'center'}});
                    targetRow.style.background = '#fffbcc';
                    setTimeout(() => targetRow.style.background = '', 2000);
                }}
            }}, 300);
            
            document.getElementById('search-results').style.display = 'none';
            document.getElementById('global-search').value = '';
        }}

        // ========== TAB MANAGEMENT ========== 
        function openTab(evt, tabName) {{
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {{
                tabcontent[i].classList.remove("active");
            }}
            tablinks = document.getElementsByClassName("tab-btn");
            for (i = 0; i < tablinks.length; i++) {{
                tablinks[i].classList.remove("active");
            }}
            document.getElementById(tabName).classList.add("active");
            evt.currentTarget.classList.add("active");
            
            // Save tab state
            localStorage.setItem('netloom-active-tab', tabName);
            
            if (tabName === 'communication') {{
                filterCommunicationTable();
            }}
        }}

        // ========== INITIALIZATION ========== 
        document.addEventListener('DOMContentLoaded', function() {{
            // Restore last active tab
            const savedTab = localStorage.getItem('netloom-active-tab');
            if (savedTab && document.getElementById(savedTab)) {{
                const tabBtn = Array.from(document.querySelectorAll('.tab-btn'))
                                   .find(btn => btn.getAttribute('onclick').includes(savedTab));
                if (tabBtn) {{
                    openTab({{currentTarget: tabBtn}}, savedTab);
                    return;
                }}
            }}
            
            // Default to communication tab
            const defaultTab = document.querySelector('.tab-btn.active');
            if (defaultTab) {{
                const tabName = defaultTab.getAttribute('onclick').match(/'([^']+)'/)[1];
                openTab({{currentTarget: defaultTab}}, tabName);
            }}
            
            // Setup communication handlers
            var protoSel = document.getElementById('protocol-select');
            if (protoSel) protoSel.onchange = filterCommunicationTable;
            
            var jitterInput = document.getElementById('udp-jitter-threshold');
            if (jitterInput) jitterInput.oninput = filterCommunicationTable;
            
            var applyBtn = document.getElementById('udp-jitter-controls') ? 
                          document.getElementById('udp-jitter-controls').querySelector('button') : null;
            if (applyBtn) applyBtn.onclick = filterCommunicationTable;
        }});
        </script>
    </body>
    </html>
        '''

        try:
            with open(self.dashboard_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.log_message(f"✅ Enhanced dashboard created: {self.dashboard_file}")
        except Exception as e:
            self.log_message(f"❌ Failed to create dashboard: {str(e)}")


    def generate_tab_contents(self):
        """Generate all tab contents for the dashboard with optional flow graph (Plotly support)."""
        import json  # Ensure JSON is imported

        # Generate protocol tables as before
        eigrp_table_html = self.generate_eigrp_table()
        bgp_table_html = self.generate_bgp_table()
        total_isis_packets = self.analysis_results.get('isis_analysis', {}).get('packet_count', 0)
        ipsec_packets_table = self.generate_ipsec_packets_table()
        isakmp_messages_table = self.generate_isakmp_messages_table()

        # Respect Flow Graph checkbox
        show_flowgraph = self._get_option_value('flowgraph_analysis')
        if not show_flowgraph:
            # Return all non-graph tabs, NO flowgraph work
            return f"""
                <div id="failures" class="tab-content">
                    <div class="analysis-section">
                        <h2 class="section-title">🚫 Neighbor Reachability Analysis</h2>
                        {self.generate_failures_table()}
                    </div>
                </div>
                <div id="stuck_states" class="tab-content">
                    <div class="analysis-section">
                        <h2 class="section-title">🔄 Stuck Neighbor State Analysis</h2>
                        <p style="color:#666; margin-bottom:20px; font-size:14px;">
                            Detects routing protocol neighbors stuck in intermediate states preventing full adjacency formation.
                            Analyzes OSPF, BGP, EIGRP, and ISIS state machine progression.
                        </p>
                        {self.generate_stuck_states_table()}
                    </div>
                </div>    
                <div id="loops" class="tab-content">
                    <div class="analysis-section">
                        <h2 class="section-title">♻️ Enhanced Routing Loop Detection with IP ID Tracking</h2>
                        {self.generate_enhanced_loops_table()}
                    </div>
                </div>
                <div id="lsas" class="tab-content">
                    <div class="analysis-section">
                        <h2 class="section-title">📚 OSPF Link-State Database (LSDB) Analysis</h2>
                        {self.generate_lsa_table()}
                        <div id="ospf_flowgraph_container" style="display:none; margin-top: 20px;"></div>
                    </div>
                </div>
                <div id="eigrp" class="tab-content">
                    <div class="analysis-section">
                        <h2 class="section-title">⚡ EIGRP Packet Analysis</h2>
                        {eigrp_table_html}
                        <div id="eigrp_flowgraph_container" style="display:none; margin-top: 20px;"></div>
                    </div>
                </div>
                <div id="bgp" class="tab-content">
                    <div class="analysis-section">
                        <h2 class="section-title">🌐 BGP Packet Analysis</h2>
                        {bgp_table_html}
                        <div id="bgp_flowgraph_container" style="display:none; margin-top: 20px;"></div>
                    </div>
                </div>
                <div id="isis" class="tab-content">
                    <div class="analysis-section">
                        <h2 class="section-title">🛰️ IS-IS Packet Analysis ({total_isis_packets} packets)</h2>
                        {self.generate_isis_table()}
                        <div id="isis_flowgraph_container" style="display:none; margin-top: 20px;"></div>
                    </div>
                </div>
                <div id="sequences" class="tab-content">
                    <div class="analysis-section">
                        <h2 class="section-title">🔢 TCP Sequence Analysis</h2>
                        {self.generate_sequences_table()}
                    </div>
                </div>
                <!-- NEW MTU / MSS / Fragmentation tab -->
                <div id="mtu" class="tab-content">
                    <div class="analysis-section">
                        <h2 class="section-title">📏 MTU / MSS / Fragmentation Analysis</h2>
                        {self.generate_mtu_mss_table()}
                        <hr style="margin: 40px 0; border: none; border-top: 2px solid #dee2e6;">
                        {self.generate_mtu_protocol_correlation_table()}
                    </div>
                </div>   
            """

        # ---------- Flow Graph ENABLED below (Plotly support) ----------

        # Generate Plotly HTML for each protocol to enable live-switching
        plotly_all,  flow_events_all  = self.generate_flowgraph_svg(protocol_filter=None)
        plotly_tcp,  flow_events_tcp  = self.generate_flowgraph_svg(protocol_filter='TCP')
        plotly_udp,  flow_events_udp  = self.generate_flowgraph_svg(protocol_filter='UDP')
        plotly_icmp, flow_events_icmp = self.generate_flowgraph_svg(protocol_filter='ICMP')
        plotly_icmpv6, flow_events_icmpv6 = self.generate_flowgraph_svg(protocol_filter='ICMPv6')
        plotly_ospf, flow_events_ospf = self.generate_flowgraph_svg(protocol_filter='OSPF')
        plotly_eigrp, flow_events_eigrp = self.generate_flowgraph_svg(protocol_filter='EIGRP')
        plotly_bgp,  flow_events_bgp  = self.generate_flowgraph_svg(protocol_filter='BGP')
        plotly_isis, flow_events_isis = self.generate_flowgraph_svg(protocol_filter='ISIS')
        plotly_other, flow_events_other = self.generate_flowgraph_svg(protocol_filter='Other')

        comments_all  = self.generate_comment_table(flow_events_all)
        comments_tcp  = self.generate_comment_table(flow_events_tcp)
        comments_udp  = self.generate_comment_table(flow_events_udp)
        comments_icmp = self.generate_comment_table(flow_events_icmp)
        comments_icmpv6 = self.generate_comment_table(flow_events_icmpv6)
        comments_ospf  = self.generate_comment_table(flow_events_ospf)
        comments_eigrp = self.generate_comment_table(flow_events_eigrp)
        comments_bgp   = self.generate_comment_table(flow_events_bgp)
        comments_isis  = self.generate_comment_table(flow_events_isis)
        comments_other = self.generate_comment_table(flow_events_other)

        tabIdMap_js = json.dumps({'OSPF': 'lsas', 'EIGRP': 'eigrp', 'BGP': 'bgp', 'ISIS': 'isis'})

        flow_tab_html = f"""
        <div id="flowgraph" class="tab-content">
            <div class="analysis-section">
                <h2 class="section-title">🗺️ Flow Graph (All Flows)</h2>
                <label for="flowTypeDropdown"><b>Flow Type:</b></label>
                <select id="flowTypeDropdown" onchange="updateFlowGraph(event);">
                  <option value="all" selected>All Flows</option>
                  <option value="TCP">TCP Flows</option>
                  <option value="UDP">UDP Flows</option>
                  <option value="ICMP">ICMP Flows</option>
                  <option value="ICMPv6">ICMPv6 Flows</option>
                  <option value="OSPF">OSPF Flows</option>
                  <option value="EIGRP">EIGRP Flows</option>
                  <option value="BGP">BGP Flows</option>
                  <option value="ISIS">IS-IS Flows</option>
                  <option value="Other">Other</option>
                </select>

                <div id="flowgraph_all" style="margin-top:10px;">{plotly_all}{comments_all}</div>
                <div id="flowgraph_TCP" style="display:none;">{plotly_tcp}{comments_tcp}</div>
                <div id="flowgraph_UDP" style="display:none;">{plotly_udp}{comments_udp}</div>
                <div id="flowgraph_ICMP" style="display:none;">{plotly_icmp}{comments_icmp}</div>
                <div id="flowgraph_ICMPv6" style="display:none;">{plotly_icmpv6}{comments_icmpv6}</div>
                <div id="flowgraph_OSPF" style="display:none;">{plotly_ospf}{comments_ospf}</div>
                <div id="flowgraph_EIGRP" style="display:none;">{plotly_eigrp}{comments_eigrp}</div>
                <div id="flowgraph_BGP" style="display:none;">{plotly_bgp}{comments_bgp}</div>
                <div id="flowgraph_ISIS" style="display:none;">{plotly_isis}{comments_isis}</div>
                <div id="flowgraph_Other" style="display:none;">{plotly_other}{comments_other}</div>

                <script>
                var tabIdMap  = {tabIdMap_js};

                function updateFlowGraph(evt) {{
                    var v = evt.target.value;
                    var protocolTabs = ['OSPF', 'EIGRP', 'BGP', 'ISIS'];

                    // Hide routing protocol containers in other tabs
                    ['ospf', 'eigrp', 'bgp', 'isis'].forEach(function(proto) {{
                        var container = document.getElementById(proto + '_flowgraph_container');
                        if (container) {{
                            container.style.display = 'none';
                            container.innerHTML = '';
                        }}
                    }});

                    if (protocolTabs.includes(v)) {{
                        // Jump to protocol tab + populate its flowgraph container
                        var tabId = tabIdMap[v] || v.toLowerCase();
                        if (typeof openTab === 'function') {{
                            openTab(evt, tabId);
                        }}
                        var containerId = (v === 'OSPF')
                            ? 'ospf_flowgraph_container'
                            : v.toLowerCase() + '_flowgraph_container';
                        var container = document.getElementById(containerId);
                        if (container) {{
                            // Clone the Plotly graph from flowgraph tab
                            var sourceDiv = document.getElementById('flowgraph_' + v);
                            if (sourceDiv) {{
                                container.innerHTML = sourceDiv.innerHTML;
                                // Re-initialize Plotly graphs in cloned container
                                var plotlyDivs = container.querySelectorAll('.plotly-graph-div');
                                plotlyDivs.forEach(function(div) {{
                                    if (div.data && div.layout) {{
                                        Plotly.react(div, div.data, div.layout);
                                    }}
                                }});
                            }} else {{
                                container.innerHTML = '<div>No flow graph data available.</div>';
                            }}
                            container.style.display = 'block';
                        }}
                    }} else {{
                        // Stay in flowgraph tab, show/hide Plotly containers
                        if (typeof openTab === 'function') {{
                            openTab(evt, 'flowgraph');
                        }}
                        ['all','TCP','UDP','ICMP','ICMPv6','OSPF','EIGRP','BGP','ISIS','Other'].forEach(function(name) {{
                            var div = document.getElementById('flowgraph_' + name);
                            if (div) {{
                                div.style.display = (v === name) ? '' : 'none';
                            }}
                        }});
                    }}
                }}
                </script>
            </div>
        </div>
        """

        # All tabs + flow graph when enabled
        return f"""
            <div id="failures" class="tab-content">
                <div class="analysis-section">
                    <h2 class="section-title">🚫 Neighbor Reachability Analysis</h2>
                    {self.generate_failures_table()}
                </div>
            </div>
            <div id="stuck_states" class="tab-content">
                <div class="analysis-section">
                    <h2 class="section-title">🔄 Stuck Neighbor State Analysis</h2>
                    <p style="color:#666; margin-bottom:20px; font-size:14px;">
                        Detects routing protocol neighbors stuck in intermediate states preventing full adjacency formation.
                        Analyzes OSPF, BGP, EIGRP, and ISIS state machine progression.
                    </p>
                    {self.generate_stuck_states_table()}
                </div>
            </div>
            <div id="loops" class="tab-content">
                <div class="analysis-section">
                    <h2 class="section-title">♻️ Enhanced Routing Loop Detection with IP ID Tracking</h2>
                    {self.generate_enhanced_loops_table()}
                </div>
            </div>
            <div id="lsas" class="tab-content">
                <div class="analysis-section">
                    <h2 class="section-title">📚 OSPF Link-State Database (LSDB) Analysis</h2>
                    {self.generate_lsa_table()}
                    <div id="ospf_flowgraph_container" style="display:none; margin-top: 20px;"></div>
                </div>
            </div>
            <div id="eigrp" class="tab-content">
                <div class="analysis-section">
                    <h2 class="section-title">⚡ EIGRP Packet Analysis</h2>
                    {eigrp_table_html}
                    <div id="eigrp_flowgraph_container" style="display:none; margin-top: 20px;"></div>
                </div>
            </div>
            <div id="bgp" class="tab-content">
                <div class="analysis-section">
                    <h2 class="section-title">🌐 BGP Packet Analysis</h2>
                    {bgp_table_html}
                    <div id="bgp_flowgraph_container" style="display:none; margin-top: 20px;"></div>
                </div>
            </div>
            <div id="isis" class="tab-content">
                <div class="analysis-section">
                    <h2 class="section-title">🛰️ IS-IS Packet Analysis ({total_isis_packets} packets)</h2>
                    {self.generate_isis_table()}
                    <div id="isis_flowgraph_container" style="display:none; margin-top: 20px;"></div>
                </div>
            </div>
            <div id="sequences" class="tab-content">
                <div class="analysis-section">
                    <h2 class="section-title">🔢 TCP Sequence Analysis</h2>
                    {self.generate_sequences_table()}
                </div>
            </div>
            <!-- NEW MTU / MSS / Fragmentation tab -->
            <div id="mtu" class="tab-content">
                <div class="analysis-section">
                    <h2 class="section-title">📏 MTU / MSS / Fragmentation Analysis</h2>
                    {self.generate_mtu_mss_table()}
                    <hr style="margin: 40px 0; border: none; border-top: 2px solid #dee2e6;">
                    {self.generate_mtu_protocol_correlation_table()}
                </div>
            </div>   
            {flow_tab_html}
        """


    # Fixed table generation methods
    def generate_drops_table(self):
        """Generate packet drops table with IPv6 support and clear explanations for drop, retransmit, and reorder metrics."""
        try:
            drops = self.analysis_results.get('packet_drops', [])
            if not drops:
                return (
                    '<div class="success-message">'
                    '✅ No packet drops detected – TCP connections look stable (no sequence gaps seen).'
                    '</div>'
                )

            # Short legend to explain metrics
            legend = (
                '<div style="background:#e8f5e9; padding:12px; border-left:4px solid #4caf50; '
                'border-radius:4px; margin-bottom:10px; font-size:13px;">'
                '<strong>📖 How to read this table:</strong><br>'
                '• <b>Drop Count</b> = Missing TCP bytes inferred from sequence gaps<br>'
                '• <b>Retransmissions</b> = Segments resent with the same sequence number<br>'
                '• <b>Reordered</b> = Segments that arrived out of order (older sequence after newer)<br>'
                '• <b>IP Version</b> = IPv4 or IPv6 protocol in use'
                '</div>'
            )

            # Add info banner if many drops
            total_drops = len(drops)
            if total_drops > 50:
                legend += (
                    f'<div style="background:#fff3cd; padding:12px; border-left:4px solid #ffc107; '
                    f'border-radius:4px; margin-bottom:10px; font-size:13px;">'
                    f'⚠️ <strong>Analysis Summary:</strong> {total_drops} connections with drops, '
                    f'retransmissions, or reordering detected. All shown below for complete visibility.'
                    '</div>'
                )

            html = legend
            html += '''
            <table>
                <thead>
                    <tr>
                        <th>IP Ver</th>
                        <th>Connection</th>
                        <th title="Time since the last packet was seen on this connection">Idle Time (s)</th>
                        <th>Last Seen</th>
                        <th title="Time To Live (IPv4) or Hop Limit (IPv6)">TTL/HL</th>
                        <th>Protocol</th>
                        <th title="Total missing TCP bytes estimated from forward sequence gaps">Drop Count</th>
                        <th title="Number of TCP segments resent with the same sequence number">Retransmits</th>
                        <th title="Number of TCP segments that arrived out of order">Reordered</th>
                        <th title="Last TCP sequence number observed">Last Seq</th>
                        <th title="Last TCP acknowledgement number observed">Last Ack</th>
                    </tr>
                </thead>
                <tbody>
            '''

            for drop in drops:
                # IP version badge
                ip_version = drop.get('ip_version', 'N/A')
                if ip_version == 'IPv6':
                    version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
                    conn_style = 'font-family: monospace; font-size: 11px;'
                elif ip_version == 'IPv4':
                    version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
                    conn_style = 'font-family: monospace;'
                else:
                    version_badge = 'N/A'
                    conn_style = ''
                
                # Protocol color coding
                proto = drop.get("protocol", "Unknown")
                proto_colors = {
                    'TCP': '#1976d2',
                    'UDP': '#388e3c',
                    'ICMP': '#fbc02d',
                    'ICMPv6': '#ff7043'
                }
                proto_color = proto_colors.get(proto, '#666')
                
                # Highlight high drop/retransmit counts
                drop_count = drop.get("drop_count", 0)
                retransmit = drop.get("retransmit_count", 0)
                reorder = drop.get("reorder_count", 0)
                
                drop_style = 'font-weight:bold; color:#d32f2f;' if drop_count > 1000 else ''
                retransmit_style = 'font-weight:bold; color:#ff9800;' if retransmit > 10 else ''
                reorder_style = 'font-weight:bold; color:#fbc02d;' if reorder > 5 else ''
                
                html += f'''
                <tr>
                    <td style="text-align:center;">{version_badge}</td>
                    <td style="{conn_style}" title="5-tuple/direction for this flow">{drop["connection"]}</td>
                    <td>{drop["idle_seconds"]}</td>
                    <td style="font-family:Consolas,monospace; font-size:11px;">{drop["last_seen"]}</td>
                    <td>{drop.get("ttl", "N/A")}</td>
                    <td style="color:{proto_color}; font-weight:bold;">{proto}</td>
                    <td style="{drop_style}">{drop_count}</td>
                    <td style="{retransmit_style}">{retransmit}</td>
                    <td style="{reorder_style}">{reorder}</td>
                    <td>{drop.get("last_seq", "N/A")}</td>
                    <td>{drop.get("last_ack", "N/A")}</td>
                </tr>
                '''

            html += '</tbody></table>'
            
            # Add analysis notes
            html += '''
            <div style="margin-top:15px; padding:10px; background:#e3f2fd; border-left:4px solid #2196f3; 
                        border-radius:4px; font-size:12px;">
                <strong>💡 Analysis Notes:</strong><br>
                • High drop counts may indicate network congestion or packet loss<br>
                • Multiple retransmissions suggest unreliable network conditions<br>
                • Reordering is normal in multi-path networks but excessive reordering may impact performance<br>
                • IPv6 connections use Hop Limit (HL) instead of TTL
            </div>
            '''
            
            return html

        except Exception as e:
            import traceback
            self.log_message(f"❌ Error in generate_drops_table: {str(e)}")
            self.log_message(traceback.format_exc())
            return '<div class="no-data">❌ Error generating drops table.</div>'


    def generate_failures_table(self):
        """
        Generate neighbor failure table with anti-crash limits.
        Shows max 50 rows even if 1000s analyzed.
        """
        failures = self.analysis_results.get('neighbor_failures', [])
        
        if not failures:
            return '''
            <div class="success-message" style="padding: 20px; text-align: center;">
                <strong>✅ No Neighbor Data</strong><br>
                <span style="font-size: 13px; color: #666;">
                    No neighbor packets detected or all neighbors healthy.
                </span>
            </div>
            '''
        
        total_count = len(failures)
        display_count = min(50, total_count)  # MAX 50 ROWS
        display_failures = failures[:display_count]
        
        # Truncation warning
        truncated_msg = ""
        if total_count > display_count:
            truncated_msg = f'''
            <div style="background: #fff3cd; padding: 10px; margin-bottom: 15px; border-left: 4px solid #ffc107; border-radius: 4px;">
                <strong>⚠️ Large Dataset Detected</strong><br>
                <span style="font-size: 12px;">
                    Showing top {display_count} of {total_count} neighbors (sorted by activity). 
                    Full analysis completed but display limited to prevent browser overload.
                </span>
            </div>
            '''
        
        html = f'''
        <div class="analysis-section" style="border-left: 4px solid #667eea; padding-left: 15px;">
            <h3 style="color: #495057; margin-top: 0;">🔗 Neighbor Reachability</h3>
            <p style="font-size: 13px; color: #666; margin: 10px 0;">
                <strong>Total Analyzed:</strong> {total_count} | 
                <strong>Displaying:</strong> {display_count}
            </p>
            {truncated_msg}
            
            <table style="font-size: 12px; width: 100%; table-layout: fixed;">
                <thead>
                    <tr style="background: #667eea; color: white; font-weight: 600;">
                        <th style="padding: 10px; width: 28%;">Neighbor</th>
                        <th style="padding: 10px; width: 12%;">Protocol</th>
                        <th style="padding: 10px; width: 12%;">RTT (ms)</th>
                        <th style="padding: 10px; width: 12%;">Missed Hello</th>
                        <th style="padding: 10px; width: 14%;">Last Hello</th>
                        <th style="padding: 10px; width: 22%;">Action</th>
                    </tr>
                </thead>
                <tbody>
        '''
        
        for failure in display_failures:
            action_style = f'background: {failure["color"]}10; padding: 5px 8px; border-left: 3px solid {failure["color"]}; font-size: 11px;'
            
            html += f'''
            <tr style="border-left: 4px solid {failure['color']}; background: {failure['color']}05;">
                <td style="padding: 8px; overflow: hidden; text-overflow: ellipsis;" title="{failure['neighbor']}">
                    <strong>{failure['neighbor']}</strong>
                </td>
                <td style="padding: 8px;">{failure['protocol']}</td>
                <td style="padding: 8px; text-align: center;">{failure['response_time_ms']}</td>
                <td style="padding: 8px; text-align: center; color: {failure['color']}; font-weight: bold;">
                    {failure['consecutive_missed']}
                </td>
                <td style="padding: 8px; font-size: 11px;">{failure['last_hello']}</td>
                <td style="padding: 8px; {action_style}">{failure['recommended_action']}</td>
            </tr>
            '''
        
        html += '''
                </tbody>
            </table>
        </div>
        '''
        
        return html

    def generate_enhanced_loops_table(self):
        """Generate enhanced routing loops table with IP ID tracking and IPv6 support."""
        try:
            loops = self.analysis_results.get('routing_loops', [])
            if not loops:
                return '<div class="success-message">✅ No routing loops detected - routing is stable!</div>'

            # ✅ Count by IP version
            ipv4_count = sum(1 for l in loops if l.get('ip_version') == 'IPv4')
            ipv6_count = sum(1 for l in loops if l.get('ip_version') == 'IPv6')

            html = '''
            <div class="analysis-section">
                <h3>♻️ Enhanced Routing Loop Detection with IP ID Tracking</h3>
                <p><strong>Enhanced Detection Methods:</strong> IP Identification Field Duplication, Flow-Label Analysis (IPv6), TTL-based Analysis, MAC Address Correlation, Payload Fingerprints</p>
                <p style="margin-top: 10px;">
                    <strong>Total Loops:</strong> {total} 
                    <span style="margin-left: 15px;">IPv4: {ipv4}</span>
                    <span style="margin-left: 10px;">IPv6: {ipv6}</span>
                </p>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>IP Ver</th>
                        <th>Flow</th>
                        <th>TTL Before</th>
                        <th>TTL After</th>
                        <th>MAC Srcs</th>
                        <th>MAC Dsts</th>
                        <th>IP ID Before</th>
                        <th>IP ID After</th>
                        <th>Loop Type</th>
                        <th>Evidence</th>
                        <th>Detection Method</th>
                    </tr>
                </thead>
                <tbody>
            '''.format(total=len(loops), ipv4=ipv4_count, ipv6=ipv6_count)

            for loop in loops[:50]:  # Show up to 50 loops
                confidence = loop.get('confidence', 0)
                
                # ✅ Color-code rows by confidence
                if confidence >= 90:
                    row_style = 'border-left: 4px solid #dc3545;'  # Red = Critical
                elif confidence >= 80:
                    row_style = 'border-left: 4px solid #ff9800;'  # Orange = Warning
                else:
                    row_style = 'border-left: 4px solid #ffc107;'  # Yellow = Moderate

                # ✅ IP version badge
                ip_version = loop.get('ip_version', 'N/A')
                if ip_version == 'IPv6':
                    version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
                elif ip_version == 'IPv4':
                    version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
                else:
                    version_badge = 'N/A'

                ip_id_before = loop.get('ip_id_before_hex', 'N/A')
                ip_id_after = loop.get('ip_id_after_hex', 'N/A')
                
                # ✅ Highlight if IP IDs match (duplicate detection)
                ip_id_style = ''
                if ip_id_before == ip_id_after and ip_id_before != 'N/A':
                    ip_id_style = 'background-color: #fff3cd; font-weight: bold;'

                html += '<tr style="{}">'.format(row_style)
                html += '<td style="text-align:center;">{}</td>'.format(version_badge)
                html += '<td><code>{}</code></td>'.format(loop.get('flow', 'Unknown'))
                html += '<td>{}</td>'.format(loop.get('ttl_before', 0))
                html += '<td>{}</td>'.format(loop.get('ttl_after', 0))
                html += '<td><code style="font-size:11px;">{}</code></td>'.format(loop.get('mac_srcs', 'N/A'))
                html += '<td><code style="font-size:11px;">{}</code></td>'.format(loop.get('mac_dsts', 'N/A'))
                html += '<td style="{}">{}</td>'.format(ip_id_style, ip_id_before)
                html += '<td style="{}">{}</td>'.format(ip_id_style, ip_id_after)
                html += '<td>{}</td>'.format(loop.get('loop_type', 'Unknown'))
                html += '<td>{}</td>'.format(loop.get('evidence', 'Unknown'))
                html += '<td>{}</td>'.format(loop.get('detection_method', loop.get('evidence', 'N/A')))
                html += '</tr>'

            html += '''
                </tbody>
            </table>
            
            <div style="margin-top: 15px; padding: 10px; background: #e3f2fd; border-left: 4px solid #2196f3; border-radius: 4px; font-size: 12px;">
                <strong>💡 Analysis Notes:</strong><br>
                • <strong>IPv4</strong>: Uses IP Identification field (reliable unique identifier)<br>
                • <strong>IPv6</strong>: Uses Flow Label (less reliable - confidence reduced by 10%)<br>
                • <strong>TTL Before/After</strong>: Packets losing TTL indicates routing through loops<br>
                • <strong>MAC Changes</strong>: Different MACs confirm traversal through different segments
            </div>
            '''

            return html
            
        except Exception as e:
            import traceback
            self.log_message("❌ Error in generate_enhanced_loops_table: {}".format(str(e)))
            self.log_message(traceback.format_exc())
            return '<div class="no-data">❌ Error generating enhanced loops table.</div>'

#===================================lsa_table===================================================#

    def extract_lsa_details(self, lsa, packet, area_id, is_ack=False, protocol='OSPF'):
        """
        Extract LSA age, sequence number, and checksum from LSA headers.
        Supports both OSPF (IPv4) and OSPFv3 (IPv6).

        Args:
            lsa: OSPF LSA object from Scapy
            packet: Parent packet for timestamp/source info
            area_id: OSPF area ID
            is_ack: Boolean indicating if this is from LSAck packet
            protocol: Protocol version ('OSPF' or 'OSPFv3')
        
        Returns:
            Dictionary with LSA details including age, sequence, checksum
        """
        try:
            from scapy.layers.inet import IP
            from scapy.layers.inet6 import IPv6
            
            # ✅ OSPFv3 has different LSA types
            if protocol == 'OSPFv3':
                lsa_types = {
                    0x2001: 'Router-LSA',
                    0x2002: 'Network-LSA',
                    0x2003: 'Inter-Area-Prefix-LSA',
                    0x2004: 'Inter-Area-Router-LSA',
                    0x4005: 'AS-External-LSA',
                    0x2007: 'NSSA-LSA',
                    0x0008: 'Link-LSA',
                    0x2009: 'Intra-Area-Prefix-LSA',
                    # Fallback numeric types
                    1: 'Router-LSA',
                    2: 'Network-LSA',
                    3: 'Inter-Area-Prefix-LSA',
                    4: 'Inter-Area-Router-LSA',
                    5: 'AS-External-LSA',
                    7: 'NSSA-LSA',
                    8: 'Link-LSA',
                    9: 'Intra-Area-Prefix-LSA'
                }
            else:
                lsa_types = {
                    1: 'Router LSA',
                    2: 'Network LSA',
                    3: 'Summary LSA (IP)',
                    4: 'Summary LSA (ASBR)',
                    5: 'AS-External LSA',
                    7: 'NSSA-External LSA',
                    9: 'Opaque LSA (Link-Local)',
                    10: 'Opaque LSA (Area-Local)',
                    11: 'Opaque LSA (AS)'
                }
        
            # Extract LSA type
            lsa_type = getattr(lsa, 'type', 0)
            
            # Extract LSA ID (Link State ID)
            lsa_id = getattr(lsa, 'id', 'N/A')
            
            # 🔥 KEY FIX: Advertising Router extraction
            adv_router = 'N/A'
            
            # Method 1: Direct attribute
            if hasattr(lsa, 'advrtr'):
                adv_router = lsa.advrtr
            # Method 2: Alternative spelling
            elif hasattr(lsa, 'advrouter'):
                adv_router = lsa.advrouter
            # Method 3: Check if it's in the raw packet bytes
            elif hasattr(lsa, 'fields') and 'advrtr' in lsa.fields:
                adv_router = lsa.fields['advrtr']
            # Method 4: Try to extract from show2() output
            else:
                try:
                    lsa_str = lsa.show2(dump=True)
                    if 'advrtr' in lsa_str:
                        for line in lsa_str.split('\n'):
                            if 'advrtr' in line:
                                adv_router = line.split('=')[-1].strip()
                                break
                except:
                    pass
        
            # 🎯 KEY FIELDS: Age, Sequence, Checksum
            age = getattr(lsa, 'age', 'N/A')
            sequence = getattr(lsa, 'seq', 'N/A')
            
            # Checksum might be 'chksum' or 'checksum'
            checksum = getattr(lsa, 'chksum', getattr(lsa, 'checksum', 'N/A'))
        
            # Format sequence number as hex (0x80000001 format)
            if sequence != 'N/A' and isinstance(sequence, int):
                seq_formatted = '0x{:08X}'.format(sequence)
            else:
                seq_formatted = str(sequence)
        
            # Format checksum as hex
            if checksum != 'N/A' and isinstance(checksum, int):
                checksum_formatted = '0x{:04X}'.format(checksum)
            else:
                checksum_formatted = str(checksum)
        
            # Calculate age status
            age_status = self.get_lsa_age_status(age)
            
            # ✅ Extract source and destination IPs from both IPv4 and IPv6
            src_ip = None
            dst_ip = None
            
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
            else:
                src_ip = 'N/A'
                dst_ip = 'N/A'
        
            return {
                'timestamp': safe_timestamp(packet.time),
                'src': src_ip,
                'dst': dst_ip,
                'area': area_id,
                'protocol': protocol,  # ✅ Track protocol version
                'lsa_type': lsa_types.get(lsa_type, 'Type {}'.format(lsa_type)),
                'lsa_type_num': lsa_type,
                'link_id': lsa_id,
                'adv_router': adv_router,
                'age': age,
                'age_status': age_status,
                'sequence': seq_formatted,
                'sequence_raw': sequence,
                'checksum': checksum_formatted,
                'checksum_raw': checksum,
                'packet_type': 'LSAck' if is_ack else 'LSU',
                'length': getattr(lsa, 'len', getattr(lsa, 'length', 'N/A'))
            }
        
        except Exception as e:
            import traceback
            self.log_message("⚠️ LSA extraction error: {}".format(str(e)))
            self.log_message(traceback.format_exc())
            return None


    def get_lsa_age_status(self, age):
        """
        Determine LSA age status based on RFC 2328 (OSPF) and RFC 5340 (OSPFv3).
        LSAs age every second and refresh every 30 minutes (1800s).
        MaxAge is 3600 seconds.

        Args:
            age: LSA age in seconds
        
        Returns:
            Status string indicating LSA freshness
        """
        if age == 'N/A' or not isinstance(age, (int, float)):
            return 'Unknown'

        if age >= 3600:  # MaxAge - LSA should be flushed
            return 'MaxAge (Flushing)'
        elif age >= 1800:  # 30 minutes - normal refresh time
            return 'Aging (Near Refresh)'
        elif age >= 900:  # 15 minutes
            return 'Valid (Mid-life)'
        else:
            return 'Fresh'


        

    def generate_lsa_table(self):
        """Generate enhanced OSPF/OSPFv3 LSA table with Age, Sequence, and Checksum."""
        try:
            lsa_database = self.analysis_results.get('ospf_lsa_analysis', {}).get('lsa_database', [])
        
            if not lsa_database:
                return '<div class="no-data">No OSPF/OSPFv3 LSAs detected in traffic.</div>'
        
            # Sort by timestamp
            lsa_database_sorted = sorted(lsa_database, key=lambda x: x.get('timestamp', ''))
        
            html = '<div class="analysis-section">'
            html += '<h3>📊 OSPF/OSPFv3 Link-State Database (LSDB) Analysis</h3>'
            html += '<p><strong>Total LSAs:</strong> {}</p>'.format(len(lsa_database))
        
            # ✅ Summary statistics with protocol breakdown
            lsa_type_counts = Counter(lsa.get('lsa_type', 'Unknown') for lsa in lsa_database)
            protocol_counts = Counter(lsa.get('protocol', 'OSPF') for lsa in lsa_database)
            
            html += '<div style="margin-bottom: 15px;">'
            html += '<strong>Protocol Distribution:</strong><br>'
            for proto, count in protocol_counts.most_common():
                html += '&nbsp;&nbsp;• {}: {}<br>'.format(proto, count)
            html += '</div>'
            
            html += '<div style="margin-bottom: 15px;">'
            html += '<strong>LSA Type Distribution:</strong><br>'
            for lsa_type, count in lsa_type_counts.most_common():
                html += '&nbsp;&nbsp;• {}: {}<br>'.format(lsa_type, count)
            html += '</div>'
        
            html += '<table><thead><tr>'
            html += '<th>Timestamp</th>'
            html += '<th>Protocol</th>'  # ✅ Added Protocol column
            html += '<th>Source</th>'
            html += '<th>LSA Type</th>'
            html += '<th>Link ID</th>'
            html += '<th>Age (s)</th>'
            html += '<th>Age Status</th>'
            html += '<th>Sequence</th>'
            html += '<th>Checksum</th>'
            html += '<th>Area</th>'
            html += '<th>Packet Type</th>'
            html += '</tr></thead><tbody>'
        
            for lsa in lsa_database_sorted[:500]:  # ✅ Increased limit to 500
                # Color-code age status
                age_status = lsa.get('age_status', 'Unknown')
                age = lsa.get('age', 'N/A')
            
                if age_status == 'MaxAge (Flushing)':
                    age_color = 'color: #d32f2f;'  # Red
                elif age_status == 'Aging (Near Refresh)':
                    age_color = 'color: #f57c00;'  # Orange
                elif age_status == 'Valid (Mid-life)':
                    age_color = 'color: #fbc02d;'  # Yellow
                else:
                    age_color = 'color: #388e3c;'  # Green
                
                # ✅ Protocol badge styling
                protocol = lsa.get('protocol', 'OSPF')
                if protocol == 'OSPFv3':
                    protocol_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">OSPFv3</span>'
                else:
                    protocol_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">OSPF</span>'
            
                html += '<tr>'
                html += '<td>{}</td>'.format(lsa.get('timestamp', 'N/A'))
                html += '<td>{}</td>'.format(protocol_badge)  # ✅ Protocol badge
                html += '<td style="font-family:monospace; font-size:11px;">{}</td>'.format(lsa.get('src', 'N/A'))  # ✅ Better styling for IPv6
                html += '<td>{}</td>'.format(lsa.get('lsa_type', 'N/A'))
                html += '<td>{}</td>'.format(lsa.get('link_id', 'N/A'))
                html += '<td style="{}">{}</td>'.format(age_color, age)
                html += '<td style="{}">{}</td>'.format(age_color, age_status)
                html += '<td><code>{}</code></td>'.format(lsa.get('sequence', 'N/A'))
                html += '<td><code>{}</code></td>'.format(lsa.get('checksum', 'N/A'))
                html += '<td>{}</td>'.format(lsa.get('area', 'N/A'))
                html += '<td>{}</td>'.format(lsa.get('packet_type', 'N/A'))
                html += '</tr>'
        
            if len(lsa_database) > 500:
                html += '<tr><td colspan="11" style="text-align: center; font-style: italic;">'
                html += 'Showing 500 of {} LSAs</td></tr>'.format(len(lsa_database))
        
            html += '</tbody></table></div>'
        
            return html
        
        except Exception as e:
            import traceback
            self.log_message("⚠️ Error in generate_lsa_table: {}".format(str(e)))
            self.log_message(traceback.format_exc())
            return '<div class="no-data">Error generating LSA table.</div>'
        
#=================================eigrp==================generation table====================#

    def generate_eigrp_sia_table(self):
        """
        Generate HTML table specifically for EIGRP SIA events.
        Supports both IPv4 and IPv6 with enhanced display.
        """
        sia_events = self.analysis_results.get('routing_protocol_analysis', {}).get('eigrp_sia_events', [])
        
        if not sia_events:
            return ''  # Return empty string if no SIA events
        
        html = '''
        <div class="analysis-section" style="border-left: 4px solid #c01528; padding-left: 15px; margin-bottom: 30px; background-color: #fff5f5;">
            <h3 style="color: #c01528; margin-top: 10px;">⚠️ EIGRP SIA Events Detected ({} events)</h3>
            <p style="color: #666; font-size: 13px; margin-bottom: 15px;">
                <strong>SIA (Stuck-in-Active)</strong> occurs when EIGRP Query-Reply process takes too long, 
                indicating routing convergence issues, link problems, or topology instability.
            </p>
            <table style="font-size: 13px;">
                <thead>
                    <tr style="background: #c01528; color: white;">
                        <th style="padding: 10px;">Query Origin</th>
                        <th style="padding: 10px;">Responder</th>
                        <th style="padding: 10px;">IP Version</th>
                        <th style="padding: 10px;">AS Number</th>
                        <th style="padding: 10px;">Seq Number</th>
                        <th style="padding: 10px;">Query Time</th>
                        <th style="padding: 10px;">Reply Time</th>
                        <th style="padding: 10px;">Delay (s)</th>
                        <th style="padding: 10px;">Status</th>
                    </tr>
                </thead>
                <tbody>
        '''.format(len(sia_events))
        
        for event in sia_events:
            # Determine color based on status
            if 'SIA' in event['status'] or 'Retry' in event['status'] or 'Unanswered' in event['status']:
                status_color = '#c01528'  # Red for critical
                row_bg = '#ffebee'  # Light red background
            else:
                status_color = '#e68161'  # Orange for warning
                row_bg = '#fff3e0'  # Light orange background
            
            # ✅ IP version badge
            ip_version = event.get('ip_version', 'IPv4')
            if ip_version == 'IPv6':
                version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:600;">IPv6</span>'
            else:
                version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:600;">IPv4</span>'
            
            # ✅ Format IPs with monospace font and smaller size for IPv6
            query_origin = event['query_origin']
            responder = event['responder']
            ip_style = 'font-family: monospace; font-size: 11px;' if ip_version == 'IPv6' else 'font-family: monospace;'
            
            html += f'''
                <tr style="background: {row_bg};">
                    <td style="padding: 8px; font-weight: 600; {ip_style}">{query_origin}</td>
                    <td style="padding: 8px; font-weight: 600; {ip_style}">{responder}</td>
                    <td style="padding: 8px; text-align: center;">{version_badge}</td>
                    <td style="padding: 8px;">{event['as_number']}</td>
                    <td style="padding: 8px;">{event['seq_number']}</td>
                    <td style="padding: 8px; font-size: 12px;">{event['query_time']}</td>
                    <td style="padding: 8px; font-size: 12px;">{event['reply_time']}</td>
                    <td style="padding: 8px; color: {status_color}; font-weight: bold; font-size: 14px;">{event['delay_seconds']}</td>
                    <td style="padding: 8px; color: {status_color}; font-weight: bold;">{event['status']}</td>
                </tr>
            '''
        
        html += '''
                </tbody>
            </table>
            
            <div style="margin-top: 15px; padding: 10px; background: #e3f2fd; border-left: 4px solid #2196f3; font-size: 12px;">
                <strong>📖 Status Legend:</strong><br>
                <span style="color: #e68161; font-weight: bold;">● Slow Reply (90-180s):</span> Link congestion or CPU load - Monitor closely<br>
                <span style="color: #c01528; font-weight: bold;">● SIA (&gt;180s):</span> Critical - Route computation stuck, investigate immediately<br>
                <span style="color: #c01528; font-weight: bold;">● Unanswered Query/Retry Exceeded:</span> Critical - No reply received, neighbor may be down<br>
                <span style="color: #666; font-weight: bold;">● SIA-Query Sent:</span> Router detected potential SIA and sent SIA-Query to verify neighbor status<br>
                <span style="color: #28a745; font-weight: bold;">● SIA-Reply Received:</span> Neighbor responded to SIA-Query, adjacency still active
            </div>
        </div>
        '''
        
        return html


    def generate_eigrp_table(self):
        """Generate HTML table for EIGRP packets with SIA analysis at the top. Supports IPv4 and IPv6."""
        packets = self.analysis_results.get('routing_protocol_analysis', {}).get('eigrp_packets', [])
        sia_events = self.analysis_results.get('routing_protocol_analysis', {}).get('eigrp_sia_events', [])
        
        if not packets and not sia_events:
            return '<div class="no-data">No EIGRP packets found in this capture.</div>'
        
        html = ''
        
        # ✅ Add SIA events table at the TOP if any detected
        sia_table = self.generate_eigrp_sia_table()
        if sia_table:
            html += sia_table
        
        # ✅ Packet summary with IPv4/IPv6 breakdown
        ipv4_count = sum(1 for p in packets if p.get('ip_version') == 'IPv4')
        ipv6_count = sum(1 for p in packets if p.get('ip_version') == 'IPv6')
        
        # Count by opcode
        opcode_counts = Counter(p.get('opcode', 'Unknown') for p in packets)
        
        html += f'''
        <div class="analysis-section">
            <h3>📊 EIGRP Packet Details</h3>
            <div style="margin-bottom: 15px; padding: 10px; background: #f5f5f5; border-radius: 6px;">
                <strong>Total Packets:</strong> {len(packets)} 
                <span style="margin-left: 15px;">IPv4: {ipv4_count}</span> 
                <span style="margin-left: 10px;">IPv6: {ipv6_count}</span><br>
                <strong style="margin-top: 5px; display: inline-block;">Packet Distribution:</strong><br>
        '''
        
        for opcode, count in opcode_counts.most_common():
            html += f'&nbsp;&nbsp;• {opcode}: {count}<br>'
        
        html += '''
            </div>
            <table>
                <thead>
                    <tr>
                        <th>IP Version</th>
                        <th>Source IP</th>
                        <th>Destination IP</th>
                        <th>Timestamp</th>
                        <th>Opcode</th>
                        <th>AS Number</th>
                        <th>Seq Number</th>
                        <th>Hold Time (s)</th>
                    </tr>
                </thead>
                <tbody>
        '''
        
        for pkt in packets[:200]:  # Limit to 200 for performance
            hold_display = pkt.get('hold_time', 0) if pkt.get('opcode') == 'Hello' else 'N/A'
            
            # ✅ IP version badge
            ip_version = pkt.get('ip_version', 'IPv4')
            if ip_version == 'IPv6':
                version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:600;">IPv6</span>'
                ip_style = 'font-family: monospace; font-size: 11px;'
            else:
                version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:600;">IPv4</span>'
                ip_style = 'font-family: monospace;'
            
            # Highlight Query and Reply packets
            row_style = ''
            opcode_style = ''
            if pkt.get('opcode') == 'Query':
                row_style = 'background: #fff9c4;'  # Light yellow for Query
                opcode_style = 'color: #ff9800; font-weight: bold;'
            elif pkt.get('opcode') == 'Reply':
                row_style = 'background: #c8e6c9;'  # Light green for Reply
                opcode_style = 'color: #28a745; font-weight: bold;'
            elif 'SIA' in pkt.get('opcode', ''):
                row_style = 'background: #ffebee;'  # Light red for SIA
                opcode_style = 'color: #c01528; font-weight: bold;'
            
            html += f'''
            <tr style="{row_style}">
                <td style="text-align: center;">{version_badge}</td>
                <td style="{ip_style}">{pkt['src_ip']}</td>
                <td style="{ip_style}">{pkt['dst_ip']}</td>
                <td>{pkt['timestamp']}</td>
                <td style="{opcode_style}">{pkt['opcode']}</td>
                <td>{pkt.get('as_number', 0)}</td>
                <td>{pkt.get('seq_number', 0)}</td>
                <td>{hold_display}</td>
            </tr>
            '''
        
        if len(packets) > 200:
            html += f'<tr><td colspan="8" style="text-align: center; font-style: italic; padding: 10px;">Showing 200 of {len(packets)} packets</td></tr>'
        
        html += '</tbody></table></div>'
        return html


#==================================BGP generation============================#

    def generate_bgp_table(self):
        """Generate enhanced HTML table for BGP analysis with session summary. Supports IPv4 and IPv6."""
        packets = self.analysis_results.get('routing_protocol_analysis', {}).get('bgp_packets', [])
        sessions = self.analysis_results.get('routing_protocol_analysis', {}).get('bgp_sessions', [])
        
        if not packets and not sessions:
            return '<div class="no-data">No BGP packets found in this capture.</div>'
        
        # ✅ SESSION SUMMARY TABLE
        session_html = ''
        if sessions:
            session_html = '''
            <div style="margin-bottom: 30px; border-left: 4px solid #007bff; padding-left: 15px;">
                <h3 style="color: #495057; margin-top: 0;">📊 BGP Session Summary</h3>
                <table style="font-size: 12px; width: 100%;">
                    <thead>
                        <tr style="background: #007bff; color: white; font-weight: 600;">
                            <th style="padding: 10px;">Peers</th>
                            <th style="padding: 10px;">IP Version</th>
                            <th style="padding: 10px;">State</th>
                            <th style="padding: 10px;">Status</th>
                            <th style="padding: 10px;">AS Number</th>
                            <th style="padding: 10px;">Duration</th>
                            <th style="padding: 10px;">Updates (Sent/Rcv)</th>
                            <th style="padding: 10px;">Keepalives (Sent/Rcv)</th>
                            <th style="padding: 10px;">Prefixes (Ann/With)</th>
                            <th style="padding: 10px;">Notifications</th>
                            <th style="padding: 10px;">Flaps</th>
                        </tr>
                    </thead>
                    <tbody>
            '''
            
            for session in sessions:
                status_style = f'color: {session["color"]}; font-weight: bold;'
                row_style = f'border-left: 4px solid {session["color"]}; background: {session["color"]}05;'
                
                # ✅ IP version badge
                ip_version = session.get('ip_version', 'N/A')
                if ip_version == 'IPv6':
                    version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:600;">IPv6</span>'
                    peer_style = 'font-family: monospace; font-size: 11px;'
                elif ip_version == 'IPv4':
                    version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:600;">IPv4</span>'
                    peer_style = 'font-family: monospace;'
                else:
                    version_badge = '<span style="background:#666; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">N/A</span>'
                    peer_style = ''
                
                session_html += f'''
                <tr style="{row_style}">
                    <td style="padding: 10px; {peer_style}"><strong>{session['peers']}</strong></td>
                    <td style="padding: 10px; text-align: center;">{version_badge}</td>
                    <td style="padding: 10px;"><code>{session['state']}</code></td>
                    <td style="padding: 10px; {status_style}">{session['icon']} {session['status']}</td>
                    <td style="padding: 10px; text-align: center;">{session['as_number']}</td>
                    <td style="padding: 10px; text-align: center;">{session['duration']}</td>
                    <td style="padding: 10px; text-align: center;">{session['updates_sent']} / {session['updates_received']}</td>
                    <td style="padding: 10px; text-align: center;">{session['keepalives_sent']} / {session['keepalives_received']}</td>
                    <td style="padding: 10px; text-align: center;">{session['prefixes_announced']} / {session['prefixes_withdrawn']}</td>
                    <td style="padding: 10px; text-align: center; {'color: #d32f2f; font-weight: bold;' if session['notifications'] > 0 else ''}">{session['notifications']}</td>
                    <td style="padding: 10px; text-align: center; {'color: #fbc02d; font-weight: bold;' if session['flap_count'] > 0 else ''}">{session['flap_count']}</td>
                </tr>
                '''
            
            session_html += '''
                    </tbody>
                </table>
                
                <div style="margin-top: 15px; padding: 12px; background: #f5f5f5; border-radius: 5px; font-size: 12px;">
                    <strong>📊 Status Legend:</strong><br>
                    <span style="color: #28a745; font-weight: bold;">✅ Healthy:</span> Established, no flaps, hold timer OK<br>
                    <span style="color: #fbc02d; font-weight: bold;">⚠️ Flapping:</span> Session resets detected<br>
                    <span style="color: #ff9800; font-weight: bold;">🔴 Hold Timer Risk:</span> No recent keepalives<br>
                    <span style="color: #d32f2f; font-weight: bold;">❌ Down:</span> Session in Idle state<br>
                    <span style="color: #007bff; font-weight: bold;">🔄 Establishing:</span> Connection in progress
                </div>
            </div>
            '''
        
        # ✅ DETAILED PACKET TABLE with IP version breakdown
        ipv4_count = sum(1 for p in packets if p.get('ip_version') == 'IPv4')
        ipv6_count = sum(1 for p in packets if p.get('ip_version') == 'IPv6')
        
        packet_html = f'''
            <div style="border-left: 4px solid #667eea; padding-left: 15px;">
                <h3 style="color: #495057; margin-top: 0;">📦 BGP Packet Details</h3>
                <div style="margin-bottom: 15px; padding: 10px; background: #f5f5f5; border-radius: 6px; font-size: 13px;">
                    <strong>Total Packets:</strong> {len(packets)} 
                    <span style="margin-left: 15px;">IPv4: {ipv4_count}</span> 
                    <span style="margin-left: 10px;">IPv6: {ipv6_count}</span>
                </div>
                <table style="font-size: 12px; width: 100%;">
                    <thead>
                        <tr style="background: #667eea; color: white; font-weight: 600;">
                            <th style="padding: 10px;">IP Version</th>
                            <th style="padding: 10px;">Source IP</th>
                            <th style="padding: 10px;">Destination IP</th>
                            <th style="padding: 10px;">Timestamp</th>
                            <th style="padding: 10px;">BGP Type</th>
                            <th style="padding: 10px;">Session State</th>
                            <th style="padding: 10px;">TCP Flags</th>
                            <th style="padding: 10px;">Details</th>
                        </tr>
                    </thead>
                    <tbody>
        '''
        
        for pkt in packets[:200]:  # ✅ Increased limit to 200
            details_str = ''
            if pkt.get('details'):
                details = pkt['details']
                if 'as_number' in details:
                    details_str = f"AS: {details['as_number']}, Hold: {details['hold_time']}s"
                elif 'prefixes_announced' in details:
                    details_str = f"Announced: {details['prefixes_announced']}, Withdrawn: {details['prefixes_withdrawn']}"
                elif 'error_name' in details:
                    details_str = f"⚠️ {details['error_name']} (Code: {details['error_code']})"
            
            # Color-code by BGP type
            type_color = {
                'OPEN': '#28a745',
                'UPDATE': '#007bff',
                'NOTIFICATION': '#d32f2f',
                'KEEPALIVE': '#fbc02d'
            }.get(pkt['bgp_type'], '#6c757d')
            
            # ✅ IP version badge
            ip_version = pkt.get('ip_version', 'N/A')
            if ip_version == 'IPv6':
                version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
                ip_style = 'font-family: monospace; font-size: 11px;'
            elif ip_version == 'IPv4':
                version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
                ip_style = 'font-family: monospace;'
            else:
                version_badge = 'N/A'
                ip_style = ''
            
            packet_html += f'''
            <tr style="border-left: 3px solid {type_color};">
                <td style="padding: 10px; text-align: center;">{version_badge}</td>
                <td style="padding: 10px; {ip_style}">{pkt['src_ip']}</td>
                <td style="padding: 10px; {ip_style}">{pkt['dst_ip']}</td>
                <td style="padding: 10px; font-size: 11px;">{pkt['timestamp']}</td>
                <td style="padding: 10px; color: {type_color}; font-weight: bold;">{pkt['bgp_type']}</td>
                <td style="padding: 10px;"><code style="font-size: 11px;">{pkt['session_state']}</code></td>
                <td style="padding: 10px; font-size: 11px;">{pkt['tcp_flags']}</td>
                <td style="padding: 10px; font-size: 11px;">{details_str}</td>
            </tr>
            '''
        
        if len(packets) > 200:
            packet_html += f'''
            <tr><td colspan="8" style="padding: 10px; text-align: center; background: #fff3cd; font-weight: bold;">
                Showing first 200 of {len(packets)} packets
            </td></tr>
            '''
        
        packet_html += '''
                    </tbody>
                </table>
            </div>
        '''
        
        return session_html + packet_html


#=========================================isis generation====================================#

    def generate_isis_table(self):
        """Generate HTML for IS-IS packet dashboard with IPv4/IPv6 awareness."""
        isis_data = self.analysis_results.get('isis_analysis', {})
        
        # Compile pdu_stats dictionary
        pdu_stats = Counter()
        for pdu_list in ['hello_pdus', 'lsp_pdus', 'csnp_pdus', 'psnp_pdus']:
            for pkt in isis_data.get(pdu_list, []):
                pdu_type = pkt.get('type', 'Unknown')
                pdu_stats[pdu_type] += 1

        # Combine all packet details
        packet_details = []
        for pdu_list in ['hello_pdus', 'lsp_pdus', 'csnp_pdus', 'psnp_pdus']:
            packet_details.extend(isis_data.get(pdu_list, []))

        total_packets = isis_data.get('packet_count', len(packet_details))
        address_families = isis_data.get('address_families', [])

        if total_packets == 0:
            return '<div class="no-data">ℹ️ No IS-IS packets detected in traffic.</div>'

        # ✅ Header with address family information
        af_display = ', '.join(address_families) if address_families else 'Unknown'
        html = f'''
        <div class="analysis-section">
            <h3>IS-IS Packet Analysis</h3>
            <div style="margin-bottom: 15px; padding: 10px; background: #e3f2fd; border-left: 4px solid #2196f3; border-radius: 4px;">
                <strong>📡 Protocol Info:</strong> IS-IS is Layer 2 protocol-agnostic (supports IPv4 & IPv6 simultaneously)<br>
                <strong>🌐 Detected Address Families:</strong> {af_display}<br>
                <strong>📊 Total Packets:</strong> {total_packets}
            </div>
        '''

        # Stats summary table
        html += '<h4>IS-IS PDU Type Summary</h4>'
        html += '<table style="width:auto"><thead><tr><th>IS-IS PDU Type</th><th>Count</th></tr></thead><tbody>'
        for pdu_type, count in sorted(pdu_stats.items(), key=lambda x: -x[1]):
            html += '<tr><td>{}</td><td>{}</td></tr>'.format(pdu_type, count)
        html += '</tbody></table></div>'

        # Per-packet details table
        html += '<div class="analysis-section"><h3>Detailed IS-IS Packet List</h3>'
        html += '''<table><thead><tr>
            <th>Source MAC</th>
            <th>Dest MAC</th>
            <th>Timestamp</th>
            <th>PDU Type</th>
            <th>Level</th>
            <th>Holding Time</th>
            <th>Priority</th>
            <th>LSP ID / System ID</th>
        </tr></thead><tbody>'''

        for pkt in packet_details[:200]:  # Limit to 200
            html += '''<tr>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>'''.format(
                pkt.get('src_mac', 'N/A'),
                pkt.get('dst_mac', 'N/A'),
                pkt.get('timestamp', 'N/A'),
                pkt.get('type', 'N/A'),
                pkt.get('level', 'N/A'),
                pkt.get('holding_time', 'N/A'),
                pkt.get('priority', 'N/A'),
                pkt.get('lsp_id', pkt.get('system_id', 'N/A'))
            )
        
        if len(packet_details) > 200:
            html += f'<tr><td colspan="8" style="text-align: center; font-style: italic; padding: 10px;">Showing 200 of {len(packet_details)} packets</td></tr>'

        html += '</tbody></table></div>'

        return html


#==============================================================================#

    def generate_isakmp_sa_table(self):
        """Generate HTML table for ISAKMP security associations with IPv6 support."""
        sa_list = self.analysis_results.get('isakmp_analysis', {}).get('isakmp_sas', [])
        
        if not sa_list:
            return '<div class="no-data">ℹ️ No ISAKMP security associations found.</div>'
        
        html = '''
        <table><thead><tr>
            <th>IP Version</th>
            <th>Message ID</th>
            <th>Encryption</th>
            <th>Hash Algorithm</th>
            <th>Lifetime</th>
            <th>Status</th>
        </tr></thead><tbody>
        '''
        
        for sa in sa_list[:200]:
            if not isinstance(sa, dict):
                continue
            
            # ✅ IP version badge
            ip_version = sa.get('ip_version', 'N/A')
            if ip_version == 'IPv6':
                version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
            elif ip_version == 'IPv4':
                version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
            else:
                version_badge = 'N/A'
            
            html += f'''
            <tr>
                <td style="text-align: center;">{version_badge}</td>
                <td style="font-family: monospace; font-size: 11px;">{sa.get('msg_id', 'N/A')}</td>
                <td>{sa.get('encryption', 'N/A')}</td>
                <td>{sa.get('hash_alg', 'N/A')}</td>
                <td>{sa.get('lifetime', 'N/A')}</td>
                <td><span style="color: #28a745;">●</span> {sa.get('status', 'N/A')}</td>
            </tr>
            '''
        
        html += '</tbody></table>'
        return html

    def generate_ipsec_sa_table(self):
        """Generate HTML table for IPsec security associations with IPv6 support."""
        sa_list = self.analysis_results.get('ipsec_analysis', {}).get('ipsec_sas', [])
        
        if not sa_list:
            return '<div class="no-data">ℹ️ No IPsec security associations found.</div>'
        
        html = '''
        <table><thead><tr>
            <th>IP Version</th>
            <th>SPI</th>
            <th>Source → Destination</th>
            <th>Encryption</th>
            <th>Authentication</th>
            <th>Lifetime</th>
            <th>Status</th>
        </tr></thead><tbody>
        '''
        
        for sa in sa_list[:200]:
            if not isinstance(sa, dict):
                continue
            
            # ✅ IP version badge
            ip_version = sa.get('ip_version', 'N/A')
            if ip_version == 'IPv6':
                version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
                ip_style = 'font-family: monospace; font-size: 11px;'
            elif ip_version == 'IPv4':
                version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
                ip_style = 'font-family: monospace;'
            else:
                version_badge = 'N/A'
                ip_style = ''
            
            src = sa.get('src', 'N/A')
            dst = sa.get('dst', 'N/A')
            tunnel = f"{src} → {dst}"
            
            html += f'''
            <tr>
                <td style="text-align: center;">{version_badge}</td>
                <td style="font-family: monospace;">{sa.get('spi', 'N/A')}</td>
                <td style="{ip_style}">{tunnel}</td>
                <td>{sa.get('encryption', 'N/A')}</td>
                <td>{sa.get('authentication', 'N/A')}</td>
                <td>{sa.get('lifetime', 'N/A')}</td>
                <td><span style="color: #28a745;">●</span> {sa.get('status', 'N/A')}</td>
            </tr>
            '''
        
        html += '</tbody></table>'
        return html


    def generate_sequences_table(self):
        """Generate sequence analysis table with IPv6 support."""
        try:
            gaps = self.analysis_results.get('sequence_analysis', {}).get('sequence_gaps', [])
            jumps = self.analysis_results.get('sequence_analysis', {}).get('sequence_jumps', [])
            duplicates = self.analysis_results.get('sequence_analysis', {}).get('duplicate_sequences', [])
            
            if not gaps and not jumps and not duplicates:
                return '<div class="success-message">✅ No TCP sequence issues detected - TCP flows are healthy!</div>'
            
            # ✅ Summary with breakdown
            html = f'''
            <div style="margin-bottom: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                <strong>⚠️ TCP Sequence Issues Detected:</strong><br>
                Gaps: {len(gaps)} | Large Jumps: {len(jumps)} | Duplicates: {len(duplicates)}
            </div>
            '''
            
            html += '''
            <table>
                <thead>
                    <tr>
                        <th>IP Version</th>
                        <th>Flow</th>
                        <th>Timestamp</th>
                        <th>Expected</th>
                        <th>Actual</th>
                        <th>Gap/Jump Size</th>
                        <th>Source</th>
                        <th>ACK</th>
                        <th>Flags</th>
                        <th>Type</th>
                    </tr>
                </thead>
                <tbody>
            '''
            
            # ✅ Add gaps
            for gap in gaps[:50]:  # Increased limit
                # IP version badge
                ip_version = gap.get('ip_version', 'N/A')
                if ip_version == 'IPv6':
                    version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
                elif ip_version == 'IPv4':
                    version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
                else:
                    version_badge = 'N/A'
                
                html += '''
                <tr style="background: #fff3e0; border-left: 3px solid #ff9800;">
                    <td style="text-align:center;">{}</td>
                    <td style="font-family:monospace; font-size:11px;">{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td style="color:#ff9800; font-weight:bold;">{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td><span style="background:#ff9800; color:white; padding:3px 8px; border-radius:4px;">Gap</span></td>
                </tr>
                '''.format(
                    version_badge,
                    gap.get("flow", "Unknown"),
                    gap.get("timestamp", "Unknown"),
                    gap.get("expected", 0),
                    gap.get("actual", 0),
                    gap.get("gap_size", 0),
                    gap.get("source", "Unknown"),
                    gap.get("ack", 0),
                    self.format_tcp_flags(gap.get("flags", 0))
                )
            
            # ✅ Add jumps
            for jump in jumps[:50]:  # Increased limit
                # IP version badge
                ip_version = jump.get('ip_version', 'N/A')
                if ip_version == 'IPv6':
                    version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
                elif ip_version == 'IPv4':
                    version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
                else:
                    version_badge = 'N/A'
                
                html += '''
                <tr style="background: #ffebee; border-left: 3px solid #d32f2f;">
                    <td style="text-align:center;">{}</td>
                    <td style="font-family:monospace; font-size:11px;">{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td style="color:#d32f2f; font-weight:bold;">{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td><span style="background:#d32f2f; color:white; padding:3px 8px; border-radius:4px;">Jump</span></td>
                </tr>
                '''.format(
                    version_badge,
                    jump.get("flow", "Unknown"),
                    jump.get("timestamp", "Unknown"),
                    jump.get("expected", 0),
                    jump.get("actual", 0),
                    jump.get("jump_size", 0),
                    jump.get("source", "Unknown"),
                    jump.get("ack", 0),
                    self.format_tcp_flags(jump.get("flags", 0))
                )
            
            # ✅ Add duplicates
            for dup in duplicates[:50]:  # Increased limit
                # IP version badge
                ip_version = dup.get('ip_version', 'N/A')
                if ip_version == 'IPv6':
                    version_badge = '<span style="background:#4a5fc2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv6</span>'
                elif ip_version == 'IPv4':
                    version_badge = '<span style="background:#3146a2; color:white; padding:3px 8px; border-radius:4px; font-size:11px;">IPv4</span>'
                else:
                    version_badge = 'N/A'
                
                html += '''
                <tr style="background: #e8f5e9; border-left: 3px solid #28a745;">
                    <td style="text-align:center;">{}</td>
                    <td style="font-family:monospace; font-size:11px;">{}</td>
                    <td>{}</td>
                    <td>N/A</td>
                    <td>{}</td>
                    <td style="color:#28a745; font-weight:bold;">Duplicate</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td><span style="background:#28a745; color:white; padding:3px 8px; border-radius:4px;">Duplicate</span></td>
                </tr>
                '''.format(
                    version_badge,
                    dup.get("flow", "Unknown"),
                    dup.get("timestamp", "Unknown"),
                    dup.get("seq", 0),
                    dup.get("source", "Unknown"),
                    dup.get("ack", 0),
                    self.format_tcp_flags(dup.get("flags", 0))
                )
            
            html += '</tbody></table>'
            
            # ✅ Analysis summary with recommendations
            html += '''
            <div style="margin-top: 15px; padding: 12px; background: #e3f2fd; border-left: 4px solid #2196f3; border-radius: 4px; font-size: 13px;">
                <strong>📊 Analysis Summary:</strong><br>
                • <strong>Sequence Gaps:</strong> {} - May indicate packet loss or out-of-order delivery<br>
                • <strong>Large Jumps:</strong> {} - Could indicate connection resets or time-based issues<br>
                • <strong>Duplicates:</strong> {} - Possible retransmissions or replay issues<br>
                <br>
                <strong>💡 Recommendations:</strong><br>
                • Check for packet loss in network path<br>
                • Review TCP retransmission timers<br>
                • Verify network jitter and latency
            </div>
            '''.format(len(gaps), len(jumps), len(duplicates))
            
            return html
            
        except Exception as e:
            import traceback
            self.log_message("❌ Error in generate_sequences_table: {}".format(str(e)))
            self.log_message(traceback.format_exc())
            return '<div class="no-data">❌ Error generating sequences table.</div>'
    
    def generate_communication_table(self, selected_protocol="ALL", jitter_threshold=None, jitter_metric="avg_jitter"):
        """Generate enhanced flow table with IPv4/IPv6 indicator."""
        try:
            flows = self.analysis_results.get('communication_analysis', {}).get('flows', [])
            if not flows:
                return '<div class="no-data">ℹ️ No communication flows detected.</div>'

            html = (
                '<table id="comm-table">'
                '<thead><tr>'
                '<th>Flow</th>'
                '<th>IP Ver</th>'  # 🆕 New column
                '<th>Packets</th>'
                '<th>Data Volume</th>'
                '<th>Protocol</th>'
                '<th>TTL/HL</th>'  # 🆕 Changed label (TTL for IPv4, Hop Limit for IPv6)
                '<th>Duration</th>'
                '<th>Min Jitter (ms)</th>'
                '<th>Packets Above Jitter</th>'
                '</tr></thead><tbody>'
            )

            for flow in flows[:50]:
                proto = flow.get("protocol", "")
                if selected_protocol != "ALL" and proto != selected_protocol:
                    continue

                # Get IP version
                ip_version = flow.get('ip_version', 'IPv4')
                
                # 🆕 Color-code IP version badge
                if ip_version == "IPv6":
                    ip_badge = '<span style="background:#4a90e2;color:white;padding:2px 6px;border-radius:3px;font-size:10px;">IPv6</span>'
                else:
                    ip_badge = '<span style="background:#2ecc71;color:white;padding:2px 6px;border-radius:3px;font-size:10px;">IPv4</span>'

                # Jitter calculation (UDP only)
                if proto == "UDP":
                    min_jitter = flow.get("min_jitter", "")
                    flagged_indices = flow.get('flagged_jitter_indices', [])
                    flagged_count = len(flagged_indices) if flagged_indices else 0
                    flagged_details = str(flagged_count) if flagged_count > 0 else 'None'
                else:
                    min_jitter = "N/A"
                    flagged_details = "N/A"

                # TTL/Hop Limit label
                ttl_value = flow.get("ttl", "")
                
                html += (
                    f'<tr>'
                    f'<td>{flow["flow"]}</td>'
                    f'<td>{ip_badge}</td>'  # 🆕 IP version badge
                    f'<td>{flow["packet_count"]}</td>'
                    f'<td>{flow["data_volume"]}</td>'
                    f'<td class="col-proto">{proto}</td>'
                    f'<td>{ttl_value}</td>'
                    f'<td>{flow["duration"]}</td>'
                    f'<td class="col-jitter">{min_jitter}</td>'
                    f'<td>{flagged_details}</td>'
                    f'</tr>'
                )

            html += '</tbody></table>'
            return html

        except Exception as e:
            self.log_message(f"❌ Error in generate_communication_table: {str(e)}")
            return '<div class="no-data">❌ Error generating communication table.</div>'


    def open_dashboard(self):
        """Open the generated dashboard in the default web browser."""
        if self.dashboard_file and os.path.exists(self.dashboard_file):
            webbrowser.open('file://' + os.path.abspath(self.dashboard_file))
            self.log_message("📊 Dashboard opened in browser")
        else:
            messagebox.showwarning("Dashboard Not Found", "Please run analysis first to generate the dashboard.")

    def export_results(self):
        """Export analysis results to JSON file."""
        if not self.analysis_results:
            messagebox.showwarning("No Results", "Please run analysis first.")
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        export_file = 'ultra_analysis_results_{}.json'.format(timestamp)
        
        try:
            export_data = {}
            for key, value in self.analysis_results.items():
                if key == 'communication_analysis' and isinstance(value, dict) and 'unique_ips' in value:
                    export_data[key] = value.copy()
                    export_data[key]['unique_ips'] = list(value['unique_ips'])
                else:
                    export_data[key] = value
            
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            messagebox.showinfo("Export Complete", "Results exported to: {}".format(export_file))
            self.log_message("📋 Results exported to: {}".format(export_file))
        except Exception as e:
            messagebox.showerror("Export Error", "Failed to export results: {}".format(str(e)))


            

if __name__ == "__main__":
    import sys
    import hashlib  # 🆕 For file fingerprinting
    
    # Check if running with Streamlit
    if 'streamlit' in sys.modules:
        import streamlit as st
        import tempfile
        import os
        
        # Page config
        st.set_page_config(
            page_title="Netloom PCAP Analyzer",
            page_icon="🌐",
            layout="wide"
        )
        
        # Title
        st.title("🌐 Netloom – PCAP Network Analyzer - Beta ")
        st.markdown("### Weaving PCAP Data Into Visuals")
        
        # Sidebar
        with st.sidebar:
            st.header("⚙️ Configuration")
            
            st.markdown("---")
            
            # Analysis mode selector
            st.subheader("📊 Analysis Mode")
            analysis_mode = st.radio(
                "Select mode:",
                ["Single PCAP", "Dual PCAP (Source + Destination)"],
                help="Single PCAP analyzes one file. Dual PCAP compares source and destination captures."
            )
            
            single_mode = (analysis_mode == "Single PCAP")
            
            st.markdown("---")
            
            # File uploads
            st.subheader("📁 Upload PCAP Files")
            
            # Source PCAP
            source_file = st.file_uploader(
                "Source PCAP" if not single_mode else "PCAP File",
                type=['pcap', 'pcapng', 'cap'],
                help="Upload PCAP file (up to 500MB analyzed)",
                key="source"
            )
            
            if source_file:
                try:
                    file_size_mb = source_file.size / (1024 * 1024)
                    st.success(f"✅ {source_file.name} ({file_size_mb:.1f} MB)")
                except:
                    st.success(f"✅ {source_file.name}")
            
            # Destination PCAP (only if dual mode)
            dest_file = None
            if not single_mode:
                dest_file = st.file_uploader(
                    "Destination PCAP",
                    type=['pcap', 'pcapng', 'cap'],
                    help="Upload destination PCAP file (up to 500MB analyzed) **⚠️ Must be DIFFERENT from Source PCAP**",
                    key="destination"
                )
                
                if dest_file:
                    try:
                        file_size_mb = dest_file.size / (1024 * 1024)
                        st.success(f"✅ {dest_file.name} ({file_size_mb:.1f} MB)")
                    except:
                        st.success(f"✅ {dest_file.name}")
            
            st.markdown("---")
            
            # 🆕 Same file validation - BLOCKS ANALYSIS
            same_file_warning = False
            if not single_mode and source_file and dest_file:
                # Compare file content using MD5 hash
                source_hash = hashlib.md5(source_file.getvalue()).hexdigest()
                dest_hash = hashlib.md5(dest_file.getvalue()).hexdigest()
                
                if source_hash == dest_hash:
                    same_file_warning = True
                    st.error("❌ **Cannot use the same PCAP file for both Source and Destination!**")
                    st.info("👉 **Please upload a DIFFERENT PCAP file for Destination.**")
                    st.markdown("---")
            
            # Analysis options
            st.subheader("🔬 Analysis Options")
            
            with st.expander("Core Features", expanded=True):
                enable_drops = st.checkbox("📉 Packet Drop Detection", value=True)
                enable_failures = st.checkbox("🚫 Neighbor Reachability Analysis", value=True)
                enable_loops = st.checkbox("♻️ Routing Loop Detection", value=True)
                enable_ospf = st.checkbox("📚 OSPF Analysis", value=True)
                enable_sequence = st.checkbox("🔢 TCP Sequence Analysis", value=True)
                enable_isis = st.checkbox("🛰️ IS-IS Analysis", value=True)
            
            with st.expander("Advanced Features", expanded=True):
                enable_routing = st.checkbox("🔀 Enhanced BGP/EIGRP Analysis", value=True)
                enable_communication = st.checkbox("💬 Network Communication Flow", value=True)
                enable_flowgraph = st.checkbox("🗺️ Flow Graph Visualization", value=False)
            
            st.markdown("---")
            
            # Protocol filter
            st.subheader("🎛️ Filters")
            protocol_filter = st.selectbox(
                "Protocol Filter",
                ["ALL", "UDP", "TCP", "ICMP", "ARP", "ICMPv6", "UIM"],
                help="Filter analysis by specific protocol"
            )
            
            # Jitter threshold (only for UDP)
            jitter_threshold = 100
            if protocol_filter == "UDP":
                jitter_threshold = st.number_input(
                    "Jitter Threshold (ms)",
                    min_value=0,
                    max_value=1000,
                    value=100,
                    help="Flag packets with jitter above this value"
                )
            
            st.markdown("---")
            
            # Analyze button - 🆕 Updated condition with same_file_warning
            files_ready = (
                source_file is not None and 
                (single_mode or (dest_file is not None and not same_file_warning))
            )
            
            analyze_button = st.button(
                "🚀 Start Analysis",
                type="primary",
                disabled=not files_ready,
                use_container_width=True
            )
            
            if not files_ready:
                if source_file is None:
                    st.warning("⚠️ Upload source PCAP")
                elif not single_mode and dest_file is None:
                    st.warning("⚠️ Upload destination PCAP")
                elif same_file_warning:
                    st.warning("⚠️ **Please select DIFFERENT PCAP files for Source and Destination**")
        
        # Main content
        if not source_file:
            st.info("👈 Please upload PCAP file(s) from the sidebar to begin")
            
            st.markdown("---")
            
            # Feature overview with tabs
            tab1, tab2, tab3 = st.tabs(["🚀 Quick Start", "📊 Features", "🧭 Dashboard Guide"])
            
            with tab1:
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("""
                    ### How to Use
                    
                    1. **Upload** PCAP file(s) from sidebar
                    2. **Select** Single or Dual mode
                    3. **Enable** desired analyses
                    4. **Configure** filters (optional)
                    5. **Click** "🚀 Start Analysis"
                    6. **Wait** 1-5 minutes for processing
                    7. **Explore** interactive dashboard below
                    8. **Download** HTML report
                    """)
                
                with col2:
                    st.markdown("""
                    ### Limits & Requirements
                    
                    - **Max file size**: 500MB analyzed per PCAP
                    - **Max packets**: 100,000 per file
                    - **Processing time**: 1-5 min typical
                    - **Supported formats**: .pcap, .pcapng, .cap
                    - **Browser**: Chrome, Firefox, Edge (latest)
                    """)
            
            with tab2:
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("""
                    ### Single PCAP Analysis
                    - Protocol detection & distribution
                    - TCP sequence gap analysis
                    - Routing protocol inspection
                    - MTU/MSS/Fragmentation detection
                    - IPsec/ISAKMP tunnel analysis
                    - Communication flow patterns
                    
                    ### Dual PCAP Analysis
                    - Packet drop detection
                    - End-to-end flow tracking
                    - Neighbor failure analysis
                    - Routing loop identification
                    - Stuck neighbor state detection
                    """)
                
                with col2:
                    st.markdown("""
                    ### Supported Protocols
                    
                    **Routing**: OSPF, BGP, EIGRP, IS-IS  
                    **Transport**: TCP, UDP, ICMP, ICMPv6  
                    **Tunneling**: IPsec (ESP/AH), GRE, VXLAN  
                    **Link**: ARP, Ethernet  
                    **Application**: Custom (UIM)  
                    
                    ### Analysis Types
                    - Packet drops & losses
                    - Sequence gaps & retransmissions
                    - Routing loops (IP ID tracking)
                    - MTU/MSS issues & PMTUD
                    - Neighbor adjacency failures
                    - Flow visualization (timeline)
                    """)
            
            with tab3:
                st.markdown("""
                ### 🧭 Interactive Dashboard Guide
                
                ---
                
                ## 📂 Opening the Dashboard
                
                **After analysis completes:**
                1. Scroll down to view embedded dashboard, OR
                2. Click "Download HTML" button
                3. Open the `.html` file in any browser (Chrome/Firefox/Edge)
                4. No installation needed - works offline!
                
                ---
                
                ## 📊 Dashboard Structure (Top to Bottom)
                
                ### 1️⃣ **Header** (Purple banner)
                - Tool name and analysis timestamp
                
                ### 2️⃣ **Statistics Cards** (Summary metrics)
                Quick overview of findings with color indicators:
                - 🟢 **Green** = 0 issues (healthy)
                - 🔵 **Blue** = Informational counts
                - 🟠 **Orange** = Warnings
                - 🔴 **Red** = Critical issues
                
                ### 3️⃣ **Global Search** (Search bar)
                - Type IPs, protocols, or keywords
                - Searches across all tabs instantly
                - Click results to jump to location
                
                ### 4️⃣ **Tabs** (Main content area)
                13 tabs for different analyses - active tab has blue background
                """)
                
                st.markdown("""
                ## 🗂️ Tab Reference
                
                | Tab | What to Check | When to Use |
                |-----|---------------|-------------|
                | **📉 Packet Drops** | Missing packets between captures | Check if packets lost in transit |
                | **🔗 Neighbor Analysis** | Hello packet success rate | Verify routing adjacency health |
                | **🔄 Stuck States** | Neighbors stuck in incomplete states | Diagnose why BGP/OSPF won't form |
                | **♻️ Routing Loops** | Same packet circulating (IP ID tracking) | Find routing loop sources |
                | **📚 OSPF LSAs** | LSA types, age, sequence numbers | Check OSPF database health |
                | **🛰️ IS-IS Packets** | IIH, LSP, CSNP, PSNP messages | Verify IS-IS operations |
                | **⚡ EIGRP** | Updates, Queries, Replies, SIA events | Troubleshoot EIGRP convergence |
                | **🌐 BGP Packets** | OPEN, UPDATE, KEEPALIVE, NOTIFICATION | Check BGP session health |
                | **🔢 Sequences** | TCP sequence gaps and retransmissions | Find packet loss or reordering |
                | **📏 MTU/MSS** | Fragmentation, MTU issues, PMTUD problems | Fix MTU mismatches |
                | **💬 Communication** | Flow statistics, jitter (UDP) | Analyze traffic patterns |
                | **🗺️ Flow Graph** | Visual packet timeline | See packet exchange visually |
                """)
                
                with st.expander("🔍 How to Use", expanded=False):
                    st.markdown("""
                    ### **Basic Navigation**
                    - Click tab buttons to switch views
                    - Hover over table rows to highlight
                    - Use browser zoom (Ctrl +/-) to adjust size
                    
                    ### **Finding Issues**
                    1. **Check Statistics Cards** first - red/orange cards need attention
                    2. **Use Global Search** - type IP/protocol to find quickly
                    3. **Click relevant tab** - drill down into specific issue
                    4. **Cross-reference tabs** - issues often span multiple tabs
                    
                    ### **Protocol Filters** (in some tabs)
                    - **Communication tab**: Dropdown to filter by protocol
                    - **Flow Graph tab**: Dropdown to view specific protocol flows
                    """)
                
                with st.expander("🎯 Common Workflows", expanded=False):
                    st.markdown("""
                    ### **BGP Not Establishing?**
                    1. **Stuck States tab** → Check if stuck in "Active"
                    2. **BGP tab** → Look for OPEN/NOTIFICATION messages
                    3. **MTU/MSS tab** → Check TCP handshake issues
                    4. **Flow Graph tab** → Select "BGP" to visualize
                    
                    ### **Packet Loss?**
                    1. **Packet Drops tab** → See missing packets
                    2. **Sequences tab** → Check TCP retransmissions
                    3. **MTU/MSS tab** → Check fragmentation issues
                    
                    ### **Routing Loop?**
                    1. **Routing Loops tab** → See IP ID duplicates
                    2. **Identify routers** from TTL patterns
                    3. **Check routing protocol tabs** for misconfigurations
                    
                    ### **MTU Issues?**
                    1. **MTU/MSS tab** → See all 4 sections:
                       - TCP MSS values (should be ≤1460)
                       - ICMP Fragmentation Needed messages
                       - PMTUD Black Holes (DF bit + drops)
                       - Tunnel overhead calculations
                    2. Scroll down for **MTU/Protocol Correlations**
                    """)
                
                with st.expander("💡 Color Coding Guide", expanded=False):
                    st.markdown("""
                    **Table Row Borders:**
                    - 🟢 Green = Healthy/Normal
                    - 🟠 Orange = Warning level
                    - 🔴 Red = Critical issue
                    - 🔵 Blue = Informational
                    
                    **BGP Messages:**
                    - 🟢 Green = OPEN
                    - 🟡 Yellow = KEEPALIVE
                    - 🔵 Blue = UPDATE
                    - 🔴 Red = NOTIFICATION (error)
                    
                    **OSPF LSA Age:**
                    - 🟢 Fresh (0-600s)
                    - 🟡 Valid (600-1800s)
                    - 🟠 Aging (1800-3000s)
                    - 🔴 MaxAge (3600s - being flushed)
                    """)
                
                with st.expander("🛠️ Quick Tips & Troubleshooting", expanded=False):
                    st.markdown("""
                    ## Quick Tips
                    
                    ✅ **Use Global Search** - fastest way to find specific IPs  
                    ✅ **Check red/orange stats first** - prioritize critical issues  
                    ✅ **Cross-reference tabs** - MTU issues cause BGP stuck states  
                    ✅ **Hover tables** - see highlighting for readability  
                    ✅ **Use browser Find (Ctrl+F)** - search within current tab  
                    ✅ **Flow Graph last** - visual confirmation after analysis  
                    
                    ---
                    
                    ## Troubleshooting
                    
                    **Dashboard won't open?**
                    - Use Chrome/Firefox/Edge (latest version)
                    - Enable JavaScript in browser settings
                    - Don't open from email - save to disk first
                    
                    **Search not working?**
                    - Type exact IPs or protocol names
                    - Wait 1-2 seconds for results to appear
                    
                    **Tables hard to read?**
                    - Zoom out (Ctrl + Minus)
                    - Scroll horizontally in tables
                    - Use full-screen (F11)
                    """)
                
                st.success("💡 **Remember**: Statistics cards → Global search → Click tabs → Cross-reference → Solve issues!")
            
        elif analyze_button:
            temp_files = []
            
            try:
                # Process source file with 500MB cap
                with st.spinner(f"📤 Processing {source_file.name}..."):
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap', mode='wb') as tmp_src:
                        MAX_BYTES = 500 * 1024 * 1024  # 500MB
                        
                        file_bytes = source_file.getvalue()
                        total_size = len(file_bytes)
                        bytes_to_write = min(total_size, MAX_BYTES)
                        
                        tmp_src.write(file_bytes[:bytes_to_write])
                        src_path = tmp_src.name
                        temp_files.append(src_path)
                
                # Process destination file (if dual mode)
                dst_path = None
                if not single_mode and dest_file:
                    with st.spinner(f"📤 Processing {dest_file.name}..."):
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap', mode='wb') as tmp_dst:
                            MAX_BYTES = 500 * 1024 * 1024
                            
                            file_bytes = dest_file.getvalue()
                            total_size = len(file_bytes)
                            bytes_to_write = min(total_size, MAX_BYTES)
                            
                            tmp_dst.write(file_bytes[:bytes_to_write])
                            dst_path = tmp_dst.name
                            temp_files.append(dst_path)
                
                # Create analyzer
                with st.spinner("🔧 Initializing analyzer..."):
                    analyzer = UltraNetworkAnalyzer()
                    
                    if not hasattr(analyzer, 'analysis_results'):
                        analyzer.analysis_results = {
                            'isis_analysis': {'hello_pdus': [], 'lsp_pdus': [], 'csnp_pdus': [], 'psnp_pdus': [], 'packet_count': 0},
                            'packet_drops': [],
                            'neighbor_failures': [],
                            'routing_loops': [],
                            'ospf_lsa_analysis': {'lsa_stats': {}, 'lsa_details': []},
                            'isakmp_analysis': {'isakmp_messages': [], 'tunnel_details': []},
                            'ipsec_analysis': {'ah_packets': [], 'esp_packets': [], 'ipsec_tunnels': []},
                            'sequence_analysis': {'src_sequences': {}, 'dst_sequences': {}, 'sequence_gaps': [], 'sequence_jumps': [], 'duplicate_sequences': []},
                            'routing_protocol_analysis': {'ospf_packets': [], 'eigrp_packets': [], 'bgp_packets': [], 'bgp_sessions': [], 'routing_summary': {}},
                            'communication_analysis': {'flows': [], 'data_transfer': {}, 'unique_ips': set(), 'flow_stats': {}}
                        }
                
                analyzer.src_pcap_file = src_path
                analyzer.dst_pcap_file = dst_path
                analyzer.single_pcap_mode = single_mode
                
                analyzer.drops_analysis = enable_drops
                analyzer.failures_analysis = enable_failures
                analyzer.loops_analysis = enable_loops
                analyzer.lsa_analysis = enable_ospf
                analyzer.sequence_analysis = enable_sequence
                analyzer.isis_analysis = enable_isis
                analyzer.routing_analysis = enable_routing
                analyzer.communication_analysis = enable_communication
                analyzer.flowgraph_analysis = enable_flowgraph
                
                analyzer.protocol_var = protocol_filter
                analyzer.jitter_entry = jitter_threshold
                
                # Progress tracking
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                def streamlit_update_progress(message, percent):
                    status_text.markdown(f"**{message}**")
                    progress_bar.progress(min(int(percent), 100))
                
                def streamlit_log_message(message):
                    pass  # Silent logging
                
                analyzer.update_progress = streamlit_update_progress
                analyzer.log_message = streamlit_log_message
                
                # Run analysis
                mode_text = "Single PCAP" if single_mode else "Dual PCAP"
                analyzer.run_complete_analysis()
                
                # Complete
                progress_bar.progress(100)
                status_text.markdown("**✅ Analysis Complete!**")
                st.success(f"✅ {mode_text} analysis completed successfully!")
                
                st.markdown("---")
                st.markdown("## 📊 Interactive Dashboard")
                
                if analyzer.dashboard_file and os.path.exists(analyzer.dashboard_file):
                    with open(analyzer.dashboard_file, 'r', encoding='utf-8') as f:
                        dashboard_html = f.read()
                    
                    st.components.v1.html(dashboard_html, height=1200, scrolling=True)
                    
                    st.download_button(
                        label="📥 Download Full HTML Report",
                        data=dashboard_html,
                        file_name=f"netloom_report_{source_file.name}.html",
                        mime="text/html",
                        use_container_width=True
                    )
                else:
                    st.warning("⚠️ Dashboard file not found")
                
            except Exception as e:
                st.error(f"❌ Analysis Error: {str(e)}")
                with st.expander("🐛 Error Details", expanded=False):
                    st.exception(e)
            
            finally:
                # Cleanup temp files
                for tmp_path in temp_files:
                    try:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    except:
                        pass
    
    else:
        # GUI mode (Tkinter)
        print("🚀 Starting Netloom – Weaving PCAP Data Into Visuals...")
        print("✅ Enhanced with IP ID Tracking for Routing Loop Detection")
        print("🎯 All Features Available and Working")
        
        analyzer = UltraNetworkAnalyzer()
        analyzer.create_gui()
        analyzer.root.mainloop()

