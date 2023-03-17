import datetime
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import scapy.all as scapy

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'

# Set up Flask-SocketIO
socketio = SocketIO(app)

# Global variables
sniffing = False
packets = []
current_port_filter = None

def start_sniffing():
    global sniffing
    sniffing = True
    scapy.sniff(prn=process_packet)

def stop_sniffing():
    global sniffing
    sniffing = False

def apply_filter(port):
    global current_port_filter
    current_port_filter = int(port)
    socketio.emit('filter_applied', current_port_filter)

def remove_filter():
    global current_port_filter
    current_port_filter = None

def process_packet(packet):
    global packets, sniffing, current_port_filter

    if not sniffing:
        return

    packets.append(packet)
    timestamp = packet.time
    date_time = datetime.datetime.fromtimestamp(timestamp).strftime('%Y/%m/%d - %H:%M:%S.%f')[:-3]

    source, destination = '', ''
    source_port, destination_port = '', ''
    protocol, raw_data = '', ''
    length = len(packet)

    if packet.haslayer('IP'):
        ip_layer = packet.getlayer('IP')
        source, destination = ip_layer.src, ip_layer.dst
        protocol = ip_layer.proto

        if ip_layer.haslayer('TCP'):
            tcp_layer = ip_layer.getlayer('TCP')
            source_port, destination_port = tcp_layer.sport, tcp_layer.dport
        elif ip_layer.haslayer('UDP'):
            udp_layer = ip_layer.getlayer('UDP')
            source_port, destination_port = udp_layer.sport, udp_layer.dport
        elif ip_layer.haslayer('ICMP'):
            icmp_layer = ip_layer.getlayer('ICMP')
            source_port, destination_port = icmp_layer.type, icmp_layer.code

    elif packet.haslayer('ARP'):
        arp_layer = packet.getlayer('ARP')
        source, destination = arp_layer.hwsrc, arp_layer.hwdst
        protocol = 'ARP'

    elif packet.haslayer('Raw'):
        raw_layer = packet.getlayer('Raw')
        raw_data = raw_layer.hexdump() if hasattr(raw_layer, 'hexdump') else str(raw_layer)
        protocol = 'Raw'

    packet_dict = {
        'packetnum': len(packets),
        'timestamp': date_time,
        'source': source,
        'source_port': source_port,
        'destination': destination,
        'destination_port': destination_port,
        'protocol': protocol,
        'length': length,
        'raw_data': raw_data,
    }

    if current_port_filter is None or \
       source_port == int(current_port_filter) or \
       destination_port == int(current_port_filter):
        socketio.emit('packet', packet_dict)

@app.route('/')
def main_page():
    return render_template('index.html')

@socketio.on('start_sniffing')
def start_sniffing_route():
    start_sniffing()

@socketio.on('stop_sniffing')
def stop_sniffing_route():
    stop_sniffing()

@socketio.on('apply_filter')
def apply_filter_route(port):
    if port.strip() == '':
        remove_filter()
    else:
        try:
            port_num = int(port)
            apply_filter(port_num)
        except ValueError:
            remove_filter()

@socketio.on('remove_filter')
def remove_filter_route():
    remove_filter()

# Start the Flask-SocketIO app
if __name__ == '__main__':
    socketio.run(app)