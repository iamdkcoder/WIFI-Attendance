from flask import Flask
from scapy.all import ARP, sniff
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/mydb'
db = SQLAlchemy(app)

class WiFiLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), nullable=False)
    ip_address = db.Column(db.String(15))
    timestamp = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'<WiFiLog {self.mac_address} connected at {self.timestamp}>'

def log_wifi_connection(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 1:  # Check if it's an ARP request (ARP op code 1)
        mac_address = packet[ARP].hwsrc
        ip_address = packet[ARP].psrc
        wifi_log = WiFiLog(mac_address=mac_address, ip_address=ip_address, timestamp=datetime.now())
        db.session.add(wifi_log)
        db.session.commit()

@app.route('/')
def index():
    return 'Welcome to WiFi Logger!'

if __name__ == '__main__':
    # db.create_all()  # Create database tables before starting the app
    with app.app_context():
    # Start sniffing ARP packets in a separate thread
        sniff(prn=log_wifi_connection, filter="arp", store=0, count=0)

        app.run(debug=True)
