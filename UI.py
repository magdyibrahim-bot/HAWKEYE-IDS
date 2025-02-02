from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template
from scapy.all import rdpcap

####################################################################################################################

import sqlite3
import threading

####################################################################################################################

from log import Log
from alert import Alert
from match_rule import match_rule
from packet import Packet
from rule import Rule
from DB import clear_table

####################################################################################################################

IDS_app = Flask(__name__)
packets = rdpcap("PCAP/arpspoof.pcap")

####################################################################################################################

def establish_connection():
    try:
        conn = sqlite3.connect('DB/IDS.db', check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL;')  
        return conn
    
    except sqlite3.Error as e:
        print(f"[Database Error] {e}")
        return None

####################################################################################################################

def close_connection(conn):
    if conn:
        conn.close()
        
#####################################################################################################################

def update_Top_src_ip(alerts):
    src_ip_count = {}
    
    for alert in alerts:
        
        if alert.src_ip in src_ip_count:
            src_ip_count[alert.src_ip] += 1
            
        else:
            src_ip_count[alert.src_ip] = 1
    
    for ip, count in src_ip_count.items(): 
        
        top_ip = 'N/A'
        top = 1
        
        if count > top:
            
            top = count
            top_ip = ip
            
    return top_ip

#####################################################################################################################

def update_Top_dst_ip(alerts):
    dst_ip_count = {}
    
    for alert in alerts:
        
        if alert.dst_ip in dst_ip_count:
            dst_ip_count[alert.dst_ip] += 1
            
        else:
            dst_ip_count[alert.dst_ip] = 1
    
    for ip, count in dst_ip_count.items(): 
        
        top_ip = 'N/A'
        top = 1
        
        if count > top:
            
            top = count
            top_ip = ip
            
    return top_ip
    

#####################################################################################################################

def process_packet(pkt, rules):
    
    try:
        conn = establish_connection()
        
        if not conn:
        
            print("[Error] Failed to establish database connection.")
            
            return

        packet = Packet(pkt)

        for rule in rules:
        
            rule_1 = Rule(rule)
        
            if match_rule(packet, rule_1):
        
                time = packet.get_packet_time()
                src_ip = packet.get_src_ip()
                dst_ip = packet.get_dst_ip()
                
                action = rule_1.action
                message = rule_1.options.get("msg", "No message specified")
                layer = rule_1.options.get("attack", "No message specified")

                log = Log(time, action, src_ip, dst_ip, message, layer)
                alert = Alert(time, src_ip, dst_ip, message, layer)
                
                log.add_to_log_table(conn)
                alert.add_to_alert_table(conn)
                

    except Exception as e:
        
        print(f"[Error] Error processing packet: {e}")

    finally:
        
        close_connection(conn)

####################################################################################################################

def core(packets, rules):
    
    with ThreadPoolExecutor(max_workers=5) as executor:  
        
        futures = [executor.submit(process_packet, pkt, rules) for pkt in packets]

        for future in futures:
            
            future.result()  

####################################################################################################################

@IDS_app.route("/")
def UI():
    conn = establish_connection()
    
    if not conn:
        return "Failed to connect to the database.", 500

    try:
        rules = Rule.get_rules_from_db(conn)
        
        logs = Log.get_logs_from_db(conn)
        
        alerts = Alert.get_alerts_from_db(conn)
        
        num_alerts = len(alerts)
        
        top_src_ip = update_Top_src_ip(alerts)
        
        top_dst_ip = update_Top_dst_ip(alerts)
        
    
    except Exception as e:
     
        print(f"[Error] Error fetching data for dashboard: {e}")
        
        return "An error occurred while loading the dashboard.", 500
    
    finally:
    
        close_connection(conn)

    return render_template('index.html', title="Dashboard",logs=logs, rules=rules, alerts=alerts, num_alerts=num_alerts, top_src_ip=top_src_ip, top_dst_ip=top_dst_ip)

#####################################################################################################################

if __name__ == "__main__":
    
    try:
        
        conn = establish_connection()
        
        if not conn:
            print("[Error] Failed to connect to the database.")
            
            exit(1)

        rules = Rule.get_rules_from_db(conn)
        
        clear_table("logs",conn)
        
        clear_table("alerts",conn)
        
        close_connection(conn)
        
        threading.Thread(target=lambda: core(packets, rules), daemon=True).start()

        IDS_app.run(debug=True, port=9000)

    except Exception as e:
        
        print(f"[Critical Error] {e}")