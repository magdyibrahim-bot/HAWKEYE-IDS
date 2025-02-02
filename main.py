from flask import Flask, render_template
from scapy.all import rdpcap
from log import Log
from alert import Alert
from match_rule import match_rule
from packet import Packet
from rule import Rule
import sqlite3
import threading

####################################################################################################################

IDS_app = Flask(__name__)
packets = rdpcap("PCAP/http_slowloris.pcap")

####################################################################################################################

def establish_connection():
    try:
        conn = sqlite3.connect('DB/IDS.db', check_same_thread=False,timeout=120)
        conn.row_factory = sqlite3.Row
        return conn
    
    except sqlite3.Error as e:
     
        print(f"[Database Error] {e}")
        return None
    
####################################################################################################################

def close_connection(conn):
    if conn:
        conn.close()

####################################################################################################################

def process_packet(pkt, rules):
    try:
        conn = establish_connection()
        
        if not conn:
            
            print("Failed to establish database connection.")
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

                log = Log(time, action, src_ip, dst_ip, message)
                alert = Alert(time, src_ip, dst_ip, message)

                log.add_to_log_table(conn)
                alert.add_to_alert_table(conn)

                print(f"[Alert] Packet {packet} matches rule {rule_1}. Logged and alerted.")

    
    except Exception as e:
    
        print(f"[Error] Error processing packet: {e}")
    
    finally:
        
        close_connection(conn)

####################################################################################################################

def core(packets, rules):
    threads = []
    
    for pkt in packets:
        
        thread = threading.Thread(target=process_packet, args=(pkt, rules))
        threads.append(thread)
        thread.start()

    for thread in threads:
        
        thread.join()

####################################################################################################################
def clear_table(table_name):
    try:
        conn = establish_connection()
        if not conn:
            print(f"[Error] Failed to connect to the database.")
            return False
        
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM {table_name};")  # Delete all records
        conn.commit()
        print(f"[Success] All records from '{table_name}' have been deleted.")

        return True

    except sqlite3.Error as e:
        print(f"[Database Error] {e}")
        return False

    finally:
        close_connection(conn)
###################################################

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
        
    except Exception as e:
        
        print(f"[Error] Error fetching data for dashboard: {e}")
        return "An error occurred while loading the dashboard.", 500
    
    finally:
        
        close_connection(conn)

    return render_template('index.html', title="Dashboard", logs=logs, rules=rules, alerts=alerts, num_alerts=num_alerts)

#####################################################################################################################

if __name__ == "__main__":
    try:
        conn = establish_connection()
        if not conn:
            print("[Error] Failed to connect to the database.")
            exit(1)

        rules = Rule.get_rules_from_db(conn)
        close_connection(conn)

        clear_table("logs")
        
        core_thread = threading.Thread(target=core, args=(packets, rules), daemon=True)
        core_thread.start()

        IDS_app.run(debug=True, port=8000) 

    except Exception as e:
        print(f"[Critical Error] {e}")