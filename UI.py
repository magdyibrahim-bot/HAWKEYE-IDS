import threading
import joblib
import numpy as np
import pandas as pd
import os

from scapy.all import rdpcap

from flask import Flask, render_template, request, redirect, flash

from DB import Database
from rule import Rule
from log import Log
from alert import Alert
from signature_IDS import SignatureIDS
from alert_analyzer import AlertAnalyzer
from anomaly_IDS import AnomalyIDS

IDS_app = Flask(__name__)
IDS_app.secret_key = 'super-secret'

UPLOAD_FOLDER = 'uploads'

os.makedirs(
    UPLOAD_FOLDER, 
    exist_ok=True
)

# ========== Load model components ========== #
model = joblib.load(
    "Models/Models/tst1_stk_classifier.joblib"
)
iso_forest = joblib.load(
    "Models/Models/isolation_forest.joblib"
)
scaler = joblib.load(
    "Models/Scaler/scaler_minmax.save"
)
label_encoder = joblib.load(
    "Models/Label Encoder/lb_encoder.pkl"
)
feature_order = joblib.load(
    "Models/Features_Order/features_order.pkl"
)

# ========== Global Rule Cache ========== #
rules = []

@IDS_app.route("/")
def signature_dashboard():
    top_src_ip = 'N/A'
    top_dst_ip = 'N/A'
    
    alerts = []
    logs = []
    num_alerts = 0
    loaded_rules = []

    try:
        db = Database("DB/IDS.db")
        conn = db.connect()

        logs = [
            log for log in Log.get_logs_from_db(conn) 
            if log.method == "signature"
        ]

        alerts = [
            alert for alert in Alert.get_alerts_from_db(conn) 
            if alert.method == "signature"
        ]

        loaded_rules = Rule.get_rules_from_db(conn)

        num_alerts = len(alerts)

        analyzer = AlertAnalyzer(alerts)
        top_src_ip = analyzer.get_top_src_ip()
        top_dst_ip = analyzer.get_top_dst_ip()

        conn.close()
        
    except Exception as e:
        print(f"[Error] {e}")
        return "Dashboard error", 500

    return render_template(
        "index.html",
        title="Signature IDS Dashboard",
        logs=logs,
        alerts=alerts,
        rules=loaded_rules,      
        num_alerts=num_alerts,
        top_src_ip=top_src_ip, 
        top_dst_ip=top_dst_ip
    )



@IDS_app.route("/anomaly")
def anomaly_dashboard():
    top_src_ip = 'N/A'
    top_dst_ip = 'N/A'
    
    alerts = []
    logs = []
    
    num_alerts = 0

    try:
        db = Database("DB/IDS.db")
        conn = db.connect()
        
        logs = [
            log for log in Log.get_logs_from_db(conn) 
            if log.method == "anomaly"
        ]
        
        alerts = [
            alert for alert in Alert.get_alerts_from_db(conn) 
            if alert.method == "anomaly"
        ]
        
        num_alerts = len(alerts)

        analyzer = AlertAnalyzer(alerts)
        top_src_ip = analyzer.get_top_src_ip()
        top_dst_ip = analyzer.get_top_dst_ip()

        conn.close()
    
    except Exception as e:
        print(f"[Error] {e}")
        return "Anomaly dashboard error", 500

    return render_template(
        "anomaly.html", 
        title="Anomaly IDS Dashboard",                   
        logs=logs, 
        alerts=alerts, 
        num_alerts=num_alerts,
        top_src_ip=top_src_ip, 
        top_dst_ip=top_dst_ip
    )


@IDS_app.route("/csv", methods=["GET", "POST"])
def upload_csv():
    predictions = []
    stats = {}

    if request.method == "POST":
        file = request.files.get("csv_file")
        
        if not file or file.filename == "":
            flash("Please upload a valid CSV file")
            return redirect(request.url)

        try:
            df = pd.read_csv(file)
            path = os.path.join("Uploads", "temp_uploaded.csv")
            df.to_csv(path, index=False)

            anomaly_ids = AnomalyIDS(
                model,
                iso_forest, 
                scaler, 
                label_encoder, 
                feature_order
            )
            
            predictions, stats = anomaly_ids.predict_from_csv(path)

        except Exception as e:
            print(f"[CSV Error] {e}")
            flash("An error occurred while processing the file.")
            return redirect(request.url)

    return render_template(
        "csv.html", 
        predictions=predictions, 
        stats=stats,
        title="CSV Anomaly Detection"
    )


@IDS_app.route("/upload_pcap", methods=["GET", "POST"])
def upload_pcap():
    alerts = []

    if request.method == "POST":
        file = request.files.get("pcap_file")
        
        if not file or file.filename == "":
            flash("Please upload a PCAP file")
            return redirect(request.url)

        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        try:
            
            packets = rdpcap(filepath)
            
            sig_ids = SignatureIDS(rules)
            alerts = sig_ids.predict_from_pcap(packets)

            flash("PCAP scanned successfully.")
        
        except Exception as e:
            print(f"[PCAP Error] {type(e).__name__}: {e}")
            flash("Failed to process PCAP.")

    return render_template(
        "pcap.html", 
        alerts=alerts, 
        title="PCAP Signature Detection"
    )


@IDS_app.route("/rules")
def rules_dashboard():
    rules = []

    try:
        db = Database("DB/IDS.db")
        conn = db.connect()

        if not conn:
            print("[Error] DB Connection Failed.")
            return "Database connection error", 500

        rules = Rule.get_rules_from_db(conn)
        conn.close()

    except Exception as e:
        print(f"[Error] {e}")
        return "Rules dashboard error", 500

    return render_template(
        "rules.html", 
        title="Rules Dashboard", 
        rules=rules
    )


# ========== Main ========== #
if __name__ == "__main__":
    try:
        db = Database("DB/IDS.db")
        conn = db.connect()

        if not conn:
            print("[Error] DB Connection Failed.")
            exit(1)

        # Load rules
        rules = Rule.get_rules_from_db(conn)

        # Clear old alerts/logs
        db.clear_table("logs")
        db.clear_table("alerts")
        conn.close()

        # Read test pcap
        packets = rdpcap("test/test3.pcap")

        # Start Signature IDS
        threading.Thread(
            target=lambda: 
            SignatureIDS(rules).detect(packets),
            daemon=True
        ).start()

        # Start Anomaly IDS
        threading.Thread(
            target=lambda: 
            AnomalyIDS(
                model, 
                iso_forest, 
                scaler, 
                label_encoder, 
                feature_order
            ).detect(packets),
            daemon=True
            ).start()

        IDS_app.run(
            debug=True,
            port=8000
        )

    except Exception as e:
        print(f"[Startup Error] {e}")
