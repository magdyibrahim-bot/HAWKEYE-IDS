# 🛡️ HAWKEYE IDS - Intelligent Intrusion Detection System  
**Graduation Project - Faculty of Computers and Artificial Intelligence, Cairo University (2025)**

---

## 📌 Overview

**HAWKEYE IDS** is a hybrid Intrusion Detection System that combines both anomaly-based and signature-based detection techniques to effectively identify and prevent known and unknown cyber threats in real-time network traffic.

This system was developed as our final year graduation project, and it aims to offer high accuracy, fast detection, and an interactive interface for real-time monitoring.

---

## 🚀 Features

- ✅ Hybrid detection engine (Anomaly + Signature based)
- 🔍 Detects known attacks using signature rules
- 🤖 Detects unknown attacks using machine learning (Isolation Forest + DNN + Z-Score)
- 📈 Real-time packet feature extraction using Scapy
- 📊 Dashboard built with Flask for live alerts and log visualization
- 🧠 Trained on CIC-IDS-2017 dataset

---

## 🛠️ Technologies Used

| Component         | Technology |
|------------------|------------|
| Frontend         | HTML, Bootstrap, JS |
| Backend          | Python (Flask) |
| ML Models        | Scikit-learn, TensorFlow |
| Real-time Traffic| Scapy |
| Dataset          | CIC-IDS-2017 |
| Signature Rules  | Custom SQLite Database |
| Deployment       | GitHub / Localhost |

---

## 📂 Project Structure

```bash
HAWKEYE_IDS/
├── models/                  # Pre-trained ML models (DNN, Isolation Forest)
├── signature_db/           # SQLite DB containing rules
├── utils/                  # Feature extraction and packet parser
├── dashboard/              # Flask-based web interface
├── static/                 # Bootstrap, JS, CSS
├── templates/              # HTML templates
├── app.py                  # Main Flask app
├── README.md               # This file
```

## 🔧 Installation
- git clone https://github.com/magdyibrahim-bot/IDS_GradProjecet_CairoUni.git
- cd IDS_GradProjecet_CairoUni
- pip install -r requirements.txt
- python app.py

Then open your browser at http://127.0.0.1:5000/
---

