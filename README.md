# 🛡️ HAWKEYE IDS - Intelligent Intrusion Detection System  
**Graduation Project - Faculty of Computers and Artificial Intelligence, Cairo University (2025)**

---

## 📌 Overview

**HAWKEYE IDS** is an Intrusion Detection System that combines both anomaly-based and signature-based detection techniques to effectively identify and prevent known and unknown cyber threats in real-time network traffic.

This system was developed as our final year graduation project, and it aims to offer high accuracy, fast detection, and an interactive interface for real-time monitoring.

---

## 🚀 Features

- ✅ Signature or Anomaly detection engine
- 🔍 Detects known attacks using signature rules
- 🤖 Detects unknown attacks using machine learning (Isolation Forest + Ensemble learning)
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
├── models/                 # Pre-trained ML models (DNN, Isolation Forest)
├── signature_db/           # SQLite DB containing rules
├── utils/                  # Feature extraction and packet parser
├── dashboard/              # Flask-based web interface
├── static/                 # Bootstrap, JS, CSS
├── templates/              # HTML templates
├── UI.py                  # Main Flask app
├── README.md               # This file
```

## 🔧 Installation
- git clone https://github.com/magdyibrahim-bot/IDS_GradProjecet_CairoUni.git
- cd IDS_GradProjecet_CairoUni
- pip install -r requirements.txt
- python app.py

Then open your browser at http://127.0.0.1:5000/
---

## 🧪 How It Works

- Anomaly Engine: Trained on clean traffic + known attacks using hybrid model (Isolation Forest + Ensembel Learning). Detects abnormal behavior.

- Signature Engine: Matches traffic against predefined malicious patterns stored in a local database.

- Real-time Packet Parser: Extracts features from network packets using scapy.
---


## 🎯 Goals

- Detect zero-day attacks

- Reduce false positives

- Provide an easy-to-use dashboard

- Enhance real-time performance

---

## 📄 License

- This project is for academic use. Feel free to fork and build on it, giving credit where it's due.

---

## 📬 Contact
- 📧 Email: magdyibrahim.bot@gmail.com

- 🌐 LinkedIn: Your LinkedIn

- 📁 Portfolio: [Coming Soon...]
  ---
