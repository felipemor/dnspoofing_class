from flask import Flask, render_template, send_file
import threading
import spoof_engine
import pandas as pd
from collections import Counter
import os

app = Flask(__name__)

@app.route("/")
def index():
    csv_path = "logs/spoof_log.csv"
    # If CSV does not exist or is empty, create empty DataFrame with English column names
    if not os.path.exists(csv_path) or os.stat(csv_path).st_size == 0:
        df = pd.DataFrame(columns=["Date", "Domain", "Responded_IP", "Real_IP"])
    else:
        df = pd.read_csv(csv_path, names=["Date", "Domain", "Responded_IP", "Real_IP"], header=None)

    domain_counts = Counter(df["Domain"]) if not df.empty else {}
    labels = list(domain_counts.keys())
    data = list(domain_counts.values())

    return render_template("index.html",
                           logs=df.to_dict(orient="records"),
                           chart_labels=labels,
                           chart_data=data)

@app.route("/export/pdf")
def export_pdf():
    csv_path = "logs/spoof_log.csv"
    df = pd.read_csv(csv_path, names=["Date", "Domain", "Responded_IP", "Real_IP"], header=None)
    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, "Spoofing Report", ln=True, align="C")
    pdf.ln()

    for _, row in df.iterrows():
        pdf.cell(200, 10, f"{row['Date']} | {row['Domain']} → {row['Responded_IP']} (Query: {row['Real_IP']})", ln=True)

    output_path = "logs/spoof_log.pdf"
    pdf.output(output_path)
    return send_file(output_path, as_attachment=True)

if __name__ == "__main__":
    print("[*] Starting sniffing thread...")
    t = threading.Thread(target=spoof_engine.start_sniffing)
    t.daemon = True
    t.start()
    print("[*] Sniffing thread started.")

    print("[*] Starting Flask server on port 8080...")
    app.run(host="0.0.0.0", port=8080, debug=True)
