Overview
This project consists of two main tools:

DNS Spoofing — to intercept and spoof DNS requests.

DoS Attack — simple script to perform Denial of Service attacks.

Dependencies Installation
To install all necessary dependencies, run the following command:


pip install flask scapy pandas fpdf requests
How to Run DNS Spoofing Tool
Run the DNS spoofing application with:


sudo python3 app.py
Note: sudo is required to grant the necessary permissions to capture and spoof network packets.

After running, open your web browser and navigate to:

http://localhost:8080
to access the dashboard and monitor the spoofing activity.

How to Run DoS Script
To run the DoS script, first make sure requests is installed:

pip install requests

Then execute the script:
python dos.py


⚠️ Disclaimer: This project was developed strictly for educational and research purposes only.
I do not take any responsibility for any misuse, illegal activity, or damage caused by this code.
Use it at your own risk, and always within legal and ethical boundaries.
