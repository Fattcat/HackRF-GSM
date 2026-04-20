# HackRF-GSM
Testing
- for educational purposes only !
<p align="center">
<img src="https://visitor-badge.laobi.icu/badge?page_id=Fattcat.HackRF-GSM" alt="Visitors"/>

# Terminal 1 – capture
grgsm_livemon -f 947.6M -g 40

# Terminal 2 – detect cypher
python3 gsm_cipher_detector.py

# Terminal 3 – Wireshark visualization
sudo wireshark -k -Y "gsm_a.dtap.msg_rr_type == 0x35" -i lo
