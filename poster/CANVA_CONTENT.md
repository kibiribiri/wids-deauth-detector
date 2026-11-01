# A1 Poster: Canva Content Pack

**Format:** A1 portrait, 594 x 841 mm (Canva: Create design, Custom size).
**Colours:** navy `#0B2545`, teal `#13A89E`, amber `#F2A541`, light grey `#F4F6F8`, white.
**Margins:** 25 mm; gutter 12 mm; 3 equal columns.
**Fonts:** title 80 to 90 pt bold; section headings 36 to 40 pt bold; body 22 to 26 pt; captions 18 pt; code/log 16 pt monospace.
**Images:** use `results/confusion_matrix_random_forest.png` and `results/feature_importance.png` at full column width (200+ dpi).

---

## Header

**Title:** Machine-Learning Wireless Intrusion Detection System
**Subtitle:** Detecting 802.11 Deauthentication Floods with a Random Forest
**Author:** Ted Kamau
**Line:** WIDS/WIPS Assignment, November 2026
**Key takeaway strip:** A Random Forest looks at each MAC address every second and flags deauthentication floods. On held-out traffic it got 100% accuracy and named the MAC that caused the flood.

---

## Column 1

### The problem
Deauthentication frames are management frames, and many networks do not protect them. An attacker can spoof them and kick clients off the network. That is a denial of service, and it can also help an evil twin attack. A WIDS detects this and raises an alert. A WIPS would also block it. I built the WIDS.

### Dataset
I used one capture from the public **WPA3 Attacks Dataset** (Mendeley Data, CC BY 4.0): the deauthentication attack capture.

- 916 s, 722,606 frames
- 515,384 normal frames
- 207,222 deauth-labelled frames
- 370 s flood; peak over 1,300 deauth/s
- Isolated WPA3 testbed built by the dataset authors
- No new traffic captured or generated

**Citation:** Halbouni, Ong & Leow (2026), *WPA3 Attacks Dataset*, DOI 10.17632/cxx5t5nw7z.3, CC BY 4.0.

### Features
One row per **transmitter MAC per second** (2,692 rows, 235 MACs). There are 22 features, including:

| Feature | Why it matters |
|---|---|
| deauth count / ratio | Direct flood signal |
| frames per second | Flood volume |
| frame-type counts | Management vs data mix |
| mean / std RSSI | Transmitter proximity |
| unique destinations | Broadcast/spoof pattern |
| retry ratio | Channel stress |
| reason-code count | Deauth/disassoc variety |

The MAC address and timestamp are **not** model inputs.

### System architecture
Build this as a 5-box flow:

**Capture** (monitor-mode PCAP) -> **Feature extraction** (tshark, 1 s windows per MAC) -> **Random Forest** (P(deauth flood)) -> **Episode rule** (score at least 0.5, at least 20 deauth/s, at least 2 s) -> **Alert + CSV log** (MAC, time, rate, RSSI, score).

---

## Column 2

### Machine learning
- Random Forest: 300 trees, depth 10, balanced class weights.
- Baseline: Decision Tree, depth 6.
- Median imputation for missing RSSI.
- **Time-based split:** earlier traffic for training, later traffic held out. No random window leakage.
- 1,973 training windows; 719 test windows (607 normal, 112 attack).

### Results
| Metric | Random Forest | Decision Tree |
|---|---:|---:|
| Accuracy | 100.0% | 100.0% |
| Precision | 100.0% | 100.0% |
| Recall | 100.0% | 100.0% |
| F1 | 100.0% | 100.0% |

**Confusion matrix (RF):** TN 607, FP 0, FN 0, TP 112.

The flood is easy to separate. Normal traffic still has 436 windows with some deauth frames (up to 64/s), but the attack sends hundreds to over 1,300/s. The lowest attack score was 0.85 and the highest normal score was 0.28.

**Figures:** confusion matrix (left), feature importance (right).
Top features: `n_deauth`, `dst_diversity`, `n_mgmt`, `frames_per_sec`, `n_frames`, `deauth_ratio`.

---

## Column 3

### Detection demo
60 s normal excerpt:

```
No deauthentication-flood episodes detected.
```

60 s attack excerpt:

```
[ALERT 1] 07:34:12 to 07:35:07
MAC 02:00:00:00:00:72
deauth=215/s  RSSI=-29 dBm  score=1.00

[ALERT 2] 07:34:12 to 07:35:07
MAC 02:00:00:00:00:cb
deauth=1289/s  RSSI=-32 dBm  score=1.00
```

On the full 15-minute capture the detector found the two sustained floods. Two short low-rate exchanges (3 to 16/s) were filtered by the 20/s rule.

### Limitations
- One capture, one testbed, so 100% is optimistic.
- 1-second windows, and only deauth floods are modelled.
- MAC spoofing makes the source in the alert unreliable.
- No live monitor-mode test because the VM has no adapter. The PCAP replay path is used.
- Two low-rate episodes are false positives at window level, but the rate rule suppresses them.

### What I would improve
- Test on AWID3 and new captures from different networks.
- Add disassociation floods, beacon floods and evil twin detection.
- Try sliding windows and online learning for concept drift.
- Test evasion with low-rate, bursty or spoofed-source attacks.
- Add a live dashboard and maybe AP integration.

### AI use
I used OpenCode with a DeepSeek model to help me find and download the public dataset, set up the Python pipeline, debug the tshark extraction and draft the poster text. I checked the dataset and code, ran the training and evaluation, and confirmed that no MAC address or timestamp is used as a feature. All reported numbers come from the included scripts.

### Reproduce
```bash
python prepare_data.py
python train.py
python detect.py --pcap data/demo_attack.pcap
```

---

## Footer
Code and results: local submission. Dataset DOI: 10.17632/cxx5t5nw7z.3. Built with Python, tshark and scikit-learn.
