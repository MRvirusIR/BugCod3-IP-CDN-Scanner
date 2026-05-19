# 🧠 BugCod3 IP CDN Scanner

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 🚀 Overview

**BugCod3 IP CDN Scanner** is a high-performance asynchronous network intelligence tool designed for analyzing IP addresses, domains, and CIDR ranges.

It provides deep visibility into exposed services, CDN usage, ASN data, and reverse DNS information — all through a fast, multi-worker scanning engine.

This project is built for **research, educational, and network analysis purposes**.

---

## ⚡ Key Features

- 🚀 High-performance async scanning engine
- 🌐 Supports IPs, Domains, and CIDR ranges
- 🔍 CDN detection (Cloudflare, Google, Fastly, Akamai, and more)
- 🧠 ASN & ISP identification
- 🌍 Reverse DNS (Domain resolution from IP)
- ⚡ TCP port scanning (default: 80, 443)
- 📊 Real-time terminal dashboard (Rich UI)
- 📄 JSON & HTML reporting system
- 🎨 Modern dark-themed HTML report with CDN highlighting

---

## 📥 Input Support

The scanner accepts multiple input types:

- Single IP: `1.1.1.1`
- Domain: `example.com`
- CIDR range: `192.168.0.0/24`
- Bulk file input: `targets.txt`

---

## ⚙️ Installation

```bash
git clone https://github.com/your-username/bugcod3-ip-cdn-scanner.git
cd bugcod3-ip-cdn-scanner

pip install -r requirements.txt
```
---
## 🚀 Usage

Run the scanner:
```bash
python3 main.py
```
---
## 📁 Project Structure
```txt
.
├── core/               # Engine, worker, queue system
├── scanner/            # CDN, ASN, CIDR logic
├── output/             # JSON & HTML report generators
├── data/targets.txt    # Input file
├── config.py           # Configuration settings
├── main.py             # Entry point

```
---
## ⚙️ Configuration
```bash
MAX_WORKERS = 500
BATCH_SIZE = 200

TIMEOUT = 4
RETRIES = 2

PORTS = [80, 443]

SEMAPHORE_LIMIT = 1000
```
---
## 📊 Output Example
🔹 Terminal Dashboard

▫️Live scanning speed (CPS)

▫️Total scanned targets

▫️Open hosts counter

▫️CDN distribution stats


---
## 🧠 Technical Highlights
▫️Fully asynchronous scanning architecture (asyncio)

▫️Worker-based concurrency model

▫️Semaphore-based rate limiting

▫️CIDR expansion engine

▫️Reverse DNS resolution (PTR lookup)

▫️Safe schema normalization layer

▫️Jinja2-based HTML report generator

▫️Live terminal dashboard using Rich

---
## 📦 Output Files
After execution:
```bash
report.json
report.html
```
---
## 📌 Notes
▫️Large CIDR ranges may be partially skipped for stability

▫️DNS and reverse DNS results depend on external resolvers

▫️Performance depends on system limits and network conditions

---
## 🛡 Disclaimer
This tool is developed strictly for:

▫️Educational purposes
▫️Network analysis research
▫️Authorized security testing

The author is not responsible for any misuse of this software.
---
## ⭐ Credits
Built with ❤️ by BugCod3
T.me/BugCod3
