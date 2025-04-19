Absolutely! Here’s a **detailed documentation** explaining each feature of your security scanner, including its **purpose, usage, and example code snippets**.

---

# **Advanced Network Security Scanner – Documentation**

### **Version 1.0 – Feature Breakdown & Usage Guide**

## **Introduction**

This tool is a **powerful CLI-based network scanner**, combining **port scanning, exploit detection, vulnerability assessments, tracerouting, SOCKS5 proxy support, and dynamic status updates** to provide a **full-fledged security analysis** of any target network.

---

## **Features & Usage Guide**

### **1. Attack Profiles (`-m recon`, `-m service`, `-m firewall-evasion`)**

#### **Purpose:**

Allows different scanning modes tailored for reconnaissance, service detection, or firewall evasion.

#### **Modes & Example Usage:**

```bash
# Recon Mode (Basic scanning)
python3 scanner.py -s 192.168.1.0/24 -p 22,80 -m recon

# Detailed Service Detection Mode
python3 scanner.py -s 192.168.1.0/24 -p 21,443 -m service

# Firewall Evasion Mode (Stealth scanning with OS detection)
python3 scanner.py -s 192.168.1.0/24 -p 135,445,3389 -m firewall-evasion
```

---

### **2. Port Scanning (`-p 22,80,443` or `-p 20-100`)**

#### **Purpose:**

Scans specific ports or ranges for **open/closed** status.

#### **Example Usage:**

```bash
# Scan specific ports
python3 scanner.py -s 192.168.1.0/24 -p 22,80,443

# Scan a port range
python3 scanner.py -s 192.168.1.0/24 -p 20-100
```

---

### **3. UDP Scanning (`-sU`)**

#### **Purpose:**

Detects **open UDP ports**, commonly used for DNS, SNMP, and other services.

#### **Example Usage:**

```bash
# Enable UDP scanning alongside TCP
python3 scanner.py -s 192.168.1.0/24 -p 53,161,443 -sU
```

---

### **4. Traceroute Mapping (`--traceroute`)**

#### **Purpose:**

Maps network routes and identifies **network hops** to the destination.

#### **Example Usage:**

```bash
python3 scanner.py -s 192.168.1.0/24 -p 80 --traceroute
```

---

### **5. SOCKS5 Proxy Support (`--proxy ip:port`)**

#### **Purpose:**

Routes scans through **SOCKS5 proxy** to enhance anonymity.

#### **Example Usage:**

```bash
python3 scanner.py -s 192.168.1.0/24 -p 22,80 --proxy 127.0.0.1:9050
```

---

### **6. Exploit Detection & CVE Mapping (`--vuln-detect`)**

#### **Purpose:**

Detects **outdated and vulnerable** services based on an exploit database.

#### **Example Usage:**

```bash
python3 scanner.py -s 192.168.1.0/24 -p 22,443 --vuln-detect
```

---

### **7. Showing Closed Ports (`--show-closed`)**

#### **Purpose:**

Enables **closed port visibility** instead of only scanning open ports.

#### **Example Usage:**

```bash
python3 scanner.py -s 192.168.1.0/24 -p 20-100 --show-closed
```

---

### **8. Save Results to File (`--output results.json`)**

#### **Purpose:**

Stores scan results in **JSON or TXT** format for further analysis.

#### **Example Usage:**

```bash
python3 scanner.py -s 192.168.1.0/24 -p 22,80,443 --output scan_results.json
```

---

### **9. Rotating Activity Indicator (Live Progress Display)**

#### **Purpose:**

Displays **a rotating progress indicator** while scanning.

#### **Example Code Snippet (Included in Final Implementation)**

```python
import itertools, threading

def rotating_indicator():
    """ Rotating indicator for scan responsiveness """
    for frame in itertools.cycle(["|", "/", "-", "\\"]):
        print(f"\r[Scanning...] {frame}", end="", flush=True)
        time.sleep(0.3)

# Start spinner thread
spinner_thread = threading.Thread(target=rotating_indicator, daemon=True)
spinner_thread.start()
```

---

### **Example Full Scan Command**

This command enables **traceroute, proxy routing, closed port visibility, and CVE detection**:

```bash
python3 scanner.py -s 192.168.1.0/24 -p 20-100 -m service --traceroute --proxy 127.0.0.1:9050 --show-closed --vuln-detect --output scan_results.json
```

---

### **Final Notes**

-   This **fully optimized scanner** allows **deep security analysis**, making network monitoring **efficient and interactive**.
-   The **exploit detection** integration uses CVE mappings to flag vulnerable services.
-   The **progress indicator keeps users informed** while scans are running.
