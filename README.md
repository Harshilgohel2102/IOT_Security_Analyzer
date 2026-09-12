# IoT Security Analyzer for Threat Detection and Vulnerability Assessment

## Project Description

**IoT Security Analyzer for Threat Detection and Vulnerability Assessment** is a cybersecurity application designed to analyze devices connected to a network and identify potential security risks.

The system uses network scanning and security analysis techniques to discover devices, identify open ports and services, and assess possible security risks. It provides a centralized interface for viewing scan results and analyzing the security status of detected devices.

The project follows a **Web Application + Local Scanning Agent** architecture. The local agent performs network discovery and scanning using Nmap, while the web application receives, processes, and displays the collected security information.

The project is developed as an academic cybersecurity project with a focus on **IoT/network security, vulnerability assessment, threat detection, and security monitoring**.

---

## Technology Stack

### Backend

* Python
* FastAPI

### Network Security & Scanning

* Nmap
* Python-Nmap

### Frontend

* HTML5
* CSS3
* JavaScript
* Chart.js
* Vis-Network

### Other Technologies

* REST API
* JSON

---

# Installation Guide

## Prerequisites

Make sure the following software is installed on your system:

* Python 3.10 or later
* Nmap

### Verify Python

```bash
python --version
```

### Verify Nmap

```bash
nmap --version
```

---

## 1. Clone the Repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
```

Navigate to the project directory:

```bash
cd <PROJECT_FOLDER>
```

---

## 2. Create a Virtual Environment

### Windows

```bash
python -m venv venv
```

Activate the virtual environment:

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

---

## 3. Install Python Dependencies

Install the required packages:

```bash
pip install -r requirements.txt
```

If a `requirements.txt` file is not included, install the required dependencies manually:

```bash
pip install fastapi uvicorn python-nmap requests
```

---

## 4. Start the Server

From the project directory, run:

```bash
uvicorn main:app --reload
```

If your FastAPI application is located in another file, replace `main` with the appropriate Python filename.

For example:

```bash
uvicorn server:app --reload
```

The server will normally be available at:

```text
http://127.0.0.1:8000
```

---

## 5. Start the Local Scanning Agent

Open a new terminal and activate the virtual environment again.

### Windows

```bash
venv\Scripts\activate
```

Run the scanning agent:

```bash
python agent.py
```

The agent detects the local network and performs network scanning using Nmap. Scan information is then sent to the running server for analysis.

---

## 6. Open the Application

After starting the server and scanning agent, open the application in your browser:

```text
http://127.0.0.1:8000
```

The application can then be used to view detected devices and their security scan information.

---

## Configuration

Before running the scanning agent, verify the server address configured in the agent.

Example:

```python
SERVER_URL = "http://127.0.0.1:8000"
```

If the server is running on another computer, replace the address with the appropriate server IP address.

---

## Important

The scanning functionality should only be used on networks and devices that you own or have explicit permission to assess.
