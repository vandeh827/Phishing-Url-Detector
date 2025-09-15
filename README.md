# Phishing URL Detector

This is a simple, graphical phishing URL detector built with Python, leveraging the **VirusTotal API** to scan URLs and provide a safety report. The application features a user-friendly interface powered by `tkinter` and includes functionalities like real-time clipboard monitoring, a scan history log, and the ability to save detailed reports.

-----

## ✨ Key Features

  * **Quick URL Scanning:** Instantly check any URL by pasting it into the app and clicking "Scan URL."
  * **VirusTotal Integration:** Get comprehensive threat analysis by tapping into VirusTotal's regularly updated database.
  * **Real-Time Clipboard Monitoring:** The app automatically detects when you copy a URL and offers to scan it for you, streamlining your workflow.
  * **Session History:** Keep track of all scanned URLs and their safety verdicts throughout your current session.
  * **Detailed Reports:** Save the full JSON report from the VirusTotal API to perform a deep dive into the scan results.
  * **Responsive Interface:** Multi-threading ensures the GUI remains responsive and doesn't freeze while API calls are being made.

-----

## 🛠️ Prerequisites

To run this application, you will need:

1.  **Python 3.x**
2.  **A VirusTotal API Key:** You can get a free public API key by signing up on the [VirusTotal website](https://www.virustotal.com/gui/my-apikey).

-----

## 🚀 Getting Started

### 1\. Installation

First, clone the repository and install the necessary Python libraries.

```bash
git clone https://github.com/vandeh827/Phishing-Url-Detector.git
cd Phishing-Url-Detector
pip install requests
```

### 2\. API Key Configuration

For security, the application reads your API key from your system's environment variables. Set a new environment variable named `VT_API_KEY` with your key as the value.

**On Windows:**

```bash
setx VT_API_KEY "YOUR_API_KEY_HERE"
```

**On macOS/Linux:**

```bash
export VT_API_KEY="YOUR_API_KEY_HERE"
```

> **Note:** For macOS/Linux, you can add this line to your `~/.bashrc` or `~/.zshrc` file to make the variable permanent across sessions.

### 3\. Running the Application

Once your API key is configured, you can run the main script from your terminal.

```bash
python main.py
```

-----

## 📂 Project Structure

```
├── main.py                   # The main application script
└── README.md                 # This file
```

The core logic, including the GUI setup, API communication, and multi-threading, is all contained within the `phishing_detector.py` file.

-----

## 🤝 Contributing

Contributions are what make the open-source community an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

-----

## 📄 License

This project is distributed under the MIT License. See `LICENSE` for more information.
