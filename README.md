# Phishing URL Detector

⚠️ **Disclaimer:** This tool is for educational purposes and personal use only. The accuracy of the results depends on the VirusTotal API, which may not be 100% accurate. Do not rely on this tool for critical security decisions.

This Python application is a simple, graphical phishing URL detector. It uses the **VirusTotal API** to scan URLs and provides a report on their safety. The application has a user-friendly GUI built with `tkinter`, and it includes features like real-time clipboard monitoring, scan history, and the ability to save full scan reports.

-----

## ✨ Features

  * **URL Scanning:** Scan any URL by entering it into the text box and clicking "Scan URL."
  * **VirusTotal Integration:** Utilizes the robust and regularly updated VirusTotal database for comprehensive threat analysis.
  * **Clipboard Monitoring:** Automatically detects when you copy a URL to your clipboard and asks if you'd like to scan it.
  * **Scan History:** Keeps a log of all scanned URLs and their verdicts (safe or malicious) during the current session.
  * **Full Report Generation:** Save the complete JSON report from the VirusTotal API for a deep dive into the scan results.
  * **Responsive GUI:** The application uses threading to perform API calls in the background, ensuring the user interface remains responsive and doesn't freeze.
  * **User-Friendly Interface:** A clean, intuitive design makes it easy for anyone to use.

-----

## 🛠️ Prerequisites

To run this application, you'll need:

1.  **Python 3.x**
2.  **A VirusTotal API Key:** You can get a free public API key by signing up on the [VirusTotal website](https://www.virustotal.com/gui/my-apikey).

-----

## 🚀 Getting Started

### 1\. Installation

Clone the repository and install the required Python libraries.

```bash
git clone https://github.com/your-username/Phishing-URL-Detector.git
cd Phishing-URL-Detector
pip install requests
```

### 2\. API Key Configuration

For security, the application reads the API key from your system's environment variables. Set a new environment variable named `VT_API_KEY` with your VirusTotal API key as the value.

**On Windows:**

```bash
setx VT_API_KEY "YOUR_API_KEY_HERE"
```

**On macOS/Linux:**

```bash
export VT_API_KEY="YOUR_API_KEY_HERE"
```

> **Note:** For macOS/Linux, you might need to add this line to your `~/.bashrc` or `~/.zshrc` file to make the variable persistent.

### 3\. Running the Application

Run the main script from your terminal.

```bash
python phishing_detector.py
```

-----

## 🖼️ Screenshots

-----

## 📂 Project Structure

```
├── phishing_detector.py      # The main application script
├── README.md                # This file
└── ...                      # Other potential files
```

The core logic, including the GUI setup, API communication, and multi-threading, is contained within the `phishing_detector.py` file.

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

Distributed under the MIT License. See `LICENSE` for more information.
