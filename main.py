import requests
import json
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from threading import Thread
import os


API_KEY = os.getenv("VT_API_KEY", "20aa6165ea461bedf59546fb3ebcc06e8aca1113ad02172ec33795a39f7a537a")


class PhishingDetectorApp:
    def __init__(self, master):
        self.master = master
        master.title("VirusTotal Phishing Detector")
        master.geometry("800x600")
        master.resizable(True, True)
        master.configure(bg="#2c3e50")

        # A list to store the scan history
        self.scan_history = []
        self.report_data = None

        self.main_frame = tk.Frame(master, padx=20, pady=20, bg="#2c3e50")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # URL Input Label and Entry
        self.url_label = tk.Label(self.main_frame, text="Enter URL to Check:", bg="#2c3e50", fg="#ecf0f1",
                                  font=("Helvetica", 12, "bold"))
        self.url_label.pack(pady=(0, 5))

        self.url_entry = tk.Entry(self.main_frame, width=80, relief=tk.FLAT, bg="#34495e", fg="#ecf0f1",
                                  insertbackground="#ecf0f1", font=("Helvetica", 11))
        self.url_entry.pack(pady=(0, 10))

        # Buttons Frame
        self.buttons_frame = tk.Frame(self.main_frame, bg="#2c3e50")
        self.buttons_frame.pack(pady=(0, 10))

        self.scan_button = tk.Button(self.buttons_frame, text="Scan URL", command=self.start_scan, bg="#27ae60",
                                     fg="white", relief=tk.FLAT, font=("Helvetica", 10, "bold"))
        self.scan_button.pack(side=tk.LEFT, padx=5, ipadx=10, ipady=5)

        self.clear_button = tk.Button(self.buttons_frame, text="Clear", command=self.clear_fields, bg="#e74c3c",
                                      fg="white", relief=tk.FLAT, font=("Helvetica", 10, "bold"))
        self.clear_button.pack(side=tk.LEFT, padx=5, ipadx=10, ipady=5)

        self.generate_report_button = tk.Button(self.buttons_frame, text="Generate Report",
                                                command=self.generate_report, state=tk.DISABLED, bg="#3498db",
                                                fg="white", relief=tk.FLAT, font=("Helvetica", 10, "bold"))
        self.generate_report_button.pack(side=tk.LEFT, padx=5, ipadx=10, ipady=5)

        # Status Label and Loading Indicator
        self.status_label = tk.Label(self.main_frame, text="Ready", fg="#bdc3c7", bg="#2c3e50",
                                     font=("Helvetica", 10, "italic"))
        self.status_label.pack(pady=(0, 10))
        self.loading_animation_id = None
        self.loading_frame_count = 0

        # Results Text Area
        self.results_text = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, width=90, height=20,
                                                      state=tk.DISABLED, bg="#34495e", fg="#ecf0f1", relief=tk.FLAT,
                                                      font=("Courier New", 10))
        self.results_text.pack(fill=tk.BOTH, expand=True)

        # Scan History Area
        self.history_frame = tk.LabelFrame(self.main_frame, text="Scan History", padx=10, pady=10, bg="#2c3e50",
                                           fg="#ecf0f1", font=("Helvetica", 10, "bold"))
        self.history_frame.pack(fill=tk.BOTH, expand=True, pady=(20, 0))
        self.history_listbox = tk.Listbox(self.history_frame, height=5, bg="#34495e", fg="#ecf0f1",
                                          selectbackground="#1abc9c", relief=tk.FLAT, font=("Courier New", 9))
        self.history_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.history_scrollbar = tk.Scrollbar(self.history_frame, orient=tk.VERTICAL)
        self.history_scrollbar.config(command=self.history_listbox.yview)
        self.history_listbox.config(yscrollcommand=self.history_scrollbar.set)
        self.history_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Start clipboard monitoring
        self.clipboard_monitor_thread = Thread(target=self.monitor_clipboard, daemon=True)
        self.clipboard_monitor_thread.start()
        self.last_clipboard_content = ""

    def start_loading_animation(self):
        self.stop_loading_animation()
        self.loading_frame_count = 0
        self.update_loading_animation()

    def update_loading_animation(self):
        frames = ["Scanning.  ", "Scanning.. ", "Scanning..."]
        self.status_label.config(text=frames[self.loading_frame_count % len(frames)], fg="#f39c12")
        self.loading_frame_count += 1
        self.loading_animation_id = self.master.after(500, self.update_loading_animation)

    def stop_loading_animation(self):
        if self.loading_animation_id:
            self.master.after_cancel(self.loading_animation_id)
            self.loading_animation_id = None

    def clear_fields(self):
        self.url_entry.delete(0, tk.END)
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.status_label.config(text="Ready", fg="#bdc3c7")
        self.generate_report_button.config(state=tk.DISABLED)
        self.report_data = None

    def update_results(self, text, color="black"):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, text + "\n")

        # Color the specific lines
        if color == "red":
            self.results_text.tag_add("verdict_red", tk.END + "-2l linestart", tk.END + "-1c")
            self.results_text.tag_config("verdict_red", foreground="#e74c3c", font=("Helvetica", 11, "bold"))
        elif color == "green":
            self.results_text.tag_add("verdict_green", tk.END + "-2l linestart", tk.END + "-1c")
            self.results_text.tag_config("verdict_green", foreground="#2ecc71", font=("Helvetica", 11, "bold"))
        else:
            self.results_text.insert(tk.END, text + "\n")
            self.results_text.tag_add(color, tk.END + "-2l linestart", tk.END + "-1c")
            self.results_text.tag_config(color, foreground="#ecf0f1")

        self.results_text.config(state=tk.DISABLED)
        self.results_text.see(tk.END)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL to scan.")
            return

        self.clear_fields()
        self.status_label.config(text="Scanning...", fg="#f39c12")
        self.start_loading_animation()

        # Start the API call in a new thread
        scan_thread = Thread(target=self.perform_scan, args=(url,))
        scan_thread.start()

    def perform_scan(self, url):
        try:
            # Step 1: Submit the URL for analysis
            self.master.after(0, lambda: self.update_status("Submitting URL for analysis...", "#bdc3c7"))
            url_endpoint = "https://www.virustotal.com/api/v3/urls"
            headers = {"x-apikey": API_KEY, "Content-Type": "application/x-www-form-urlencoded"}
            data = {"url": url}

            response = requests.post(url_endpoint, headers=headers, data=data)
            response.raise_for_status()
            result = response.json()
            analysis_id = result["data"]["id"]

            # Step 2: Poll for the analysis report
            report_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            report_response = None
            for _ in range(20):  # Poll up to 20 times (100 seconds)
                self.master.after(0, lambda: self.update_status("Polling for report...", "#bdc3c7"))
                report_response = requests.get(report_endpoint, headers=headers)
                report_response.raise_for_status()
                analysis_report = report_response.json()
                if analysis_report["data"]["attributes"]["status"] == "completed":
                    break
                time.sleep(5)
            else:
                self.master.after(0, lambda: self.update_status("Scan timed out.", "#e74c3c"))
                return

            self.report_data = analysis_report  # Store the full report for generation

            # Step 3: Display the results
            self.master.after(0, lambda: self._display_results(analysis_report))

        except requests.exceptions.RequestException as e:
            self.master.after(0, lambda: self.update_status(f"Network error: {e}", "#e74c3c"))
            messagebox.showerror("Network Error", f"A network error occurred: {e}")
        except json.JSONDecodeError:
            self.master.after(0, lambda: self.update_status("Error decoding API response.", "#e74c3c"))
            messagebox.showerror("API Error", "Invalid response from VirusTotal API.")
        except Exception as e:
            self.master.after(0, lambda: self.update_status(f"An unexpected error occurred: {e}", "#e74c3c"))
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
        finally:
            self.master.after(0, self.stop_loading_animation)
            self.master.after(0, lambda: self.status_label.config(fg="#bdc3c7"))

    def _display_results(self, report):
        self.status_label.config(text="Scan Complete", fg="#2ecc71")

        url = self.url_entry.get().strip()
        stats = report["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)

        self.update_results(f"URL Scanned: {url}")
        self.update_results("-" * 40)

        self.update_results(f"Malicious Detections: {malicious}")
        self.update_results(f"Harmless Detections: {stats.get('harmless', 0)}")
        self.update_results(f"Suspicious Detections: {stats.get('suspicious', 0)}")
        self.update_results(f"Undetected: {stats.get('undetected', 0)}")

        if malicious > 0:
            self.update_results("\n[VERDICT]: This URL is HIGHLY LIKELY to be malicious!", "red")
        else:
            self.update_results("\n[VERDICT]: This URL appears to be safe.", "green")

        self.generate_report_button.config(state=tk.NORMAL)
        self.add_to_history(url, "Malicious" if malicious > 0 else "Clean")

    def update_status(self, text, color):
        self.status_label.config(text=text, fg=color)

    def generate_report(self):
        if not self.report_data:
            messagebox.showwarning("No Report", "Please scan a URL first before generating a report.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as f:
                f.write(json.dumps(self.report_data, indent=4))
            messagebox.showinfo("Report Saved", f"Report successfully saved to:\n{file_path}")

    def add_to_history(self, url, status):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        history_entry = f"[{timestamp}] - {url} ({status})"
        self.scan_history.insert(0, history_entry)
        self.history_listbox.insert(0, history_entry)

    def monitor_clipboard(self):
        while True:
            try:
                current_clipboard = self.master.clipboard_get()
                if current_clipboard != self.last_clipboard_content and self._is_url(current_clipboard):
                    self.last_clipboard_content = current_clipboard
                    self.master.after(0, lambda: self._prompt_scan_from_clipboard(current_clipboard))
                time.sleep(2)
            except tk.TclError:
                # Handle cases where clipboard is empty or inaccessible
                time.sleep(2)
            except Exception as e:
                print(f"Clipboard monitoring error: {e}")
                time.sleep(5)

    def _is_url(self, text):
        return text.startswith("http://") or text.startswith("https://")

    def _prompt_scan_from_clipboard(self, url):
        if messagebox.askyesno("Scan from Clipboard",
                               f"A URL was detected in your clipboard:\n\n{url}\n\nWould you like to scan it now?"):
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, url)
            self.start_scan()


if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingDetectorApp(root)
    root.mainloop()
