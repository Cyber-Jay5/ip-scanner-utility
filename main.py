import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import scanner
import threading
import queue

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("IP Scanner Utility - V5")
        self.geometry("900x750") 
        
        # Grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1) 

        self.scanner = scanner.NmapScanner()
        self.output_queue = queue.Queue()
        self.scan_in_progress = False
        self.last_report = ""
        self.current_scan_type = ""

        self.create_widgets()
        
        # Check nmap on startup
        if not self.scanner.is_nmap_installed():
            self.log_output("ERROR: Nmap is not installed or not in PATH.\nPlease install Nmap from https://nmap.org/download.html and restart this application.\n")
            self.scan_button.configure(state="disabled")
        else:
            self.log_output("Ready. Nmap found.\n")

        # Start periodic check for queue
        self.after(100, self.check_queue)

    def create_widgets(self):
        # --- Input Section ---
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        self.input_frame.grid_columnconfigure(1, weight=1)

        self.label_target = ctk.CTkLabel(self.input_frame, text="Targets:\n(One per line)")
        self.label_target.grid(row=0, column=0, padx=10, pady=10, sticky="n")
        
        self.entry_target = ctk.CTkTextbox(self.input_frame, height=80)
        self.entry_target.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.entry_target.insert("1.0", "google.com\n127.0.0.1") 

        # --- Options Section ---
        self.options_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.options_frame.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="ew")
        self.options_frame.grid_columnconfigure(5, weight=1) # Spacer before buttons if needed
        
        # Search Type
        self.scan_types = ["Quick Scan", "Intense Scan", "Vulnerability Scan", "Ping Scan"]
        self.option_scan_type = ctk.CTkOptionMenu(self.options_frame, values=self.scan_types)
        self.option_scan_type.grid(row=0, column=0, padx=5, pady=5)

        self.checkbox_geo = ctk.CTkCheckBox(self.options_frame, text="Geo/Whois/Curl/SSH")
        self.checkbox_geo.select() 
        self.checkbox_geo.grid(row=0, column=1, padx=5, pady=5)
        
        self.checkbox_trace = ctk.CTkCheckBox(self.options_frame, text="Traceroute")
        self.checkbox_trace.grid(row=0, column=2, padx=5, pady=5)

        # Netlas Key
        self.entry_netlas = ctk.CTkEntry(self.options_frame, placeholder_text="Netlas API Key (Optional)", width=200, show="*")
        self.entry_netlas.grid(row=0, column=3, padx=5, pady=5)

        # Action Buttons
        self.scan_button = ctk.CTkButton(self.options_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=4, padx=5, pady=5)

        # --- Button Row 2 (Stop/Save) ---
        self.buttons2_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.buttons2_frame.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")
        
        self.stop_button = ctk.CTkButton(self.buttons2_frame, text="Stop", command=self.stop_scan, fg_color="red", state="disabled")
        self.stop_button.pack(side="right", padx=5)
        
        self.report_button = ctk.CTkButton(self.buttons2_frame, text="Save Full Report", command=self.save_report, state="disabled")
        self.report_button.pack(side="right", padx=5)

        # --- Output Area ---
        self.label_output = ctk.CTkLabel(self, text="Scan Output & Summary:")
        self.label_output.grid(row=2, column=0, padx=20, pady=(10,0), sticky="w") # Overlapping grid? Wait.
        # Cleaned up layout:
        # Row 0: Input
        # Row 1: Options (Type, Checkboxes, Netlas, Start)
        # Row 2: Stop/Save buttons (Right aligned)
        # Row 3: Textbox
        
        # Let's fix the grid for Row 2/3
        self.buttons2_frame.grid(row=2, column=0, padx=20, pady=(0,5), sticky="e")
        
        self.textbox = ctk.CTkTextbox(self, width=860, height=400)
        self.textbox.grid(row=3, column=0, padx=20, pady=(5,20), sticky="nsew")
        self.textbox.configure(state="disabled") 

        # --- Status Bar ---
        self.status_label = ctk.CTkLabel(self, text="Idle", anchor="w")
        self.status_label.grid(row=4, column=0, padx=20, pady=(0, 10), sticky="ew")

    def log_output(self, text):
        self.textbox.configure(state="normal")
        self.textbox.insert("end", text)
        self.textbox.see("end")
        self.textbox.configure(state="disabled")

    def check_queue(self):
        try:
            while True:
                msg_type, content = self.output_queue.get_nowait()
                if msg_type == "output":
                    self.log_output(content)
                elif msg_type == "finished":
                    self.scan_finished(content)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.check_queue)

    def get_targets(self):
        raw = self.entry_target.get("1.0", "end").strip()
        if not raw:
            return []
        normalized = raw.replace(",", "\n")
        targets = [t.strip() for t in normalized.split("\n") if t.strip()]
        return targets

    def start_scan(self):
        targets = self.get_targets()
        if not targets:
            messagebox.showwarning("Input Error", "Please provide at least one IP address or URL.")
            return

        scan_type = self.option_scan_type.get()
        include_geo = self.checkbox_geo.get() == 1
        enable_trace = self.checkbox_trace.get() == 1
        netlas_key = self.entry_netlas.get().strip()
        
        self.textbox.configure(state="normal")
        self.textbox.delete("1.0", "end")
        self.textbox.configure(state="disabled")
        
        self.scan_in_progress = True
        self.update_ui_state(scanning=True)
        self.status_label.configure(text=f"Scanning {len(targets)} targets...")
        
        self.current_scan_type = scan_type

        # Call batch scanner
        self.scanner.run_batch_scan(
            targets, 
            scan_type,
            include_geo,
            netlas_key,
            enable_trace,
            output_callback=lambda text: self.output_queue.put(("output", text)),
            finished_callback=lambda report: self.output_queue.put(("finished", report))
        )

    def stop_scan(self):
        if self.scan_in_progress:
            self.scanner.stop_scan()
            self.log_output("\nStopping scan...\n")

    def scan_finished(self, full_report):
        self.scan_in_progress = False
        self.update_ui_state(scanning=False)
        self.status_label.configure(text="Batch Scan finished")
        
        self.last_report = full_report
        self.report_button.configure(state="normal")

    def save_report(self):
        if not self.last_report:
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save Full Report"
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.last_report)
            messagebox.showinfo("Saved", f"Report saved to {file_path}")

    def update_ui_state(self, scanning):
        if scanning:
            self.scan_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            self.report_button.configure(state="disabled")
            self.entry_target.configure(state="disabled")
            self.option_scan_type.configure(state="disabled")
            self.checkbox_geo.configure(state="disabled")
            self.checkbox_trace.configure(state="disabled")
            self.entry_netlas.configure(state="disabled")
        else:
            self.scan_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            self.entry_target.configure(state="normal")
            self.option_scan_type.configure(state="normal")
            self.checkbox_geo.configure(state="normal")
            self.checkbox_trace.configure(state="normal")
            self.entry_netlas.configure(state="normal")

if __name__ == "__main__":
    app = App()
    app.mainloop()
