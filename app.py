import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
import tkinter as tk
from analysis import analyze_file  # import analysis function from analysis.py


class ForensicsToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Forensics Tool")
        self.root.geometry("900x600")
        self.root.resizable(False, False)

        # ===== App Theme =====
        style = ttk.Style("cyborg")  # Dark modern theme

        # ===== Title =====
        title = ttk.Label(
            root,
            text="🔍 Integrated Digital Forensics Tool",
            font=("Segoe UI", 20, "bold"),
            bootstyle="info"
        )
        title.pack(pady=20)

        # ===== File Selection Section =====
        file_frame = ttk.Frame(root, padding=10)
        file_frame.pack(pady=10)

        ttk.Label(
            file_frame, text="Select a file to analyze:", font=("Segoe UI", 12)
        ).grid(row=0, column=0, padx=10)

        ttk.Button(
            file_frame,
            text="Browse",
            bootstyle="info-outline",
            command=self.browse_file
        ).grid(row=0, column=1, padx=10)

        self.selected_file_label = ttk.Label(
            file_frame,
            text="No file selected",
            bootstyle="inverse-secondary",
            width=60,
            anchor="w"
        )
        self.selected_file_label.grid(row=1, column=0, columnspan=2, pady=5)

        # ===== Buttons Section =====
        button_frame = ttk.Frame(root, padding=10)
        button_frame.pack(pady=10)

        ttk.Button(
            button_frame,
            text="Analyze File",
            bootstyle="success-outline",
            command=self.run_analysis,
            width=20
        ).grid(row=0, column=0, padx=15)

        ttk.Button(
            button_frame,
            text="Generate Report (PDF)",
            bootstyle="warning-outline",
            command=self.generate_report,
            width=20
        ).grid(row=0, column=1, padx=15)

        ttk.Button(
            button_frame,
            text="Clear Output",
            bootstyle="danger-outline",
            command=self.clear_output,
            width=20
        ).grid(row=0, column=2, padx=15)

        # ===== Output Section =====
        ttk.Label(
            root, text="Analysis Results:", font=("Segoe UI", 12, "bold")
        ).pack(pady=5)

        self.text_output = tk.Text(
            root,
            height=20,
            width=100,
            bg="#1E1E1E",
            fg="white",
            insertbackground="white",
            wrap="word"
        )
        self.text_output.pack(padx=10, pady=5)

        # ===== Status Bar =====
        self.status = tk.StringVar(value="Ready")
        status_bar = ttk.Label(
            root,
            textvariable=self.status,
            bootstyle="secondary",
            anchor="w"
        )
        status_bar.pack(side="bottom", fill="x")

    # ===== File Browsing Function =====
    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file_label.config(text=file_path)
            self.status.set(f"Selected file: {file_path}")

    # ===== Run Analysis Function =====
    def run_analysis(self):
        file_path = self.selected_file_label.cget("text")
        if file_path == "No file selected":
            messagebox.showwarning("Warning", "Please select a file first!")
            self.status.set("Please select a file first!")
            return

        self.status.set("Analyzing file...")
        self.text_output.delete(1.0, tk.END)  # Clear previous output

        # Call the actual analysis function
        results = analyze_file(file_path)

        # Display results
        if results:
            self.text_output.insert(tk.END, "\n".join(results))
        else:
            self.text_output.insert(tk.END, "No suspicious entries found.")

        self.status.set("Analysis completed!")

    # ===== Generate Report Function (Placeholder) =====
    def generate_report(self):
        messagebox.showinfo("Report", "Report generated successfully!")
        self.status.set("Report generated successfully!")

    # ===== Clear Output Function =====
    def clear_output(self):
        self.text_output.delete(1.0, tk.END)
        self.status.set("Output cleared.")


# ===== Run the App =====
if __name__ == "__main__":
    root = ttk.Window(themename="cyborg")
    app = ForensicsToolApp(root)
    root.mainloop()
