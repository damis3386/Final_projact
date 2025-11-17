# app.py
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

from analysis import analyze_file
from reportgen import PDFReportGenerator


class ForensicsToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Forensics Tool")
        self.root.geometry("900x700")
        self.root.resizable(False, False)

        self.last_results = None
        self.last_file_path = None

        ttk.Style("cyborg")

        # ===== Title =====
        title = ttk.Label(
            root,
            text="🔍 Integrated Digital Forensics Tool",
            font=("Segoe UI", 20, "bold"),
            bootstyle="info"
        )
        title.pack(pady=15)

        # =====================================================
        #  FILE SELECTION (CENTERED + SHORT FIELD)
        # =====================================================
        file_frame = ttk.Frame(root, padding=10)
        file_frame.pack(pady=10)

        ttk.Label(
            file_frame,
            text="Select a file to analyze:",
            font=("Segoe UI", 12),
            anchor="center"
        ).pack(pady=5)

        ttk.Button(
            file_frame,
            text="Browse",
            bootstyle="info-outline",
            command=self.browse_file,
            width=20
        ).pack(pady=5)

        # Shorter Path Field (width=45 instead of 60)
        self.selected_file_label = ttk.Label(
            file_frame,
            text="No file selected",
            bootstyle="inverse-secondary",
            width=45,
            anchor="center"
        )
        self.selected_file_label.pack(pady=5)

        # =====================================================
        # BUTTONS
        # =====================================================
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

        # =====================================================
        #  DASHBOARD SECTION (NOW SCROLLABLE)
        # =====================================================
        ttk.Label(
            root,
            text="Analysis Dashboard:",
            font=("Segoe UI", 12, "bold")
        ).pack(pady=5)

        dashboard_container = ttk.Frame(root)
        dashboard_container.pack(fill="both", expand=True, padx=10, pady=5)

        # Canvas for scrolling
        self.canvas = tk.Canvas(
            dashboard_container,
            bg="#1E1E1E",
            highlightthickness=0
        )
        self.canvas.pack(side="left", fill="both", expand=True)

        # Scrollbar
        self.dashboard_scrollbar = ttk.Scrollbar(
            dashboard_container,
            orient="vertical",
            command=self.canvas.yview
        )
        self.dashboard_scrollbar.pack(side="right", fill="y")

        self.canvas.configure(yscrollcommand=self.dashboard_scrollbar.set)

        # Scroll with mouse wheel
        def _on_mousewheel(event):
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        self.canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Frame inside canvas
        self.result_frame = ttk.Frame(self.canvas, padding=15)
        self.canvas.create_window((0, 0), window=self.result_frame, anchor="nw")

        def _update_scroll(event):
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

        self.result_frame.bind("<Configure>", _update_scroll)

        # =====================================================
        # TEXT REPORT (with Scrollbar)
        # =====================================================
        ttk.Label(
            root,
            text="Detailed Text Report (Preview):",
            font=("Segoe UI", 12, "bold")
        ).pack(pady=5)

        text_frame = ttk.Frame(root)
        text_frame.pack(fill="both", expand=True, padx=10, pady=5)

        scrollbar = ttk.Scrollbar(text_frame, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        self.text_output = tk.Text(
            text_frame,
            height=12,
            width=100,
            bg="#1E1E1E",
            fg="white",
            insertbackground="white",
            wrap="word",
            yscrollcommand=scrollbar.set
        )
        self.text_output.pack(side="left", fill="both", expand=True)

        scrollbar.config(command=self.text_output.yview)

        # =====================================================
        # STATUS BAR
        # =====================================================
        self.status = tk.StringVar(value="Ready")
        status_bar = ttk.Label(
            root,
            textvariable=self.status,
            bootstyle="secondary",
            anchor="w"
        )
        status_bar.pack(side="bottom", fill="x")

    # =====================================================
    # FILE BROWSER
    # =====================================================
    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file_label.config(text=file_path)
            self.status.set(f"Selected file: {file_path}")
            self.last_file_path = file_path
            self.last_results = None

    # =====================================================
    # RUN ANALYSIS
    # =====================================================
    def run_analysis(self):
        file_path = self.selected_file_label.cget("text")
        if file_path == "No file selected":
            messagebox.showwarning("Warning", "Please select a file first!")
            return

        self.status.set("Analyzing file...")
        self.text_output.delete(1.0, tk.END)

        try:
            results = analyze_file(file_path)
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error:\n{e}")
            self.status.set("Analysis failed.")
            return

        if results.get("error"):
            self.text_output.insert(tk.END, f"[ERROR] {results['error']}\n")
            self.status.set("Analysis failed.")
            return

        self.last_results = results
        self._update_dashboard(results)
        self.text_output.insert(tk.END, "Analysis completed.\nSee PDF for full details.")
        self.status.set("Analysis completed!")

    # =====================================================
    # RENDER DASHBOARD CONTENT
    # =====================================================
    def _update_dashboard(self, results):
        for widget in self.result_frame.winfo_children():
            widget.destroy()

        basic = results.get("basic_analysis", {})
        suspicious = results.get("suspicious_items", [])
        risk_level = results.get("risk_level")
        risk_bar = results.get("risk_bar")

        ttk.Label(
            self.result_frame,
            text="📊 Analysis Dashboard",
            font=("Segoe UI", 14, "bold"),
            bootstyle="info"
        ).pack(anchor="w", pady=5)

        ttk.Label(
            self.result_frame,
            text=f"Risk Level: {risk_level}",
            font=("Segoe UI", 12, "bold")
        ).pack(anchor="w")

        ttk.Label(
            self.result_frame,
            text=risk_bar,
            font=("Segoe UI", 22)
        ).pack(anchor="w", pady=5)

        ttk.Separator(self.result_frame).pack(fill="x", pady=10)

        ttk.Label(
            self.result_frame,
            text="Quick Summary:",
            font=("Segoe UI", 12, "bold")
        ).pack(anchor="w")

        ttk.Label(self.result_frame, text=f"- Total lines: {basic.get('total_lines', 0)}").pack(anchor="w")
        ttk.Label(self.result_frame, text=f"- Errors: {basic.get('errors', 0)}").pack(anchor="w")
        ttk.Label(self.result_frame, text=f"- Warnings: {basic.get('warnings', 0)}").pack(anchor="w")
        ttk.Label(self.result_frame, text=f"- Info events: {basic.get('info_events', 0)}").pack(anchor="w")

        ttk.Separator(self.result_frame).pack(fill="x", pady=10)

        ttk.Label(
            self.result_frame,
            text="Suspicious Patterns:",
            font=("Segoe UI", 12, "bold")
        ).pack(anchor="w")

        if suspicious:
            for item in suspicious:
                ttk.Label(
                    self.result_frame,
                    text=f"- {item.get('name')} ({item.get('count')})"
                ).pack(anchor="w")
        else:
            ttk.Label(
                self.result_frame,
                text="No suspicious patterns detected.",
                bootstyle="success"
            ).pack(anchor="w")

    # =====================================================
    # GENERATE PDF
    # =====================================================
    def generate_report(self):
        if self.last_results is None:
            messagebox.showwarning("Warning", "Analyze a file before generating a report.")
            return

        try:
            pdf = PDFReportGenerator()
            output = pdf.generate_pdf(self.last_results)
            if output:
                messagebox.showinfo("Success", f"PDF saved:\n{output}")
        except Exception as e:
            messagebox.showerror("Error", f"PDF Failed:\n{e}")

    # =====================================================
    # CLEAR OUTPUT
    # =====================================================
    def clear_output(self):
        self.text_output.delete(1.0, tk.END)
        for w in self.result_frame.winfo_children():
            w.destroy()
        self.status.set("Output cleared.")


if __name__ == "__main__":
    root = ttk.Window(themename="cyborg")
    app = ForensicsToolApp(root)
    root.mainloop()
