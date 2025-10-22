# core/file_handlers.py
# -*- coding: utf-8 -*-
"""
File handlers: read different file types and return unified text/content for analysis.
Supported: .txt, .log, .csv, .json, .zip, .tar, .evt, .evtx, .pcap
"""

import os
import io
import json
import zipfile
import tarfile
import csv

try:
    import dpkt  # لتحليل ملفات pcap
except ImportError:
    dpkt = None

try:
    import Evtx.Evtx as evtx  # لتحليل ملفات evtx
except ImportError:
    evtx = None


class FileHandlers:
    def __init__(self):
        pass

    def read(self, file_path):
        """Reads the file and returns its text content with metadata"""
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}", "text": "", "meta": {}}

        ext = os.path.splitext(file_path)[1].lower()
        try:
            if ext in [".txt", ".log"]:
                text = self._read_text(file_path)
            elif ext == ".csv":
                text = self._read_csv(file_path)
            elif ext == ".json":
                text = self._read_json(file_path)
            elif ext == ".zip":
                text = self._read_zip(file_path)
            elif ext == ".tar":
                text = self._read_tar(file_path)
            elif ext in [".evt", ".evtx"]:
                text = self._read_evtx(file_path)
            elif ext == ".pcap":
                text = self._read_pcap(file_path)
            else:
                return {"error": f"Unsupported file type: {ext}", "text": "", "meta": {}}

            size = os.path.getsize(file_path)
            return {"error": None, "text": text, "meta": {"ext": ext, "size": size}}

        except Exception as e:
            return {"error": str(e), "text": "", "meta": {}}

    # --- نوع النصوص العادية ---
    def _read_text(self, path):
        with io.open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    # --- CSV ---
    def _read_csv(self, path):
        output = []
        with io.open(path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                output.append(", ".join(row))
        return "\n".join(output)

    # --- JSON ---
    def _read_json(self, path):
        with io.open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        return json.dumps(data, indent=2, ensure_ascii=False)

    # --- ZIP ---
    def _read_zip(self, path):
        text_data = []
        with zipfile.ZipFile(path, "r") as z:
            for name in z.namelist():
                if name.endswith((".txt", ".log", ".json", ".csv")):
                    with z.open(name) as f:
                        try:
                            text_data.append(f"--- {name} ---\n" + f.read().decode("utf-8", "ignore"))
                        except:
                            pass
        return "\n".join(text_data)

    # --- TAR ---
    def _read_tar(self, path):
        text_data = []
        with tarfile.open(path, "r") as t:
            for member in t.getmembers():
                if member.isfile() and member.name.endswith((".txt", ".log")):
                    f = t.extractfile(member)
                    if f:
                        text_data.append(f"--- {member.name} ---\n" + f.read().decode("utf-8", "ignore"))
        return "\n".join(text_data)

    # --- EVTX ---
    def _read_evtx(self, path):
        if not evtx:
            return "⚠️ Python-Evtx not installed. Run: pip install python-evtx"
        text_data = []
        with evtx.Evtx(path) as log:
            for record in log.records():
                text_data.append(record.xml())
        return "\n".join(text_data)

    # --- PCAP ---
    def _read_pcap(self, path):
        if not dpkt:
            return "⚠️ dpkt not installed. Run: pip install dpkt"
        text_data = []
        with open(path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for timestamp, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        src = f"{ip.src[0]}.{ip.src[1]}.{ip.src[2]}.{ip.src[3]}"
                        dst = f"{ip.dst[0]}.{ip.dst[1]}.{ip.dst[2]}.{ip.dst[3]}"
                        text_data.append(f"Packet: {src} -> {dst}, len={len(buf)}")
                except Exception:
                    continue
        return "\n".join(text_data)
