# core/file_handlers.py
# -*- coding: utf-8 -*-
"""
File handlers: read different file types and return unified text/content for analysis.
Supported: .txt, .log, .csv, .json, .zip
"""

import os
import io
import json
import zipfile
import csv
from typing import Tuple, List, Dict, Optional


class FileHandlers:
    SUPPORTED = {'.txt', '.log', '.csv', '.json', '.zip'}

    @staticmethod
    def _read_text_file(path: str, encoding: str = 'utf-8') -> str:
        with open(path, 'r', encoding=encoding, errors='replace') as f:
            return f.read()

    @staticmethod
    def _read_csv(path: str, encoding: str = 'utf-8') -> str:
        rows = []
        with open(path, 'r', encoding=encoding, errors='replace', newline='') as f:
            reader = csv.DictReader(f)
            for r in reader:
                rows.append(json.dumps(r, ensure_ascii=False))
        return "\n".join(rows)

    @staticmethod
    def _read_json(path: str, encoding: str = 'utf-8') -> str:
        with open(path, 'r', encoding=encoding, errors='replace') as f:
            data = json.load(f)
        if isinstance(data, list):
            return "\n".join(json.dumps(item, ensure_ascii=False) for item in data)
        else:
            return json.dumps(data, ensure_ascii=False)

    @staticmethod
    def _read_zip(path: str, encoding: str = 'utf-8') -> Tuple[str, List[str]]:
        contents = []
        names = []
        with zipfile.ZipFile(path, 'r') as z:
            for info in z.infolist():
                names.append(info.filename)
                _, ext = os.path.splitext(info.filename.lower())
                if ext in ('.txt', '.log'):
                    try:
                        with z.open(info) as f:
                            data = f.read().decode(encoding, errors='replace')
                        contents.append(f"--- FILE: {info.filename} ---\n{data}")
                    except Exception:
                        contents.append(f"--- FILE: {info.filename} (unreadable) ---")
                elif ext == '.csv':
                    try:
                        with z.open(info) as f:
                            text = f.read().decode(encoding, errors='replace')
                        reader = csv.DictReader(io.StringIO(text))
                        rows = [json.dumps(r, ensure_ascii=False) for r in reader]
                        contents.append("\n".join(rows))
                    except Exception:
                        contents.append(f"--- FILE: {info.filename} (csv parse error) ---")
                elif ext == '.json':
                    try:
                        with z.open(info) as f:
                            text = f.read().decode(encoding, errors='replace')
                            data = json.loads(text)
                        if isinstance(data, list):
                            contents.append("\n".join(json.dumps(it, ensure_ascii=False) for it in data))
                        else:
                            contents.append(json.dumps(data, ensure_ascii=False))
                    except Exception:
                        contents.append(f"--- FILE: {info.filename} (json parse error) ---")
                else:
                    contents.append(f"--- FILE: {info.filename} (skipped - unsupported) ---")
        return "\n\n".join(contents), names

    @classmethod
    def read(cls, file_path: str) -> Dict[str, Optional[object]]:
        try:
            if not os.path.exists(file_path):
                return {"text": None, "meta": None, "error": f"File not found: {file_path}"}

            size = os.path.getsize(file_path)
            name = os.path.basename(file_path)
            _, ext = os.path.splitext(name.lower())
            meta = {"path": file_path, "size": size, "ext": ext, "files_in_zip": None}

            if ext in ('.txt', '.log'):
                text = cls._read_text_file(file_path)
            elif ext == '.csv':
                text = cls._read_csv(file_path)
            elif ext == '.json':
                text = cls._read_json(file_path)
            elif ext == '.zip':
                text, names = cls._read_zip(file_path)
                meta["files_in_zip"] = names
            else:
                return {"text": None, "meta": meta, "error": f"Unsupported extension: {ext}"}

            return {"text": text, "meta": meta, "error": None}

        except Exception as e:
            return {"text": None, "meta": None, "error": str(e)}
