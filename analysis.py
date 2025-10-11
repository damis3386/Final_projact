# analysis.py
# This module contains functions to analyze log files for suspicious entries.

import re

# Define keywords to search for (can be expanded later)
KEYWORDS = ["error", "failed", "unauthorized", "warning", "denied"]

def analyze_file(file_path):
    """
    Analyze a given file for suspicious entries.
    
    Args:
        file_path (str): The path to the log file.
        
    Returns:
        list: A list of lines containing suspicious keywords.
    """
    suspicious_entries = []
    
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            
        for line in lines:
            if any(keyword.lower() in line.lower() for keyword in KEYWORDS):
                suspicious_entries.append(line.strip())
                
    except FileNotFoundError:
        print(f"Error: File not found -> {file_path}")
    except Exception as e:
        print(f"Error reading file: {e}")
    
    return suspicious_entries


# ===== Example usage (for testing only) =====
# if __name__ == "__main__":
#     test_file = "sample_log.txt"
#     results = analyze_file(test_file)
#     if results:
#         print("Suspicious entries found:")
#         for r in results:
#             print(r)
#     else:
#         print("No suspicious entries found.")
