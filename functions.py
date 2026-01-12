from pathlib import Path
import magic
import hashlib
from collections import Counter
import math
import pefile
import requests
from dotenv import load_dotenv
import os
def check_file_size(file_path):
    path = Path(file_path)
    if path.exists():
        stats = path.stat()
        size_mb = stats.st_size / 1048576
        rounded_size = round(size_mb,1)
        return rounded_size
    else:
        return None
def identify_file_type(file_path):
    path = Path(file_path)
    if path.exists():
        mime_type = magic.from_file(str(path), mime=True)  
        return mime_type
    else:
        return None
def suspicious_strings(file_path):
    string_count = {}
    string_list = ["system","shell","download","socket","encrypt","decrypt","payload"]
    path = Path(file_path)
    if path.exists():
        try:
            with open(path, 'r') as f:
                for line in f:
                    strings = line.strip().split()
                    for string in strings:
                        lower_string = string.lower()
                        if (lower_string in string_list):
                            if lower_string in string_count:
                                string_count[lower_string] += 1
                            else:
                                string_count[lower_string] = 1
                    f.close
        except:
            with open(path, 'rb') as f:  
                    content = f.read()
                    text = content.decode('utf-8', errors='ignore')
                    strings = text.strip().split()
                    for suspicious_word in string_list:
                        count = text.lower().count(suspicious_word)
                        if count > 0:
                            string_count[suspicious_word] = count
                    f.close
        return string_count
    else:
        return None
def calculate_hash(file_path):
    path = Path(file_path)
    if path.exists():
        with open(file_path, 'rb') as f:  
            content = f.read()
        hasher = hashlib.sha256()
        hasher.update(content)
        hashed_content = hasher.hexdigest()
        f.close
        return hashed_content
    else:
        return None
def calculate_entropy(file_path):
    entropy = 0
    path =Path(file_path)
    if path.exists():
        with open(path , 'rb') as f:
            content = f.read()
            f.close
            if len(content) == 0:
                return None
            byte_counts = Counter(content)
            for i in range (256):
                count = byte_counts[i]
                probability = count / len(content)
                if probability > 0:
                  entropy -= (probability * math.log2(probability))  
    else:
        return None         
    return entropy
# function for the ML model
def get_size_of_code(file_path):
    path =Path(file_path)
    try:
        pe = pefile.PE(path)
        size_of_code = pe.OPTIONAL_HEADER.SizeOfCode
        return size_of_code
    except:
        return 0
    finally:
        if pe:
            pe.close()
def get_size_of_image(file_path):
    path =Path(file_path)
    try:
        pe = pefile.PE(path)
        size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
        return size_of_image
    except:
        return 0
    finally:
        if pe:
            pe.close()
def get_number_of_sections(file_path):
    path =Path(file_path)
    try:
        pe = pefile.PE(path)
        sections = pe.FILE_HEADER.NumberOfSections
        return sections
    except:
        return 0
    finally:
        if pe:
            pe.close()
def check_packer(file_path):
    try:
        path =Path(file_path)
        string_list = ["upx", "aspack", "pecompact", "packed"]
        pe = pefile.PE(path)
        sections = pe.sections
        for section in sections:
            section_name = section.Name.decode('utf-8', errors='ignore').lower().strip()
            if (section_name in string_list):
                return 1
        return 0
    except:
        return 0
    finally:
        if pe:
            pe.close()

    