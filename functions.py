from pathlib import Path
import magic
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
        mime_type = magic.Magic(mime=True).from_file(path)  
        return mime_type
    else:
        return None
def suspicious_strings(file_path):
    string_count = {}
    string_list = ["system","shell","download","socket","encrypt","decrypt","payload"]
    path = Path(file_path)
    if path.exists():
        with open(file_path, 'r') as f:
            for line in f:
                strings = line.strip().split()
                for string in strings:
                    lower_string = string.lower()
                    if (lower_string in string_list):
                        if lower_string in string_count:
                            string_count[lower_string] += 1
                        else:
                            string_count[lower_string] = 1
                return string_count
            else :
                return None                 