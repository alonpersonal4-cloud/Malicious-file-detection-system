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
    extension = magic.Magic(mime=True).from_file(file_path)  
    return extension
    