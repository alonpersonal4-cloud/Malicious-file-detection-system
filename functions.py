from pathlib import Path

def check_file_size(file_path):
    path = Path(file_path)
    if path.exists():
        stats = path.stat()
        size_mb = stats.st_size / 1048576
        rounded_size = round(size_mb,1)
        return rounded_size
    else:
        return None
    
    

