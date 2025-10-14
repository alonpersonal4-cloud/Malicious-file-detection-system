from pathlib import Path
import functions

def size_score(file_path):
    score = 0
    explanation=[]
    size = functions.check_file_size(file_path)
    if size <10:
        score += 0
        explanation.append("Small file (<10MB)")
    elif  size<50:
        score+=0.5
        explanation.append("Medium Size (10-50MB)")
    elif size<100:
        score+=1
        explanation.append("Large File (50-100MB)")
    else:
        score+=1.5
        explanation.append("Very Large File (100MB+)")
    return score , explanation
def type_score(file_path):
    score =0
    file_type = ""
    explanation=[]
    file_type = functions.identify_file_type(file_path)
    if "dosexec" in file_type  or "dll" in file_type :
        score += 2
        explanation.append("Executable File (DANGER)")
    elif  "script" in file_type :
        score+=0.5
        explanation.append("Medium Risk (Can contain scripts)")
    elif "archive" in file_type  or 'compress' in file_type :
        score+=1
        explanation.append("Potential Risk (Archive file)")
    else:
        score+=0
        explanation.append("Unknown file_type (proceed carefully)")
    return score , explanation        
    
    