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
    explanation=[]
    file_type = functions.identify_file_type(file_path)
    if file_type is None:  
        score = 0
        explanation.append("Could not identify file type")
        return score, explanation
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
def entropy_score(file_path):
    score = 0
    explanation = []
    file_entropy =functions.calculate_entropy(file_path)
    if file_entropy is None:  
        score =  0
        explanation.append("Could not calculate the file's entropy")
        return score, explanation
    if file_entropy < 5:
        score = 0
        explanation.append("Very low entropy level (text)")
    elif file_entropy < 6.5:
        score +=1
        explanation.append("Mid entropy level (high level language)")
    elif file_entropy <7.5:
        score+=2
        explanation.append("High entropy level (ASCII character)")
    else:
        score+=3
        explanation.append("Very high level of entropy (fully random)")
    return score , explanation
def suspicious_strings_score(file_path):
    #string_list = ["system","shell","download","socket","encrypt","decrypt","payload"]
    dangerous_words_list = ["system","shell","payload"]
    threatening_words_list =["download","socket","encrypt","decrypt"]
    dangerous_words= 0
    threatening_words =0
    score = 0
    explanation = []
    file_strings =functions.suspicious_strings(file_path)
    if file_strings is None:  
        score += 0
        explanation.append("Could not find sispicious words in the file")
    else:
        for word in dangerous_words_list:
            if dangerous_words_list[word] in file_strings:
                dangerous_words+= file_strings[word]
        if dangerous_words > 0:
            explanation.append("Found the words '{}' in the file".format(dangerous_words_list))
        for word2 in threatening_words_list:
            if threatening_words_list[word2] in file_strings:
                threatening_words+= file_strings[word2]
        if threatening_words > 0:
            explanation.append("Found a the words '{}' in the file".format(dangerous_words_list))
    score = (dangerous_words * 0.5 ) + (threatening_words * 0.3)
    if score < 0.5:
        return 0, explanation
    elif score  < 1.5:
        return 1, explanation
    elif score  < 2.5:
        return 1.5, explanation
    else :
        return 2.5,explanation
                
        
    
    