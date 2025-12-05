from pathlib import Path
import functions
import pickle
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
            if word in file_strings:
                dangerous_words+= file_strings[word]
        if dangerous_words > 0:
            explanation.append("Found the words '{}' in the file".format(dangerous_words_list))
        for word2 in threatening_words_list:
            if word2 in file_strings:
                threatening_words+= file_strings[word2]
        if threatening_words > 0:
            explanation.append("Found the words '{}' in the file".format(threatening_words_list))
    score = (dangerous_words * 0.5 ) + (threatening_words * 0.3)
    if score < 0.5:
        return 0, explanation
    elif score  < 1.5:
        return 1, explanation
    elif score  < 2.5:
        return 1.5, explanation
    else :
        return 2.5,explanation
def hash_score(file_path):
    score = 0
    explanation = ["The hash score function is under construction."]
    return score , explanation
model = pickle.load(open("malware_model.pkl", 'rb'))
def model_score(file_path):
    path = Path(file_path)
    # entropy , size , sus_words , packer , sizeofcode , sizeofimage , numofsections
    sum_sus_strings = sum(functions.suspicious_strings(path).values())
    X = [[functions.calculate_entropy(path),
          functions.check_file_size(path),
          sum_sus_strings,
          functions.check_packer(path),
          functions.get_size_of_code(path),
          functions.get_size_of_image(path),
          functions.get_number_of_sections(path)]]
    prediction = model.predict(X)
    if prediction[0] == 1:
        return 3 , ["The ML model predicts the file is a Malware !"]
    else :
        return 0 , ["The ML model predicts the file  is Safe !"]
def calculate_malware_score(file_path):
    path = Path(file_path)
    if not path.exists():
        return "Risk : None", ["file not found"], 0
    score = 0
    explanation = []
    size = size_score(file_path)#
    score = size[0] + score
    explanation.extend(size[1])
    file_type = type_score(file_path)#
    score = file_type[0] + score
    explanation.extend(file_type[1])
    entropy = entropy_score(file_path)#
    score = entropy[0] + score
    explanation.extend(entropy[1])
    sus_words = suspicious_strings_score(file_path)#
    score = sus_words[0] + score
    explanation.extend(sus_words[1])
    hash_file = hash_score(file_path)#
    score = hash_file[0] + score
    explanation.extend(hash_file[1])
    ML_prediction = model_score(file_path)#
    score = ML_prediction[0] + score
    explanation.extend(ML_prediction[1])
    if score >7:
        return "Risk : High", explanation ,score
    elif score > 4:
        return "Risk : Medium", explanation,score
    else:
        return "Risk : Low", explanation,score

        
    
    