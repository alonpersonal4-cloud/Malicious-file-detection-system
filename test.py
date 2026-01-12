import functions
from scoring import calculate_malware_score
#testing the check_file_size function
test_file_size = functions.check_file_size("C:/Users/user/Downloads/GitHubDesktopSetup-x64.exe")
print(test_file_size)
#testing the identify_file_type function
test_file_type = functions.identify_file_type("C:/Users/user/Downloads/GitHubDesktopSetup-x64.exe")
print(test_file_type)
#testing the suspicious_strings function
test_suspicious_strings1 = functions.suspicious_strings("C:/Users/user/Downloads/test.txt")
test_suspicious_strings2 = functions.suspicious_strings("C:/Users/user/Downloads/emptytest.txt")
test_suspicious_strings3 = functions.suspicious_strings("C:/Users/user/Downloads/GitHubDesktopSetup-x64.exe")
print(test_suspicious_strings1 , test_suspicious_strings2 , test_suspicious_strings3)
#testing the calculate_hash function
test_calculate_hash= functions.calculate_hash("C:/Users/user/Downloads/test.txt")
print(test_calculate_hash)
#testing the calculate_entropy function
test_calculate_entropy1 = functions.calculate_entropy("C:/Users/user/Downloads/test.txt")
test_calculate_entropy2 = functions.calculate_entropy("C:/Users/user/Downloads/GitHubDesktopSetup-x64.exe")
print(test_calculate_entropy1 , test_calculate_entropy2)
#testing the scoring system
#score_one = calculate_malware_score("C:/Users/user/Downloads/test.txt")
score_two = calculate_malware_score("C:/Users/user/Downloads/GitHubDesktopSetup-x64.exe")
#print(score_one)
print(score_two)#