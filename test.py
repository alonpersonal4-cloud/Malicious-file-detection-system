import functions
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
#print(test_suspicious_strings1 , test_suspicious_strings2 , test_suspicious_strings3)
print(test_suspicious_strings3)
        