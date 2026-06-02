def check_password_strength(password):
    length = len(password)
    
    has_upper = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(not char.isalnum() for char in password)
    
    score = has_upper + has_digit + has_symbol
    
    if length < 8 or score < 1:
        strength = "Weak"
    elif length >= 12 and score == 3:
        strength = "Strong"
    else:
        strength = "Medium"
        
    print(f"Password: {password}")
    print(f"Strength: {strength}")
  

while True:
    user_password = input("Enter a password to check: ")
    
    if user_password.lower() == 'exit':
        break
        
    if not user_password:
        continue
        
    check_password_strength(user_password)