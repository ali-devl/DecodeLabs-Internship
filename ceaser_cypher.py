mode = input("Type 'e' to encrypt or 'd' to decrypt: ").lower()
text = input("Enter your message: ")
key = int(input("Enter shift key (1-25): "))

if mode == 'd':
    key = -key

result = ""
for char in text:
    if char.isupper():
        result += chr((ord(char) - 65 + key) % 26 + 65)
    elif char.islower():
        result += chr((ord(char) - 97 + key) % 26 + 97)
    else:
        result += char

print("Result:", result)