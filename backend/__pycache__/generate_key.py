from cryptography.fernet import Fernet

# Vygeneruje náhodný bezpečný kľúč
key = Fernet.generate_key()

# Uloží ho do súboru secret.key
with open("secret.key", "wb") as key_file:
    key_file.write(key)

print("Kľúč bol vygenerovaný a uložený do secret.key")