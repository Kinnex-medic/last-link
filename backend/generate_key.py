from cryptography.fernet import Fernet

# Vygeneruje náhodný bezpečný kľúč
key = Fernet.generate_key()

# Uloží ho do súboru secret.key v binárnom režime
with open("secret.key", "wb") as key_file:
    key_file.write(key)

print("HOTOVO: Súbor secret.key bol úspešne vytvorený!")
