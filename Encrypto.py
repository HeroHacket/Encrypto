import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def encrypt(password, file_in, file_out):
    # Leggere il contenuto del file da criptare
    with open(file_in, 'rb') as f:
        data = f.read()

    # Generare una chiave a partire dalla password
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    fernet = Fernet(key)

    # Criptare il contenuto del file
    encrypted_data = fernet.encrypt(data)

    # Scrivere il contenuto criptato nel file di output
    with open(file_out, 'wb') as f:
        f.write(salt)
        f.write(encrypted_data)

def decrypt(password, file_in, file_out):
    # Leggere il contenuto del file criptato
    with open(file_in, 'rb') as f:
        salt = f.read(16)
        data = f.read()

    # Generare la chiave utilizzando la password e il sale
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    fernet = Fernet(key)

    # Decriptare il contenuto del file
    decrypted_data = fernet.decrypt(data)

    # Scrivere il contenuto decriptato nel file di output
    with open(file_out, 'wb') as f:
        f.write(decrypted_data)

# Richiedere all'utente se vuole criptare o decriptare
while True:
    action = input('Vuoi criptare o decriptare un file? (C/D)')
    if action.upper() == 'C':
        password = input('Inserisci la password: ')
        file_in = input('Inserisci il percorso del file da criptare [Lasciare vuoto per la directory attuale] [Il nome del file si deve chiamare "file_decriptato.keys"]: ')
        file_in = 'file_decriptato.keys'
        encrypt(password, 'file_decriptato.keys', 'file_criptato.bin')
    if action.upper() == 'D':
        file_out = input('Inserisci il percorso del file criptato [Lasciare vuoto per la directory attuale] [Il nome del file si deve chiamare "file_criptato.bin"]: ')
        file_out = 'file_criptato.bin'
        password = input('Inserisci la password: ')
        decrypt(password, 'file_criptato.bin', 'file_decriptato.keys')
