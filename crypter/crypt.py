import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CHUNK_SIZE = 64 * 1024  # Размер блока данных для обработки (64 КБ)

def prepare_key(manual_key: str) -> bytes:
    if len(manual_key) != 16:
        raise ValueError("Ключ должен содержать ровно 16 символов (для 32 байт AES-256)!")
    return manual_key.encode()

def encrypt_file(file_path: str, key: bytes, output_dir: str):
    iv = os.urandom(12)  # IV длиной 12 байт для GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    encrypted_file_path = os.path.join(output_dir, os.path.basename(file_path) + '.enc')
    with open(file_path, 'rb') as f_in, open(encrypted_file_path, 'wb') as f_out:
        print(f"[INFO] Шифруется файл: {file_path}")
        f_out.write(iv)  # Сохраняем IV в начале файла
        while chunk := f_in.read(CHUNK_SIZE):
            encrypted_chunk = encryptor.update(chunk)
            f_out.write(encrypted_chunk)
        f_out.write(encryptor.finalize())  # Завершаем шифрование
        print(f"[DEBUG] Tag: {encryptor.tag.hex()}")
        f_out.write(encryptor.tag)  # Сохраняем Tag в конце файла
    print(f"Файл {file_path} зашифрован в {encrypted_file_path}")

def encrypt_folder():
    print("Введите путь к папке для шифрования: ", end="")
    folder_path = input().strip()
    print("Введите ключ (ровно 16 символов): ", end="")
    manual_key = input().strip()
    
    if not os.path.isdir(folder_path):
        print(f"Папка {folder_path} не существует!")
        return
    
    try:
        key = prepare_key(manual_key)
        encrypted_folder_path = folder_path + '_encrypted'
        os.makedirs(encrypted_folder_path, exist_ok=True)
        
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                encrypt_file(file_path, key, encrypted_folder_path)
        
        print("Шифрование завершено!")
    except ValueError as e:
        print(e)

if __name__ == '__main__':
    encrypt_folder()
