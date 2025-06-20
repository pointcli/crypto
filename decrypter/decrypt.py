import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CHUNK_SIZE = 64 * 1024  # Размер блока данных для обработки (64 КБ)

def prepare_key(manual_key: str) -> bytes:
    if len(manual_key) != 16:
        raise ValueError("Ключ должен содержать ровно 16 символов (для 32 байт AES-256)!")
    return manual_key.encode()

def decrypt_file(file_path: str, key: bytes, output_dir: str):
    file_size = os.path.getsize(file_path)
    if file_size <= 28:  # Минимальный размер: 12 байт (IV) + 16 байт (Tag)
        print(f"[ERROR] Файл {file_path} слишком мал для расшифровки.")
        return

    with open(file_path, 'rb') as f_in:
        iv = f_in.read(12)  # Читаем IV (12 байт)
        encrypted_data_size = file_size - 12 - 16  # Размер зашифрованных данных (без IV и Tag)
        f_in.seek(-16, os.SEEK_END)  # Переходим к началу Tag
        tag = f_in.read(16)  # Читаем Tag (16 байт)
        print(f"[DEBUG] IV: {iv.hex()}")
        print(f"[DEBUG] Tag: {tag.hex()}")
        f_in.seek(12)  # Возвращаемся к началу зашифрованных данных

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_file_path = os.path.join(output_dir, os.path.basename(file_path).replace('.enc', ''))
        with open(decrypted_file_path, 'wb') as f_out:
            while encrypted_data_size > 0:
                chunk_size = min(CHUNK_SIZE, encrypted_data_size)
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                decrypted_chunk = decryptor.update(chunk)
                f_out.write(decrypted_chunk)
                encrypted_data_size -= len(chunk)
            try:
                f_out.write(decryptor.finalize())  # Завершаем расшифровку
                print(f"Файл {file_path} расшифрован в {decrypted_file_path}")
            except Exception as e:
                print(f"[ERROR] Ошибка при расшифровке файла {file_path}: {str(e)}")
                os.remove(decrypted_file_path)  # Удаляем неполный файл
                return

def decrypt_folder():
    print("Введите путь к папке для расшифровки: ", end="")
    folder_path = input().strip()
    print("Введите ключ (ровно 16 символов): ", end="")
    manual_key = input().strip()
    
    if not os.path.isdir(folder_path):
        print(f"Папка {folder_path} не существует!")
        return
    
    try:
        key = prepare_key(manual_key)
        decrypted_folder_path = folder_path.replace("_encrypted", "_decrypted")
        os.makedirs(decrypted_folder_path, exist_ok=True)
        
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.enc'):
                    file_path = os.path.join(root, file)
                    decrypt_file(file_path, key, decrypted_folder_path)
        
        print("Расшифровка завершена!")
    except ValueError as e:
        print(e)

if __name__ == '__main__':
    decrypt_folder()
