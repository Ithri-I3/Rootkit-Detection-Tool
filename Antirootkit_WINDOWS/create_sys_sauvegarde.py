import hashlib
import os
import csv
import winreg

# Liste des fichiers critiques
critical_files = [
    r"C:\Windows\System32\ntoskrnl.exe",       # Noyau du système Windows
    r"C:\Windows\System32\winlogon.exe",      # Processus de connexion utilisateur
    r"C:\Windows\System32\lsass.exe",         # Service d'authentification local
    r"C:\Windows\System32\drivers\pci.sys",   # Pilote PCI, souvent ciblé pour injecter des rootkits au niveau noyau
    r"C:\Windows\Boot\BCD",                   # Base de données de configuration de démarrage
]


# Liste des dossiers critiques
critical_directories = [
    r"C:\Windows\System32\drivers",           # Contient les pilotes système, cible des rootkits noyau
    r"C:\Windows\Boot",                       # Contient des fichiers critiques pour le démarrage
    r"C:\Windows\WinSxS",                     # Répertoire des versions système, cible de modifications furtives
]


# Liste des clés de registre critiques
critical_registry_keys = [
    r"SYSTEM\CurrentControlSet\Services",              # Liste des services système, cible pour les rootkits persistants
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",  # Contrôle les paramètres de connexion (userinit, shell)
    r"SYSTEM\CurrentControlSet\Control\Session Manager",       # Contient des points d'entrée pour des chargements malveillants
    r"SYSTEM\CurrentControlSet\Control\Lsa",                   # Contrôle l'authentification, souvent ciblé par des rootkits
]


# Fonction pour calculer le hash SHA-256
def calculate_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except Exception as e:
        return f"Error: {e}"

# Sauvegarder les hachages des fichiers individuels
def save_file_hashes_to_csv(files, output_csv):
    with open(output_csv, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["File Path", "SHA-256 Hash"])
        for file in files:
            hash_value = calculate_hash(file)
            writer.writerow([file, hash_value])
    print(f"File hashes saved to {output_csv}")

# Sauvegarder les hachages des dossiers et leurs contenus
def save_directory_hashes_to_csv(directories, output_csv):
    with open(output_csv, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["File Path", "SHA-256 Hash"])
        for directory in directories:
            for root, _, filenames in os.walk(directory):
                for name in filenames:
                    file_path = os.path.join(root, name)
                    hash_value = calculate_hash(file_path)
                    writer.writerow([file_path, hash_value])
    print(f"Directory hashes saved to {output_csv}")

# Lire les clés de registre et générer des hachages
def calculate_registry_hashes(keys, output_csv):
    with open(output_csv, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Registry Key", "SHA-256 Hash"])
        for key in keys:
            try:
                hive, subkey = (winreg.HKEY_LOCAL_MACHINE, key)
                with winreg.OpenKey(hive, subkey) as reg_key:
                    hash_data = ""
                    i = 0
                    while True:
                        try:
                            value_name, value_data, _ = winreg.EnumValue(reg_key, i)
                            hash_data += f"{value_name}={value_data};"
                            i += 1
                        except OSError:
                            break
                    key_hash = hashlib.sha256(hash_data.encode()).hexdigest()
                    writer.writerow([key, key_hash])
            except Exception as e:
                writer.writerow([key, f"Error: {e}"])
    print(f"Registry hashes saved to {output_csv}")

# Exécution
if __name__ == "__main__":
    # Fichiers critiques
    save_file_hashes_to_csv(critical_files, "critical_files_hashes.csv")

    # Dossiers critiques
    save_directory_hashes_to_csv(critical_directories, "critical_directories_hashes.csv")

    # Clés de registre critiques
    calculate_registry_hashes(critical_registry_keys, "critical_registry_hashes.csv")

    print("Hashing completed.")
