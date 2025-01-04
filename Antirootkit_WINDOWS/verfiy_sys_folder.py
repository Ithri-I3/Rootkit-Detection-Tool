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


# Fonction pour calculer le hash SHA-256 d'un fichier
def calculate_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except Exception as e:
        return f"Error: {e}"

# Fonction pour charger les hachages sauvegardés depuis un fichier CSV
def load_hashes_from_csv(csv_file):
    if not os.path.exists(csv_file):
        print(f"Warning: The file {csv_file} does not exist. Skipping this step.")
        return None
    hashes = {}
    try:
        with open(csv_file, mode="r") as file:
            reader = csv.reader(file)
            next(reader)  # Ignorer l'en-tête
            for row in reader:
                file_path, hash_value = row
                hashes[file_path] = hash_value
    except Exception as e:
        print(f"Error reading CSV file: {e}")
    return hashes

# Fonction pour scanner un répertoire et retourner les hachages actuels
def scan_directory(directory):
    current_hashes = {}
    for root, _, filenames in os.walk(directory):
        for name in filenames:
            file_path = os.path.join(root, name)
            current_hashes[file_path] = calculate_hash(file_path)
    return current_hashes

# Fonction pour comparer les hachages des fichiers et dossiers
def compare_hashes(saved_hashes, current_hashes):
    discrepancies = {
        "modified": [],
        "missing": [],
        "new": [],
    }
    
    # Vérifier les fichiers modifiés ou supprimés
    for file_path, saved_hash in (saved_hashes or {}).items():
        if file_path not in current_hashes:
            discrepancies["missing"].append(file_path)
        elif saved_hash != current_hashes[file_path]:
            discrepancies["modified"].append(file_path)
    
    # Vérifier les nouveaux fichiers
    for file_path in current_hashes.keys():
        if file_path not in (saved_hashes or {}):
            discrepancies["new"].append(file_path)
    
    return discrepancies

# Fonction pour lire et générer les hachages des clés de registre
def scan_registry_key(key):
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
            return hashlib.sha256(hash_data.encode()).hexdigest()
    except Exception as e:
        return f"Error: {e}"

def compare_registry_hashes(saved_hashes, current_hashes):
    discrepancies = {
        "modified": [],
        "missing": [],
        "new": [],
    }
    
    for key_path, saved_hash in (saved_hashes or {}).items():
        if key_path not in current_hashes:
            discrepancies["missing"].append(key_path)
        elif saved_hash != current_hashes[key_path]:
            discrepancies["modified"].append(key_path)
    
    for key_path in current_hashes.keys():
        if key_path not in (saved_hashes or {}):
            discrepancies["new"].append(key_path)
    
    return discrepancies

# Afficher les résultats
def display_discrepancies(discrepancies, label):
    print(f"\n{label} Discrepancies:")
    for key, items in discrepancies.items():
        if items:
            print(f"\n  {key.capitalize()} items:")
            for item in items:
                print(f"    {item}")
        else:
            print(f"  No {key} items found.")

# Exécution
if __name__ == "__main__":
    # Fichiers critiques
    print("Checking critical files...")
    saved_file_hashes = load_hashes_from_csv("critical_files_hashes.csv")
    if saved_file_hashes is not None:
        current_file_hashes = {file: calculate_hash(file) for file in critical_files}
        file_discrepancies = compare_hashes(saved_file_hashes, current_file_hashes)
        display_discrepancies(file_discrepancies, "Files")
    
    # Dossiers critiques
    print("\nChecking critical directories...")
    saved_directory_hashes = load_hashes_from_csv("critical_directories_hashes.csv")
    if saved_directory_hashes is not None:
        current_directory_hashes = {}
        for directory in critical_directories:
            current_directory_hashes.update(scan_directory(directory))
        directory_discrepancies = compare_hashes(saved_directory_hashes, current_directory_hashes)
        display_discrepancies(directory_discrepancies, "Directories")
    
    # Clés de registre critiques
    print("\nChecking critical registry keys...")
    saved_registry_hashes = load_hashes_from_csv("critical_registry_hashes.csv")
    if saved_registry_hashes is not None:
        current_registry_hashes = {key: scan_registry_key(key) for key in critical_registry_keys}
        registry_discrepancies = compare_registry_hashes(saved_registry_hashes, current_registry_hashes)
        display_discrepancies(registry_discrepancies, "Registry Keys")
    
    print("\nVerification completed.")
