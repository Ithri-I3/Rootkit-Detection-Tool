import csv
import os  # Pour vérifier si les fichiers existent
import hashlib  # Pour calculer le hash SHA256 du fichier

# Fichier CSV des rootkits
ROOTKIT_CSV = "rootkit_data.csv"

def load_rootkit_hashes(csv_file):
    """Charge les hash SHA256 des rootkits depuis le fichier CSV."""
    rootkit_hashes = set()  # Utilisation d'un set pour une recherche rapide
    
    # Vérifier si le fichier CSV existe
    if not os.path.exists(csv_file):
        print(f"Erreur : le fichier CSV {csv_file} n'existe pas.")
        return set()
    
    try:
        with open(csv_file, mode="r", newline="", encoding="utf-8") as file:
            reader = csv.reader(file)
            next(reader)  # Sauter l'en-tête
            for row in reader:
                if row:  # Vérifie que la ligne n'est pas vide
                    sha256_hash = row[0]
                    rootkit_hashes.add(sha256_hash)
        return rootkit_hashes
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier CSV : {str(e)}")
        return set()

def is_rootkit(file_hash, rootkit_hashes):
    """Vérifie si un fichier est un rootkit en comparant son hash avec la liste des rootkits."""
    if file_hash in rootkit_hashes:
        return True
    return False

def calculate_sha256(file_path):
    """Calcule le hash SHA256 d'un fichier donné."""
    if not os.path.exists(file_path):
        print(f"Erreur : le fichier {file_path} n'existe pas.")
        return None
    
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            # Lire le fichier par blocs de 4K pour éviter les gros fichiers
            for byte_block in iter(lambda: file.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Erreur lors du calcul du hash du fichier {file_path} : {str(e)}")
        return None

def main():
    # Charger les hash des rootkits depuis le fichier CSV
    rootkit_hashes = load_rootkit_hashes(ROOTKIT_CSV)
    
    if not rootkit_hashes:
        print("Aucun hash de rootkit n'a pu être chargé ou le fichier CSV est introuvable.")
        return
    
    # Demander à l'utilisateur d'entrer le chemin du fichier à tester
    file_path = input("Entrez le chemin du fichier à tester : ")
    
    # Vérification si le fichier à tester existe
    if not os.path.exists(file_path):
        print(f"Erreur : le fichier {file_path} n'existe pas.")
        return
    
    # Calculer le hash SHA256 du fichier
    file_hash = calculate_sha256(file_path)
    
    if file_hash is None:
        return
    
    # Vérifier si le fichier est un rootkit
    if is_rootkit(file_hash, rootkit_hashes):
        print(f"Le fichier avec le hash {file_hash} est un rootkit.")
    else:
        print(f"Le fichier avec le hash {file_hash} n'est pas un rootkit.")

if __name__ == "__main__":
    main()
