import os
import subprocess
import psutil
import threading
from tkinter import Tk, Button, messagebox


def analyze_file(file_path):
    """
    Fonction principale qui analyse le fichier sélectionné
    et recherche des comportements suspects dans son code.
    """
    if not os.path.exists(file_path):
        messagebox.showerror("Erreur", f"Le fichier {file_path} n'existe pas.")
        return
    
    # Analyser le contenu du fichier
    analyze_file_code(file_path)
    
    # Lancer l'analyse des processus, fichiers cachés, etc. (sur le système)
    check_suspicious_processes()  # Vérifie les processus
    check_for_injected_code()     # Vérifie l'injection de code


def analyze_file_code(file_path):
    """
    Analyse statique du code du fichier pour rechercher des signes typiques de rootkit.
    """
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de lire le fichier: {str(e)}")
        return
    
    # Liste élargie de motifs suspects
    suspicious_patterns = [
        # Injection de code
        b"NtCreateThread", b"CreateRemoteThread", b"WriteProcessMemory", b"LoadLibrary",
        b"SetWindowsHookEx", b"SetThreadContext", b"ZwQuerySystemInformation",
        
        # DLLs système souvent manipulées
        b"kernel32.dll", b"user32.dll", b"advapi32.dll", b"ntdll.dll", b"gdi32.dll", b"wininet.dll",
        b"ws2_32.dll", b"shell32.dll", b"shlwapi.dll", b"comctl32.dll", b"ole32.dll", b"crypt32.dll",
        
        # Fonctions API système associées à des comportements suspects
        b"OpenProcess", b"VirtualAllocEx", b"ReadProcessMemory", b"WriteProcessMemory",
        b"TerminateProcess", b"EnumProcesses", b"GetModuleHandle", b"GetProcAddress",
        
        # Commandes système suspectes
        b"regedit", b"cmd.exe", b"powershell.exe", b"net.exe", b"schtasks.exe", b"taskkill.exe",
        
        # Termes typiques liés à des malwares ou rootkits
        b"rootkit", b"backdoor", b"spy", b"hacker", b"keylogger", b"trojan", b"virus"
    ]

    detected_patterns = []  # Liste pour collecter tous les mots-clés détectés

    for pattern in suspicious_patterns:
        if pattern in file_content:
            detected_patterns.append(pattern.decode('utf-8', 'ignore'))

    if detected_patterns:
        # Afficher tous les mots-clés détectés
        detected_list = "\n".join(detected_patterns)
        print(f"Signes de rootkit ou comportement suspect détectés :\n{detected_list}")
        messagebox.showwarning("Alerte", f"Signes détectés dans le fichier :\n{detected_list}")
    else:
        print(f"Aucun signe de rootkit détecté dans le fichier {file_path}.")
        messagebox.showinfo("Analyse terminée", f"Aucun signe de rootkit détecté dans le fichier : {file_path}")


def check_suspicious_processes():
    """
    Rechercher des processus suspects en fonction de mots-clés dans leurs commandes ou noms.
    """
    suspicious_keywords = ['rootkit', 'backdoor', 'spy', 'hacker', 'keylogger', 'trojan', 'virus']
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info.get('cmdline', [])
            if cmdline and any(keyword in ' '.join(cmdline).lower() for keyword in suspicious_keywords):
                print(f"Processus suspect détecté : {proc.info['name']} (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


def check_for_injected_code():
    """
    Vérifie l'injection de code en recherchant des processus ou comportements suspects via tasklist.
    """
    try:
        result = subprocess.run(["tasklist", "/v"], capture_output=True, text=True, encoding="cp1252")
        if result.stdout:
            suspicious_processes = ['cmd.exe', 'powershell.exe', 'svchost.exe', 'explorer.exe']
            for line in result.stdout.splitlines():
                for process in suspicious_processes:
                    if process in line:
                        print(f"Possible injection détectée : {line}")
        else:
            print("Aucune sortie obtenue de la commande tasklist.")
    except subprocess.SubprocessError as e:
        print(f"Erreur lors de l'exécution de tasklist: {e}")
        messagebox.showerror("Erreur", f"Erreur lors de l'exécution de la commande tasklist : {e}")


def analyze_file_thread(file_path):
    """Exécute l'analyse dans un thread séparé pour ne pas bloquer l'interface utilisateur"""
    analyze_file(file_path)


def close_app(window):
    """
    Gère la fermeture de l'application de manière sécurisée
    pour éviter des erreurs lors de la fermeture.
    """
    try:
        window.quit()  # Fermer proprement l'application
    except Exception as e:
        print(f"Erreur lors de la fermeture : {str(e)}")
        window.destroy()


if __name__ == "__main__":
    # Création de la fenêtre Tkinter
    root = Tk()
    root.title("Analyse de Fichiers")
    
    # Exemple d'appel à une fonction d'analyse
    file_path = "C:/path/to/your/file.exe"

    # Démarre l'analyse dans un thread pour ne pas bloquer l'interface utilisateur
    threading.Thread(target=analyze_file_thread, args=(file_path,), daemon=True).start()
    
    # Ajouter un bouton pour fermer l'application proprement
    close_button = Button(root, text="Fermer", command=lambda: close_app(root))
    close_button.pack()

    # Quand la fenêtre est fermée, on gère la fermeture proprement
    root.protocol("WM_DELETE_WINDOW", lambda: close_app(root))
    root.mainloop()
