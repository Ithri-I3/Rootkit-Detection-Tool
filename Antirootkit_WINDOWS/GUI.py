import tkinter as tk
from tkinter import filedialog
import os
import subprocess
from tkinter import Scrollbar

def start_machine_scan():
    """
    Lancer une analyse complète de la machine en exécutant le fichier C++.
    """
    try:
        # Get the directory where the script is located
        script_dir = os.path.dirname(os.path.realpath(__file__))
        
        # Path to cpp in the same directory as the script
        executable_path = os.path.join(script_dir, "user-app_library_memory.exe")
        
        # Exécuter le fichier cpp et capturer la sortie
        result = subprocess.run(
            [executable_path], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        
        # Vérifiez s'il y a une erreur
        if result.returncode != 0:
            error_message = f"Erreur lors de l'exécution :\n{result.stderr}"
            show_scrollable_message("Erreur", error_message)
        else:
            output_message = f"Sortie de l'analyse :\n{result.stdout}"
            show_scrollable_message("Résultat de l'analyse", output_message)
    
    except FileNotFoundError:
        show_scrollable_message("Erreur", "Le fichier exécutable cpp est introuvable.")
    except Exception as e:
        show_scrollable_message("Erreur", f"Une erreur inattendue s'est produite : {str(e)}")

def show_scrollable_message(title, message):
    """
    Affiche un message dans une fenêtre Toplevel avec une zone de texte scrollable.
    """
    # Création de la fenêtre Toplevel
    top = tk.Toplevel()
    top.title(title)
    
    # Zone de texte pour afficher le message
    text_widget = tk.Text(top, wrap=tk.WORD, width=80, height=20, bg="black", fg="green", font=("Courier", 10))
    text_widget.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    
    # Ajout d'une barre de défilement
    scrollbar = Scrollbar(top, command=text_widget.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    text_widget.config(yscrollcommand=scrollbar.set)
    
    # Insertion du message dans la zone de texte
    text_widget.insert(tk.END, message)
    text_widget.config(state=tk.DISABLED)  # Rendre la zone de texte non modifiable
    
    # Bouton pour fermer la fenêtre
    close_button = tk.Button(top, text="Fermer", command=top.destroy, bg="red", fg="white")
    close_button.pack(pady=10)

def analyze_file_gui():
    """
    Permet à l'utilisateur de sélectionner un fichier à analyser.
    """
    file_path = filedialog.askopenfilename(title="Sélectionnez un fichier")
    if file_path:
        # Appeler la fonction d'analyse de fichier depuis FileAnalysis.py
        analyze_file(file_path)

def analyze_directory():
    """
    Permet à l'utilisateur de sélectionner un répertoire à analyser.
    Chaque fichier dans le répertoire est analysé.
    """
    directory_path = filedialog.askdirectory(title="Sélectionnez un répertoire")
    if directory_path:
        try:
            files = os.listdir(directory_path)
            # Filtrer les fichiers uniquement
            files = [f for f in files if os.path.isfile(os.path.join(directory_path, f))]
            if not files:
                show_scrollable_message("Analyse de répertoire", "Aucun fichier trouvé dans le répertoire.")
                return
            
            # Analyse de chaque fichier
            for file in files:
                file_path = os.path.join(directory_path, file)
                analyze_file(file_path)
            
            show_scrollable_message("Analyse de répertoire", "L'analyse du répertoire est terminée.")
        except Exception as e:
            show_scrollable_message("Erreur", f"Erreur lors de l'analyse du répertoire : {str(e)}")

# Création de la fenêtre principale
root = tk.Tk()
root.title("Outil Anti-Rootkit")

# Couleurs et thèmes pour l'interface utilisateur
bg_color = "#FFFFFF"  # Blanc pour le fond
button_color = "#000000"  # Noir pour les boutons
button_text_color = "#00FF00"  # Vert néon pour le texte des boutons
font_color = "#FF0000"  # Rouge pour les titres

# Configurer la taille et le fond de la fenêtre
root.geometry("400x300")
root.configure(bg=bg_color)

# Titre de l'application
title_label = tk.Label(root, text="Outil Anti-Rootkit", fg=font_color, bg=bg_color, font=("Helvetica", 16, "bold"))
title_label.pack(pady=20)

# Bouton pour lancer une analyse de la machine
machine_scan_button = tk.Button(
    root, text="Lancer une analyse de la machine", bg=button_color, fg=button_text_color,
    font=("Helvetica", 12), command=start_machine_scan
)
machine_scan_button.pack(pady=10)

# Bouton pour analyser un fichier
file_analysis_button = tk.Button(
    root, text="Analyser un fichier", bg=button_color, fg=button_text_color,
    font=("Helvetica", 12), command=analyze_file_gui
)
file_analysis_button.pack(pady=10)

# Bouton pour analyser un répertoire
directory_analysis_button = tk.Button(
    root, text="Analyser un répertoire", bg=button_color, fg=button_text_color,
    font=("Helvetica", 12), command=analyze_directory
)
directory_analysis_button.pack(pady=10)

# Démarrage de la boucle principale de l'application
root.mainloop()
