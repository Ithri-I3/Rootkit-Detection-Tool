import os
import subprocess
import threading
from tkinter import Tk, Button, messagebox


def analyze_file(file_path):
    """
    Main function to analyze the selected file
    and search for suspicious behaviors in its code.
    """
    if not os.path.exists(file_path):
        messagebox.showerror("Error", f"The file {file_path} does not exist.")
        return

    # Analyze file content
    analyze_file_code(file_path)

    # Perform system-level checks (e.g., injected code)
    check_for_injected_code()  # Check for injected code


def analyze_file_code(file_path):
    """
    Static analysis of the file code for typical rootkit signs.
    """
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
    except Exception as e:
        messagebox.showerror("Error", f"Cannot read the file: {str(e)}")
        return

    # Extended list of suspicious patterns
    suspicious_patterns = [
        # Linux system calls and functions
        b"execve", b"fork", b"clone", b"ptrace", b"mmap",

        # Typical malware keywords
        b"rootkit", b"backdoor", b"keylogger", b"trojan", b"virus",

        # Commands or utilities often exploited
        b"bash", b"sh", b"sudo", b"iptables", b"ssh", b"scp",

        # Libraries or binaries
        b"libc.so", b"libpthread.so", b"/bin/bash", b"/usr/bin/python"
    ]

    detected_patterns = []  # List to collect detected patterns

    for pattern in suspicious_patterns:
        if pattern in file_content:
            detected_patterns.append(pattern.decode('utf-8', 'ignore'))

    if detected_patterns:
        # Display all detected patterns
        detected_list = "\n".join(detected_patterns)
        print(f"Suspicious signs detected:\n{detected_list}")
        messagebox.showwarning("Alert", f"Suspicious signs detected in the file {file_path} :\n{detected_list}")
    else:
        print(f"No suspicious signs detected in the file {file_path}.")
        messagebox.showinfo("Analysis Complete", f"No suspicious signs detected in the file {file_path}")


def check_for_injected_code():
    """
    Checks for code injection by searching for suspicious processes using ps.
    """
    try:
        result = subprocess.run(["ps", "-aux"], capture_output=True, text=True)
        if result.stdout:
            suspicious_processes = ['bash', 'sh', 'python', 'perl', 'nc', 'wget']
            for line in result.stdout.splitlines():
                for process in suspicious_processes:
                    if process in line:
                        print(f"Possible injection detected: {line}")
        else:
            print("No output from ps command.")
    except subprocess.SubprocessError as e:
        print(f"Error running ps command: {e}")
        messagebox.showerror("Error", f"Error running ps command: {e}")


def analyze_file_thread(file_path):
    """Run the analysis in a separate thread to avoid blocking the UI."""
    analyze_file(file_path)


def close_app(window):
    """
    Safely handles application closure to avoid errors during exit.
    """
    try:
        window.quit()  # Cleanly close the application
    except Exception as e:
        print(f"Error during closure: {str(e)}")
        window.destroy()


if __name__ == "__main__":
    # Create Tkinter window
    root = Tk()
    root.title("File Analysis")

    # Example file path
    file_path = "/home/i3_mr1i/Master-SSI/Codes/antirootkit/test.txt"

    # Start analysis in a thread to avoid blocking the UI
    threading.Thread(target=analyze_file_thread, args=(file_path,), daemon=True).start()

    # Add a button to close the application cleanly
    close_button = Button(root, text="Close", command=lambda: close_app(root))
    close_button.pack()

    # Handle window closure
    root.protocol("WM_DELETE_WINDOW", lambda: close_app(root))
    root.mainloop()
