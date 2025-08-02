import customtkinter as ctk
from tkinter import filedialog, messagebox
import hashlib, os, time, threading

# --- App Configuration ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.geometry("750x750")
app.title("🔐 Advanced Hash Identifier & Cracker")

# --- Helper Functions ---
def identify_hash_type(hash_value):
    length = len(hash_value)
    if length == 32:
        return "md5"
    elif length == 40:
        return "sha1"
    elif length == 64:
        return "sha256"
    elif length == 128:
        return "sha512"
    else:
        return "unknown"

def hash_func(word, algo):
    word = word.encode()
    if algo == "md5":
        return hashlib.md5(word).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(word).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(word).hexdigest()
    elif algo == "sha512":
        return hashlib.sha512(word).hexdigest()

def browse_wordlist():
    file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file:
        wordlist_path_label.configure(text=file)

def browse_hashlist():
    file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file:
        hashlist_path_label.configure(text=file)
        single_hash_entry.delete(0, ctk.END)

def export_results(text):
    file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file:
        with open(file, "w") as f:
            f.write(text)
        messagebox.showinfo("Saved", f"Results saved to {file}")

def copy_results():
    app.clipboard_clear()
    app.clipboard_append(result_box.get("0.0", "end").strip())
    messagebox.showinfo("Copied", "Results copied to clipboard.")

def clear_fields():
    try:
        single_hash_entry.delete(0, ctk.END)
        hashlist_path_label.configure(text="No file selected")
        wordlist_path_label.configure(text="No file selected")
        result_box.configure(state="normal")
        result_box.delete("0.0", "end")
        result_box.configure(state="disabled")
        progress_bar.set(0)
        status_label.configure(text="Status: Waiting...")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to clear: {e}")

# --- Cracking Logic ---
def crack_single_hash(hash_value, algo, wordlist_path, total_words, update_bar):
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for i, word in enumerate(f, 1):
            word = word.strip()
            if hash_func(word, algo) == hash_value:
                return word
            update_bar(i / total_words)
    return None

def start_cracking():
    start_button.configure(state="disabled")
    result_box.configure(state="normal")
    result_box.delete("0.0", "end")

    hashes = []
    if hashlist_path_label.cget("text") != "No file selected":
        hash_file = hashlist_path_label.cget("text")
        if not os.path.exists(hash_file):
            messagebox.showerror("Error", "Selected hashlist file does not exist.")
            start_button.configure(state="normal")
            return
        with open(hash_file, "r") as hf:
            hashes = [line.strip() for line in hf if line.strip()]
    else:
        single_hash = single_hash_entry.get().strip()
        if single_hash:
            hashes = [single_hash]
        else:
            messagebox.showerror("Error", "Please input a hash or select a hashlist file.")
            start_button.configure(state="normal")
            return

    wordlist_file = wordlist_path_label.cget("text")
    if not os.path.exists(wordlist_file):
        messagebox.showerror("Error", "Please select a valid wordlist file.")
        start_button.configure(state="normal")
        return

    with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
        wordlist_lines = [line.strip() for line in f if line.strip()]
    total_words = len(wordlist_lines)

    manual_algo = algo_option.get().lower()
    use_manual = manual_check_var.get()

    cracked_results = []
    start_time = time.time()

    result_box.insert("0.0", f"[+] Starting crack for {len(hashes)} hash(es)...\n")
    status_label.configure(text="Status: Cracking...")
    app.update()

    for h in hashes:
        algo = manual_algo if use_manual else identify_hash_type(h)
        if algo == "unknown":
            result_box.insert("end", f"[-] Unknown hash type for: {h}\n")
            continue

        result_box.insert("end", f"[*] Cracking {h[:10]}... ({algo.upper()})\n")
        app.update()

        def update_bar(progress):
            progress_bar.set(progress)
            app.update_idletasks()

        cracked = crack_single_hash(h, algo, wordlist_file, total_words, update_bar)

        if cracked:
            result_box.insert("end", f"[+] Found: {h} = {cracked}\n")
            cracked_results.append(f"{h} = {cracked}")
        else:
            result_box.insert("end", f"[-] Not found: {h}\n")

    elapsed = time.time() - start_time
    result_box.insert("end", f"\n[+] Done in {elapsed:.2f} seconds\n")
    result_box.insert("end", f"[+] {len(cracked_results)} out of {len(hashes)} cracked\n")
    result_box.configure(state="disabled")
    progress_bar.set(1)
    status_label.configure(text="Status: Completed")
    start_button.configure(state="normal")

    if cracked_results:
        if messagebox.askyesno("Save Results?", "Do you want to save cracked passwords to a file?"):
            export_results("\n".join(cracked_results))

# --- GUI Layout ---
frame = ctk.CTkFrame(app)
frame.pack(pady=15, padx=20, fill="both", expand=True)

ctk.CTkLabel(frame, text="🔐 Advanced Hash Identifier & Cracker", font=ctk.CTkFont(size=22, weight="bold")).pack(pady=10)

# Hash input
ctk.CTkLabel(frame, text="Single Hash Input:").pack(anchor="w")
single_hash_entry = ctk.CTkEntry(frame, width=600)
single_hash_entry.pack(pady=5)

ctk.CTkLabel(frame, text="OR Load Hashlist File (.txt):").pack(anchor="w")
hashlist_path_label = ctk.CTkLabel(frame, text="No file selected", width=600)
hashlist_path_label.pack()
ctk.CTkButton(frame, text="Browse Hashlist", command=browse_hashlist).pack(pady=5)

# Wordlist input
ctk.CTkLabel(frame, text="Select Wordlist File (.txt):").pack(anchor="w")
wordlist_path_label = ctk.CTkLabel(frame, text="No file selected", width=600)
wordlist_path_label.pack()
ctk.CTkButton(frame, text="Browse Wordlist", command=browse_wordlist).pack(pady=5)

# Manual hash override
manual_check_var = ctk.BooleanVar(value=False)
manual_check = ctk.CTkCheckBox(frame, text="Use manual hash type override", variable=manual_check_var)
manual_check.pack(pady=5)

algo_option = ctk.CTkOptionMenu(frame, values=["md5", "sha1", "sha256", "sha512"])
algo_option.pack(pady=2)
algo_option.set("md5")

# Cracking button
start_button = ctk.CTkButton(
    frame, text="🚀 Start Cracking", 
    command=lambda: threading.Thread(target=start_cracking).start()
)
start_button.pack(pady=10)

# Button Row
btn_frame = ctk.CTkFrame(frame)
btn_frame.pack(pady=5)

ctk.CTkButton(btn_frame, text="🧹 Clear", command=clear_fields).pack(side="left", padx=10)
ctk.CTkButton(btn_frame, text="📋 Copy Results", command=copy_results).pack(side="left", padx=10)

# Output Box
ctk.CTkLabel(frame, text="Result Output:").pack(anchor="w")
result_box = ctk.CTkTextbox(frame, height=300, width=700)
result_box.pack(pady=10)
result_box.configure(state="disabled")

# Progress and Status
progress_bar = ctk.CTkProgressBar(frame, width=600)
progress_bar.pack(pady=5)
progress_bar.set(0)

status_label = ctk.CTkLabel(frame, text="Status: Waiting...")
status_label.pack()

# Run App
app.mainloop()

