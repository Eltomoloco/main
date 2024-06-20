from scapy.all import sniff
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import sqlite3

def save_selected_lines():
    selected_lines = text_area.tag_ranges("sel")
    if selected_lines:
        start, end = selected_lines
        selected_text = text_area.get(start, end)
        
        # Connect to SQLite database
        conn = sqlite3.connect('python.db')
        c = conn.cursor()
        
        # Create table if not exists
        c.execute('''CREATE TABLE IF NOT EXISTS selected_lines
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      line TEXT)''')
        
        # Insert selected text into the database
        c.execute("INSERT INTO selected_lines (line) VALUES (?)", (selected_text,))
        
        # Commit changes and close connection
        conn.commit()
        conn.close()
        
        messagebox.showinfo("Saved", "Selected lines saved to database successfully!")
    else:
        messagebox.showwarning("No Selection", "No lines selected.")	

def packet_callback(packet):
    # This function will be called for each packet captured
    packet_info = packet.summary()

    if "22" in packet_info:  # SSH packets
        tag = 'ssh'
    elif "80" in packet_info:  # HTTP packets
        tag = 'http'
    elif "443" in packet_info:  # HTTPS packets
        tag = 'https'
    else:
        tag = 'default'
    
    # Insert packet information with the correct tag for background color
    text_area.insert(tk.END, packet_info + '\n', tag)
    # Automatically scroll to the bottom
    text_area.see(tk.END)

def start_capture():
    # Clear any previous content in the text area
    text_area.delete('1.0', tk.END)
    # Building filter expression based on checkboxes
    filter_expression = []

    if http_var.get():
        filter_expression.append("tcp port 80")
    if https_var.get():
        filter_expression.append("tcp port 443")
    if ssh_var.get():
        filter_expression.append("tcp port 22")
    if smtp_var.get():
        filter_expression.append("tcp port 25")

    combined_filter = " or ".join(filter_expression)
    
    if combined_filter:
        status_label.config(text=f"Capturing packets with filter: {combined_filter}...")
        # Start capturing packets in a separate thread
        capture_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, filter=combined_filter, store=0))
        capture_thread.start()
    else:
        status_label.config(text="No capture option specified. Please select one or more options.")

# GUI setup
root = tk.Tk()
root.title("Packet Sniffer")

# Checkboxes for HTTP, HTTPS, SSH, and SMTP
http_var = tk.BooleanVar()
https_var = tk.BooleanVar()
ssh_var = tk.BooleanVar()
smtp_var = tk.BooleanVar()

http_checkbox = tk.Checkbutton(root, text="HTTP", variable=http_var)
http_checkbox.grid(row=0, column=0, padx=5, pady=5)

https_checkbox = tk.Checkbutton(root, text="HTTPS", variable=https_var)
https_checkbox.grid(row=0, column=1, padx=5, pady=5)

ssh_checkbox = tk.Checkbutton(root, text="SSH", variable=ssh_var)
ssh_checkbox.grid(row=0, column=2, padx=5, pady=5)

smtp_checkbox = tk.Checkbutton(root, text="SMTP", variable=smtp_var)
smtp_checkbox.grid(row=0, column=3, padx=5, pady=5)

# Button to start capture
capture_button = tk.Button(root, text="Start Capture", command=start_capture)
capture_button.grid(row=1, column=0, columnspan=4, padx=5, pady=5)

# Status label
status_label = tk.Label(root, text="")
status_label.grid(row=2, column=0, columnspan=4, padx=5, pady=5)

# Text area to display packet information
text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
text_area.grid(row=3, column=0, columnspan=4, padx=5, pady=5)

# Define tags with background colors
text_area.tag_configure('http', background='red')
text_area.tag_configure('https', background='yellow')  # You can change this to a different color
text_area.tag_configure('ssh', background='blue')
text_area.tag_configure('default', background='green')

# Button to save selected lines to database
save_button = tk.Button(root, text="Save selected output", command=save_selected_lines)
save_button.grid(row=4, column=0, columnspan=4, padx=5, pady=5)

root.mainloop()

