import socket
import threading
import sqlite3
import json
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, simpledialog

HOST = '127.0.0.1'
PORT = 5000

BG_COLOR = "#131314"
SEC_BG = "#1e1e20"
TEXT_COLOR = "#e3e3e3"
ACCENT_COLOR = "#8ab4f8"
BTN_BG = "#333537"
BTN_FG = "#ffffff"

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat")
        self.root.configure(bg=BG_COLOR)
        self.root.geometry("800x500")
        try:
            icone_img = tk.PhotoImage(file="icone.png")
            self.root.iconphoto(False, icone_img)
        except:
            pass
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))
        self.username = None
        self.current_chat = None
        self.typing_timer = None
        self.online_users = []

        self.init_db()
        self.setup_login_ui()
        threading.Thread(target=self.receive_loop, daemon=True).start()

    def init_db(self):
        self.conn = sqlite3.connect("client_db.sqlite", check_same_thread=False)
        self.c = self.conn.cursor()
        self.c.execute("CREATE TABLE IF NOT EXISTS local_history (contact TEXT, sender TEXT, timestamp TEXT, text TEXT)")
        self.c.execute("CREATE TABLE IF NOT EXISTS contacts (username TEXT UNIQUE)")
        self.conn.commit()

    def setup_login_ui(self):
        self.login_frame = tk.Frame(self.root, bg=BG_COLOR)
        self.login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        tk.Label(self.login_frame, text="Chat Login", font=("Segoe UI", 20, "bold"), bg=BG_COLOR, fg=TEXT_COLOR).pack(pady=15)

        tk.Label(self.login_frame, text="Usuário:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.entry_user = tk.Entry(self.login_frame, bg=SEC_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief=tk.FLAT, font=("Segoe UI", 12))
        self.entry_user.pack(fill=tk.X, pady=5, ipady=5)

        tk.Label(self.login_frame, text="Senha:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w", pady=(10, 0))
        self.entry_pass = tk.Entry(self.login_frame, show="*", bg=SEC_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief=tk.FLAT, font=("Segoe UI", 12))
        self.entry_pass.pack(fill=tk.X, pady=5, ipady=5)

        btn_frame = tk.Frame(self.login_frame, bg=BG_COLOR)
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="Login", command=self.login, bg=ACCENT_COLOR, fg=BG_COLOR, font=("Segoe UI", 10, "bold"), relief=tk.FLAT, width=12).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Registrar", command=self.register, bg=BTN_BG, fg=BTN_FG, font=("Segoe UI", 10), relief=tk.FLAT, width=12).pack(side=tk.LEFT, padx=5)

    def setup_chat_ui(self):
        self.login_frame.destroy()
        self.chat_frame = tk.Frame(self.root, bg=BG_COLOR)
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = tk.Frame(self.chat_frame, bg=SEC_BG, width=250)
        left_frame.pack(side=tk.LEFT, fill=tk.Y)
        left_frame.pack_propagate(False)

        top_left_frame = tk.Frame(left_frame, bg=SEC_BG)
        top_left_frame.pack(fill=tk.X, pady=10, padx=10)
        
        tk.Label(top_left_frame, text="Meus Contatos", font=("Segoe UI", 12, "bold"), bg=SEC_BG, fg=TEXT_COLOR).pack(side=tk.LEFT)
        tk.Button(top_left_frame, text="+", command=self.add_contact, bg=BTN_BG, fg=BTN_FG, relief=tk.FLAT, font=("Segoe UI", 10, "bold")).pack(side=tk.RIGHT)

        self.listbox_contacts = tk.Listbox(left_frame, bg=SEC_BG, fg=TEXT_COLOR, selectbackground=ACCENT_COLOR, selectforeground=BG_COLOR, relief=tk.FLAT, highlightthickness=0, font=("Segoe UI", 11))
        self.listbox_contacts.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.listbox_contacts.bind('<<ListboxSelect>>', self.select_contact)

        self.right_frame = tk.Frame(self.chat_frame, bg=BG_COLOR)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        header_frame = tk.Frame(self.right_frame, bg=SEC_BG)
        header_frame.pack(side=tk.TOP, fill=tk.X)
        
        self.lbl_chat_with = tk.Label(header_frame, text="Selecione um contato para conversar", font=("Segoe UI", 14, "bold"), bg=SEC_BG, fg=TEXT_COLOR, pady=10)
        self.lbl_chat_with.pack(side=tk.LEFT, padx=15)

        self.lbl_typing = tk.Label(header_frame, text="", fg=ACCENT_COLOR, bg=SEC_BG, font=("Segoe UI", 10, "italic"))
        self.lbl_typing.pack(side=tk.RIGHT, padx=15)

        # Correção: Fixando a barra inferior no fundo da tela PRIMEIRO
        bottom_frame = tk.Frame(self.right_frame, bg=BG_COLOR, pady=10, padx=15)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.entry_msg = tk.Entry(bottom_frame, bg=SEC_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief=tk.FLAT, font=("Segoe UI", 12))
        self.entry_msg.pack(fill=tk.BOTH, side=tk.LEFT, expand=True, ipady=8, padx=(0, 10))
        self.entry_msg.bind("<KeyRelease>", self.on_typing)
        self.entry_msg.bind("<Return>", lambda e: self.send_msg())

        tk.Button(bottom_frame, text="Enviar", command=self.send_msg, bg=ACCENT_COLOR, fg=BG_COLOR, font=("Segoe UI", 11, "bold"), relief=tk.FLAT, width=10).pack(side=tk.RIGHT, ipady=4)

        # Renderizando a área de texto por último para preencher apenas o espaço que sobrou
        self.text_msgs = tk.Text(self.right_frame, state=tk.DISABLED, bg=BG_COLOR, fg=TEXT_COLOR, relief=tk.FLAT, font=("Segoe UI", 11), padx=15, pady=15, height=1)
        self.text_msgs.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.refresh_contact_list()

    def add_contact(self):
        new_contact = simpledialog.askstring("Novo Contato", "Digite o nome de usuário do contato:", parent=self.root)
        if new_contact:
            if new_contact == self.username:
                messagebox.showwarning("Aviso", "Você não pode adicionar a si mesmo.")
                return
            try:
                self.c.execute("INSERT INTO contacts (username) VALUES (?)", (new_contact,))
                self.conn.commit()
                self.refresh_contact_list()
            except sqlite3.IntegrityError:
                messagebox.showinfo("Info", "este usuário já está na sua lista de contatos.")

    def refresh_contact_list(self):
        if not hasattr(self, 'listbox_contacts'): return
        
        self.listbox_contacts.delete(0, tk.END)
        self.c.execute("SELECT username FROM contacts ORDER BY username ASC")
        for row in self.c.fetchall():
            contact_name = row[0]
            status = "🟢" if contact_name in self.online_users else "⚪"
            self.listbox_contacts.insert(tk.END, f"{status} {contact_name}")

    def send_data(self, data):
        self.sock.send(json.dumps(data).encode('utf-8'))

    def register(self):
        self.send_data({"type": "register", "user": self.entry_user.get(), "pass": self.entry_pass.get()})

    def login(self):
        self.username = self.entry_user.get()
        self.send_data({"type": "login", "user": self.username, "pass": self.entry_pass.get()})

    def receive_loop(self):
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                msgs = data.decode('utf-8').replace('}{', '}\n{').split('\n')
                for msg_str in msgs:
                    if not msg_str: continue
                    res = json.loads(msg_str)

                    if res["type"] == "register_ack":
                        if res["success"]: messagebox.showinfo("OK", "Registrado com sucesso.")
                        else: messagebox.showerror("Erro", "Usuário já existe.")

                    elif res["type"] == "login_ack":
                        if res["success"]: self.root.after(0, self.setup_chat_ui)
                        else: messagebox.showerror("Erro", "Credenciais incorretas.")

                    elif res["type"] == "status_update":
                        self.online_users = res["online"]
                        self.root.after(0, self.refresh_contact_list)

                    elif res["type"] == "msg":
                        self.c.execute("INSERT INTO local_history (contact, sender, timestamp, text) VALUES (?, ?, ?, ?)",
                                       (res["sender"], res["sender"], res["timestamp"], res["text"]))
                        self.conn.commit()
                        if self.current_chat == res["sender"]:
                            self.root.after(0, self.display_msg, res["sender"], res["text"], res["timestamp"])

                    elif res["type"] == "typing":
                        if self.current_chat == res["sender"]:
                            status = "Digitando..." if res["status"] else ""
                            self.root.after(0, lambda s=status: self.lbl_typing.config(text=s))
            except Exception:
                break

    def select_contact(self, event):
        selection = self.listbox_contacts.curselection()
        if selection:
            contact_str = self.listbox_contacts.get(selection[0])
            self.current_chat = contact_str[2:] 
            self.lbl_chat_with.config(text=self.current_chat)
            self.load_history()

    def load_history(self):
        self.text_msgs.config(state=tk.NORMAL)
        self.text_msgs.delete(1.0, tk.END)
        self.c.execute("SELECT sender, timestamp, text FROM local_history WHERE contact=? ORDER BY rowid ASC", (self.current_chat,))
        for row in self.c.fetchall():
            prefix = "Você" if row[0] == self.username else row[0]
            self.text_msgs.insert(tk.END, f"[{row[1]}] {prefix}: {row[2]}\n")
        self.text_msgs.config(state=tk.DISABLED)
        self.text_msgs.see(tk.END)

    def send_msg(self):
        if not self.current_chat:
            messagebox.showwarning("Aviso", "Por favor, adicione e selecione um contato na lista à esquerda antes de enviar.")
            return

        text = self.entry_msg.get()
        if text:
            ts = datetime.now().strftime("%H:%M")
            msg_data = {"type": "msg", "sender": self.username, "recipient": self.current_chat, "timestamp": ts, "text": text}
            self.send_data(msg_data)
            
            self.c.execute("INSERT INTO local_history (contact, sender, timestamp, text) VALUES (?, ?, ?, ?)",
                           (self.current_chat, self.username, ts, text))
            self.conn.commit()
            
            self.display_msg(self.username, text, ts)
            self.entry_msg.delete(0, tk.END)
            self.send_data({"type": "typing", "sender": self.username, "recipient": self.current_chat, "status": False})

    def display_msg(self, sender, text, ts):
        self.text_msgs.config(state=tk.NORMAL)
        prefix = "Você" if sender == self.username else sender
        self.text_msgs.insert(tk.END, f"[{ts}] {prefix}: {text}\n")
        self.text_msgs.config(state=tk.DISABLED)
        self.text_msgs.see(tk.END)

    def on_typing(self, event):
        if self.current_chat and event.keysym != 'Return':
            self.send_data({"type": "typing", "sender": self.username, "recipient": self.current_chat, "status": True})
            if self.typing_timer:
                self.root.after_cancel(self.typing_timer)
            self.typing_timer = self.root.after(2000, self.stop_typing)

    def stop_typing(self):
        if self.current_chat:
            self.send_data({"type": "typing", "sender": self.username, "recipient": self.current_chat, "status": False})

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()