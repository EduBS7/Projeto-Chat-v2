import socket
import threading
import sqlite3
import json
import os
import secrets
from datetime import datetime
import tkinter as tk
from tkinter import messagebox
from security import SecurityEngine

HOST = '127.0.0.1'
PORT = 5000

BG_COLOR = "#131314"
SEC_BG = "#1e1e20"
TEXT_COLOR = "#e3e3e3"
ACCENT_COLOR = "#8ab4f8"
BTN_BG = "#333537"
BTN_FG = "#ffffff"

#Classe principal do Cliente
class ChatClient:
    def __init__(self, root):
        #config da janela base
        self.root = root
        self.root.title("Chat")
        self.root.configure(bg=BG_COLOR)
        self.root.geometry("800x500")
        
        try:
            img = tk.PhotoImage(file="icone.png")
            self.root.iconphoto(False, img)
        except:
            pass
            
        self.username = None
        self.current_chat = None
        self.typing_timer = None
        self.all_users = []
        self.online_users = []
        self.conn = None
        self.c = None
        
        self.sec = SecurityEngine()
        self.session_key1 = None
        self.session_key2 = None
        self.peer_sessions = {}
        self.peer_pub_keys = {}
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))
        
        self.do_handshake()
        self.init_local_keys_db()
        self.setup_login_ui()
        
        #cria a thread q fica ouvindo o servidor o tempo todo
        threading.Thread(target=self.receive_loop, daemon=True).start()

    def do_handshake(self):
        dh_priv, dh_pub = self.sec.generate_dh_keypair()
        salt = os.urandom(16)
        self.sock.send((json.dumps({"type": "dh_exchange", "pub_key": dh_pub.hex(), "salt": salt.hex()}) + '\n').encode('utf-8'))
        res = json.loads(self.sock.recv(4096).decode('utf-8').split('\n')[0])
        shared = self.sec.compute_shared_secret(dh_priv, bytes.fromhex(res["pub_key"]))
        self.session_key1, self.session_key2 = self.sec.derive_keys_hkdf(shared, salt)

    def send_data(self, data):
        iv, ct, mac = self.sec.encrypt_and_mac(self.session_key1, self.session_key2, json.dumps(data))
        self.sock.send((json.dumps({"iv": iv.hex(), "ciphertext": ct.hex(), "mac": mac.hex()}) + '\n').encode('utf-8'))

    def init_local_keys_db(self):
        self.keys_conn = sqlite3.connect("client_keys.sqlite", check_same_thread=False)
        self.keys_c = self.keys_conn.cursor()
        self.keys_c.execute("CREATE TABLE IF NOT EXISTS my_keys (username TEXT PRIMARY KEY, priv_key TEXT, pub_key TEXT)")
        self.keys_conn.commit()

    def get_local_keys(self, username):
        self.keys_c.execute("SELECT priv_key, pub_key FROM my_keys WHERE username=?", (username,))
        return self.keys_c.fetchone()

    def save_local_keys(self, username, priv_hex, pub_hex):
        self.keys_c.execute("REPLACE INTO my_keys (username, priv_key, pub_key) VALUES (?, ?, ?)", (username, priv_hex, pub_hex))
        self.keys_conn.commit()

    def init_chat_db(self):
        db_name = f"chat_{self.username}.sqlite"
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.c = self.conn.cursor()
        #tabelas
        self.c.execute("CREATE TABLE IF NOT EXISTS local_history (contact TEXT, sender TEXT, timestamp TEXT, text TEXT)")
        self.conn.commit()

    def setup_login_ui(self):
        #Cria e posiciona tela de Login no meio da tela
        self.login_frame = tk.Frame(self.root, bg=BG_COLOR)
        self.login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        tk.Label(self.login_frame, text="Login", font=("Segoe UI", 20, "bold"), bg=BG_COLOR, fg=TEXT_COLOR).pack(pady=15)

        #inputs de ususario
        tk.Label(self.login_frame, text="Usuário:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
        self.entry_user = tk.Entry(self.login_frame, bg=SEC_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief=tk.FLAT, font=("Segoe UI", 12))
        self.entry_user.pack(fill=tk.X, pady=5, ipady=5)

        #inputs de senha (show="*" esconde o texto)
        tk.Label(self.login_frame, text="Senha:", bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w", pady=(10, 0))
        self.entry_pass = tk.Entry(self.login_frame, show="*", bg=SEC_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief=tk.FLAT, font=("Segoe UI", 12))
        self.entry_pass.pack(fill=tk.X, pady=5, ipady=5)

        #Botoes embaixo
        btn_frame = tk.Frame(self.login_frame, bg=BG_COLOR)
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="Login", command=self.login, bg=ACCENT_COLOR, fg=BG_COLOR, font=("Segoe UI", 10, "bold"), relief=tk.FLAT, width=12).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Registrar", command=self.register, bg=BTN_BG, fg=BTN_FG, font=("Segoe UI", 10), relief=tk.FLAT, width=12).pack(side=tk.LEFT, padx=5)

    def setup_chat_ui(self):
        #Apaga tela de login e desenha a do Chat
        self.login_frame.destroy()
        self.init_chat_db()
        
        self.chat_frame = tk.Frame(self.root, bg=BG_COLOR)
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

        #Barra lateral esquerda (area dos contatos)
        left_frame = tk.Frame(self.chat_frame, bg=SEC_BG, width=250)
        left_frame.pack(side=tk.LEFT, fill=tk.Y)
        left_frame.pack_propagate(False)

        top_left_frame = tk.Frame(left_frame, bg=SEC_BG)
        top_left_frame.pack(fill=tk.X, pady=10, padx=10)
        
        tk.Label(top_left_frame, text="Contatos", font=("Segoe UI", 12, "bold"), bg=SEC_BG, fg=TEXT_COLOR).pack(side=tk.LEFT)

        #Listbox pra selecionar o contato clicando
        self.listbox_contacts = tk.Listbox(left_frame, bg=SEC_BG, fg=TEXT_COLOR, selectbackground=ACCENT_COLOR, selectforeground=BG_COLOR, relief=tk.FLAT, highlightthickness=0, font=("Segoe UI", 11))
        self.listbox_contacts.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.listbox_contacts.bind('<<ListboxSelect>>', self.select_contact) #chama evt de clique

        #Area central/direita (onde ocorre a conversa)
        self.right_frame = tk.Frame(self.chat_frame, bg=BG_COLOR)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        #topo do chat
        header_frame = tk.Frame(self.right_frame, bg=SEC_BG)
        header_frame.pack(side=tk.TOP, fill=tk.X)
        
        self.lbl_chat_with = tk.Label(header_frame, text="Selecione um contato", font=("Segoe UI", 14, "bold"), bg=SEC_BG, fg=TEXT_COLOR, pady=10)
        self.lbl_chat_with.pack(side=tk.LEFT, padx=15)

        #Aviso de alguem digitando
        self.lbl_typing = tk.Label(header_frame, text="", fg=ACCENT_COLOR, bg=SEC_BG, font=("Segoe UI", 10, "italic"))
        self.lbl_typing.pack(side=tk.RIGHT, padx=15)

        bottom_frame = tk.Frame(self.right_frame, bg=BG_COLOR, pady=10, padx=15)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        #input do texto q vou mandar
        self.entry_msg = tk.Entry(bottom_frame, bg=SEC_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief=tk.FLAT, font=("Segoe UI", 12))
        self.entry_msg.pack(fill=tk.BOTH, side=tk.LEFT, expand=True, ipady=8, padx=(0, 10))
        self.entry_msg.bind("<KeyRelease>", self.on_typing) #evento pra disparar q to digitando
        self.entry_msg.bind("<Return>", lambda e: self.send_msg()) #enter funciona q nem o botao

        tk.Button(bottom_frame, text="Enviar", command=self.send_msg, bg=ACCENT_COLOR, fg=BG_COLOR, font=("Segoe UI", 11, "bold"), relief=tk.FLAT, width=10).pack(side=tk.RIGHT, ipady=4)

        self.text_msgs = tk.Text(self.right_frame, state=tk.DISABLED, bg=BG_COLOR, fg=TEXT_COLOR, relief=tk.FLAT, font=("Segoe UI", 11), padx=15, pady=15, height=1)
        self.text_msgs.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.refresh_contact_list()

    def refresh_contact_list(self):
        #atualiza a barra lateral (ve quem ta on pra por a bolinha verde)
        if not hasattr(self, 'listbox_contacts'): return
        self.listbox_contacts.delete(0, tk.END)
        for u in self.all_users:
            if u != self.username:
                status = "🟢" if u in self.online_users else "⚪"
                self.listbox_contacts.insert(tk.END, f"{status} {u}")

    def register(self):
        u = self.entry_user.get()
        p = self.entry_pass.get()
        priv_bytes, pub_bytes = self.sec.generate_signature_keypair()
        self.save_local_keys(u, priv_bytes.hex(), pub_bytes.hex())
        self.send_data({"type": "register", "user": u, "pass": p, "pub_key": pub_bytes.hex()})

    def login(self):
        #botao de logar
        self.username = self.entry_user.get()
        keys = self.get_local_keys(self.username)
        if keys:
            self.send_data({"type": "login_request", "user": self.username})
        else:
            p = self.entry_pass.get()
            priv_bytes, pub_bytes = self.sec.generate_signature_keypair()
            self.save_local_keys(self.username, priv_bytes.hex(), pub_bytes.hex())
            self.send_data({"type": "login_new_device", "user": self.username, "pass": p, "pub_key": pub_bytes.hex()})

    def receive_loop(self):
        #Thread roda isso infinito (esperando infos do server)
        while True:
            try:
                data = self.sock.recv(16384)
                if not data: break
                for msg_str in data.decode('utf-8').split('\n'):
                    if not msg_str.strip(): continue
                    payload = json.loads(msg_str)
                    
                    if "ciphertext" in payload:
                        pt = self.sec.verify_mac_and_decrypt(self.session_key1, self.session_key2, bytes.fromhex(payload["iv"]), bytes.fromhex(payload["ciphertext"]), bytes.fromhex(payload["mac"]))
                        if not pt: continue
                        res = json.loads(pt)
                    else: 
                        res = payload

                    #IFs definindo oq q o servidor respondeu
                    if res["type"] == "register_ack":
                        m = "Registrado com sucesso." if res["success"] else "Falha no registro (Usuário já existe)."
                        self.root.after(0, lambda m=m: messagebox.showinfo("Aviso", m))
                        
                    elif res["type"] == "login_challenge":
                        keys = self.get_local_keys(self.username)
                        if keys:
                            sig = self.sec.sign_nonce(bytes.fromhex(keys[0]), bytes.fromhex(res["nonce"]))
                            self.send_data({"type": "login_verify", "user": self.username, "signature": sig.hex()})
                            
                    elif res["type"] == "login_ack":
                        #se foi sucesso entra no app, senao da erro
                        if res["success"]: self.root.after(0, self.setup_chat_ui)
                        else: self.root.after(0, lambda: messagebox.showerror("Erro", "Login falhou."))
                        
                    elif res["type"] == "status_update":
                        self.all_users = res["all"]
                        self.online_users = res["online"]
                        self.root.after(0, self.refresh_contact_list)
                        
                    elif res["type"] == "pub_key_res": 
                        self.peer_pub_keys[res["target"]] = res["pub_key"]
                        self.init_e2ee(res["target"])
                        
                    elif res["type"] == "e2ee_handshake_init": 
                        self.handle_e2ee_init(res)
                        
                    elif res["type"] == "e2ee_handshake_res": 
                        self.handle_e2ee_res(res)
                        
                    elif res["type"] == "e2ee_auth_req": 
                        self.handle_peer_auth_req(res)
                        
                    elif res["type"] == "e2ee_auth_res": 
                        self.peer_sessions[res["sender"]]["auth"] = True
                        
                    elif res["type"] == "msg": 
                        self.handle_incoming_msg(res)
                        
                    elif res["type"] == "typing":
                        #aparece q a pessoa ta digitando... no topo da tela
                        if self.current_chat == res["sender"]:
                            status = "Digitando..." if res["status"] else ""
                            self.root.after(0, lambda s=status: self.lbl_typing.config(text=s))
            except Exception as e: 
                break

    def select_contact(self, event):
        #evento de clicar num contato da listbox da esq
        selection = self.listbox_contacts.curselection()
        if selection:
            contact_str = self.listbox_contacts.get(selection[0])
            self.current_chat = contact_str.split(" ", 1)[1].strip()
            self.lbl_chat_with.config(text=self.current_chat)
            self.load_history()
            
            if self.current_chat not in self.peer_sessions: 
                self.send_data({"type": "get_pub_key", "target": self.current_chat})

    def init_e2ee(self, target):
        priv, pub = self.sec.generate_dh_keypair()
        salt = os.urandom(16)
        self.peer_sessions[target] = {"dh_priv": priv, "salt": salt, "auth": False}
        self.send_data({"type": "e2ee_handshake_init", "sender": self.username, "recipient": target, "pub_key": pub.hex(), "salt": salt.hex()})

    def handle_e2ee_init(self, res):
        target = res["sender"]
        priv, pub = self.sec.generate_dh_keypair()
        shared = self.sec.compute_shared_secret(priv, bytes.fromhex(res["pub_key"]))
        k1, k2 = self.sec.derive_keys_hkdf(shared, bytes.fromhex(res["salt"]))
        self.peer_sessions[target] = {"k1": k1, "k2": k2, "auth": False}
        self.send_data({"type": "e2ee_handshake_res", "sender": self.username, "recipient": target, "pub_key": pub.hex()})
        nonce = secrets.token_hex(16)
        self.peer_sessions[target]["nonce"] = nonce
        self.send_data({"type": "e2ee_auth_req", "sender": self.username, "recipient": target, "nonce": nonce})

    def handle_e2ee_res(self, res):
        target = res["sender"]
        if target in self.peer_sessions and "dh_priv" in self.peer_sessions[target]:
            s = self.peer_sessions[target]
            shared = self.sec.compute_shared_secret(s["dh_priv"], bytes.fromhex(res["pub_key"]))
            s["k1"], s["k2"] = self.sec.derive_keys_hkdf(shared, s["salt"])
            nonce = secrets.token_hex(16)
            s["nonce"] = nonce
            self.send_data({"type": "e2ee_auth_req", "sender": self.username, "recipient": target, "nonce": nonce})

    def handle_peer_auth_req(self, res):
        target = res["sender"]
        keys = self.get_local_keys(self.username)
        if keys:
            sig = self.sec.sign_nonce(bytes.fromhex(keys[0]), bytes.fromhex(res["nonce"]))
            self.send_data({"type": "e2ee_auth_res", "sender": self.username, "recipient": target, "signature": sig.hex()})

    def send_msg(self):
        if not self.current_chat: return
        txt = self.entry_msg.get()
        
        if txt:
            if self.current_chat in self.peer_sessions and "k1" in self.peer_sessions[self.current_chat]:
                s = self.peer_sessions[self.current_chat]
                ts = datetime.now().strftime("%H:%M")
                iv, ct, mac = self.sec.encrypt_and_mac(s["k1"], s["k2"], txt)
                msg = {"type": "msg", "sender": self.username, "recipient": self.current_chat, "timestamp": ts, "iv": iv.hex(), "ct": ct.hex(), "mac": mac.hex()}
                self.send_data(msg)
                
                self.c.execute("INSERT INTO local_history (contact, sender, timestamp, text) VALUES (?, ?, ?, ?)", (self.current_chat, self.username, ts, txt))
                self.conn.commit()
                
                self.display_msg(self.username, txt, ts)
                self.entry_msg.delete(0, tk.END)
                self.send_data({"type": "typing", "sender": self.username, "recipient": self.current_chat, "status": False})
            else:
                #regra de segurança
                messagebox.showwarning("Segurança E2EE", "A mensagem não pôde ser entregue.\n\nPor questão de segurança, vocês precisam estar online ao mesmo tempo pelo menos uma vez para gerar a chave de segurança ponta-a-ponta.")

    def handle_incoming_msg(self, res):
        sender = res["sender"]
        #proteção extra para garantir que só descriptografa se a chave existir
        if sender in self.peer_sessions and "k1" in self.peer_sessions[sender]:
            s = self.peer_sessions[sender]
            txt = self.sec.verify_mac_and_decrypt(s["k1"], s["k2"], bytes.fromhex(res["iv"]), bytes.fromhex(res["ct"]), bytes.fromhex(res["mac"]))
            if txt:
                self.c.execute("INSERT INTO local_history (contact, sender, timestamp, text) VALUES (?, ?, ?, ?)", (sender, sender, res["timestamp"], txt))
                self.conn.commit()
                if self.current_chat == sender: 
                    self.root.after(0, self.display_msg, sender, txt, res["timestamp"])

    def display_msg(self, sender, text, ts):
        self.text_msgs.config(state=tk.NORMAL)
        prefix = "Você" if sender == self.username else sender
        self.text_msgs.insert(tk.END, f"[{ts}] {prefix}: {text}\n")
        self.text_msgs.config(state=tk.DISABLED)
        self.text_msgs.see(tk.END)

    def load_history(self):
        self.text_msgs.config(state=tk.NORMAL)
        self.text_msgs.delete(1.0, tk.END)
        self.c.execute("SELECT sender, timestamp, text FROM local_history WHERE contact=? ORDER BY rowid ASC", (self.current_chat,))
        for row in self.c.fetchall(): 
            prefix = "Você" if row[0] == self.username else row[0]
            self.text_msgs.insert(tk.END, f"[{row[1]}] {prefix}: {row[2]}\n")
        self.text_msgs.config(state=tk.DISABLED) #trava edicao dnv
        self.text_msgs.see(tk.END) #joga barra rolagem pro fim

    def on_typing(self, event):
        #dispara status true pra digitando se n foi enter (return)
        if self.current_chat and event.keysym != 'Return':
            self.send_data({"type": "typing", "sender": self.username, "recipient": self.current_chat, "status": True})
            if self.typing_timer: self.root.after_cancel(self.typing_timer)
            self.typing_timer = self.root.after(2000, self.stop_typing)

    def stop_typing(self):
        #manda status false de digitando
        if self.current_chat:
            self.send_data({"type": "typing", "sender": self.username, "recipient": self.current_chat, "status": False})

#inicia o programa
if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop() #loop infinito do UI q deixa a janela viva