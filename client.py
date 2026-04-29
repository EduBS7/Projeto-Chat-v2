import socket #pra conectar no servidor TCP
import threading #pra rodar o loop de receber msgs sem congelar a tela
import sqlite3 #banco de dados local (pra historico e chaves)
import json #pra serializar os pacotes q vao pela rede
import os #pra gerar bytes aleatorios (urandom)
import secrets #pra gerar tokens seguros (nonce)
from datetime import datetime #pra pegar a hora exata q a msg chegou
import tkinter as tk #interface grafica
from tkinter import messagebox
from security import SecurityEngine #nosso motor criptografico (nota 10)

#configs de conexao
HOST = '127.0.0.1'
PORT = 5000

#cores modo dark pro app ficar bonito
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
        
        #bota o icone, se der ruim ignora
        try:
            img = tk.PhotoImage(file="icone.png")
            self.root.iconphoto(False, img)
        except:
            pass
            
        #estados do cliente
        self.username = None
        self.current_chat = None
        self.typing_timer = None
        self.all_users = []
        self.online_users = []
        
        #instancia nossa classe de seguranca
        self.sec = SecurityEngine()
        
        #chaves da sessao com o SERVIDOR
        self.session_key1 = None #aes do server
        self.session_key2 = None #hmac do server
        
        #dicionarios pra guardar as sessoes com OS AMIGOS (E2EE)
        self.peer_sessions = {}
        self.peer_pub_keys = {}
        
        #chave aes usada SO pra trancar o nosso banco sqlite local
        self.local_aes_keys = None 
        
        #conecta no server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))
        
        #ordem de boot
        self.do_handshake() #negocia chaves do server
        self.init_local_keys_db() #inicia bd local
        self.setup_login_ui() #desenha tela de login
        
        #inicia a escuta infinita em backgroud
        threading.Thread(target=self.receive_loop, daemon=True).start()

    def do_handshake(self):
        #defesa: aqui rola o Diffie-Hellman Efêmero (DHE) c/ o servidor. 
        #tanto no inicio do app, qto pra renovar chaves qdo elas expiram!
        dh_priv, dh_pub = self.sec.generate_dh_keypair()
        salt = os.urandom(16)
        
        #manda minha chave pub e o salt pro server
        self.sock.send((json.dumps({"type": "dh_exchange", "pub_key": dh_pub.hex(), "salt": salt.hex()}) + '\n').encode('utf-8'))
        res = json.loads(self.sock.recv(4096).decode('utf-8').split('\n')[0])
        
        #calcula o segredo q so nois dois sabemos e joga no HKDF
        shared = self.sec.compute_shared_secret(dh_priv, bytes.fromhex(res["pub_key"]))
        self.session_key1, self.session_key2 = self.sec.derive_keys_hkdf(shared, salt)

    def send_data(self, data):
        #tudo q vai pro server passa por aqui pra ser cifrado (AES + HMAC)
        iv, ct, mac = self.sec.encrypt_and_mac(self.session_key1, self.session_key2, json.dumps(data))
        self.sock.send((json.dumps({"iv": iv.hex(), "ciphertext": ct.hex(), "mac": mac.hex()}) + '\n').encode('utf-8'))

    def init_local_keys_db(self):
        #bd pra salvar minhas chaves asssimetricas e a local_key do historico
        self.keys_conn = sqlite3.connect("client_keys.sqlite", check_same_thread=False)
        self.keys_c = self.keys_conn.cursor()
        self.keys_c.execute("CREATE TABLE IF NOT EXISTS my_keys (username TEXT PRIMARY KEY, priv_key TEXT, pub_key TEXT, local_key TEXT)")
        self.keys_conn.commit()

    def get_local_keys(self, username):
        #puxa as chaves do meu usuario no bd
        self.keys_c.execute("SELECT priv_key, pub_key, local_key FROM my_keys WHERE username=?", (username,))
        return self.keys_c.fetchone()

    def save_local_keys(self, username, priv_hex, pub_hex, local_key_hex):
        #salva ou atualiza as chaves locais
        self.keys_c.execute("REPLACE INTO my_keys (username, priv_key, pub_key, local_key) VALUES (?, ?, ?, ?)", (username, priv_hex, pub_hex, local_key_hex))
        self.keys_conn.commit()

    def init_chat_db(self):
        #cada usuario tem seu proprio bd de historico no pc
        db_name = f"chat_{self.username}.sqlite"
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.c = self.conn.cursor()
        self.c.execute("CREATE TABLE IF NOT EXISTS local_history (contact TEXT, sender TEXT, timestamp TEXT, text TEXT)")
        self.conn.commit()

    def setup_login_ui(self):
        #desenha a tela de login (labels, inputs e botoes)
        self.login_frame = tk.Frame(self.root, bg=BG_COLOR)
        self.login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        tk.Label(self.login_frame, text="Login", font=("Segoe UI", 20, "bold"), bg=BG_COLOR, fg=TEXT_COLOR).pack(pady=15)

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
        #destroi login e desenha a interface do chat em si
        self.login_frame.destroy()
        self.init_chat_db()
        
        self.chat_frame = tk.Frame(self.root, bg=BG_COLOR)
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = tk.Frame(self.chat_frame, bg=SEC_BG, width=250)
        left_frame.pack(side=tk.LEFT, fill=tk.Y)
        left_frame.pack_propagate(False)

        top_left_frame = tk.Frame(left_frame, bg=SEC_BG)
        top_left_frame.pack(fill=tk.X, pady=10, padx=10)
        
        tk.Label(top_left_frame, text="Contatos", font=("Segoe UI", 12, "bold"), bg=SEC_BG, fg=TEXT_COLOR).pack(side=tk.LEFT)

        self.listbox_contacts = tk.Listbox(left_frame, bg=SEC_BG, fg=TEXT_COLOR, selectbackground=ACCENT_COLOR, selectforeground=BG_COLOR, relief=tk.FLAT, highlightthickness=0, font=("Segoe UI", 11))
        self.listbox_contacts.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.listbox_contacts.bind('<<ListboxSelect>>', self.select_contact)

        self.right_frame = tk.Frame(self.chat_frame, bg=BG_COLOR)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        header_frame = tk.Frame(self.right_frame, bg=SEC_BG)
        header_frame.pack(side=tk.TOP, fill=tk.X)
        
        self.lbl_chat_with = tk.Label(header_frame, text="Selecione um contato", font=("Segoe UI", 14, "bold"), bg=SEC_BG, fg=TEXT_COLOR, pady=10)
        self.lbl_chat_with.pack(side=tk.LEFT, padx=15)

        self.lbl_typing = tk.Label(header_frame, text="", fg=ACCENT_COLOR, bg=SEC_BG, font=("Segoe UI", 10, "italic"))
        self.lbl_typing.pack(side=tk.RIGHT, padx=15)

        bottom_frame = tk.Frame(self.right_frame, bg=BG_COLOR, pady=10, padx=15)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.entry_msg = tk.Entry(bottom_frame, bg=SEC_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief=tk.FLAT, font=("Segoe UI", 12))
        self.entry_msg.pack(fill=tk.BOTH, side=tk.LEFT, expand=True, ipady=8, padx=(0, 10))
        self.entry_msg.bind("<KeyRelease>", self.on_typing)
        self.entry_msg.bind("<Return>", lambda e: self.send_msg())

        tk.Button(bottom_frame, text="Enviar", command=self.send_msg, bg=ACCENT_COLOR, fg=BG_COLOR, font=("Segoe UI", 11, "bold"), relief=tk.FLAT, width=10).pack(side=tk.RIGHT, ipady=4)

        #caixa de texto grandona p msgs (desativada p ngm editar na mao)
        self.text_msgs = tk.Text(self.right_frame, state=tk.DISABLED, bg=BG_COLOR, fg=TEXT_COLOR, relief=tk.FLAT, font=("Segoe UI", 11), padx=15, pady=15, height=1)
        self.text_msgs.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.refresh_contact_list()

    def refresh_contact_list(self):
        #atualiza a listbox de contatos com a bolinha verde pra quem ta on
        if not hasattr(self, 'listbox_contacts'): return
        self.listbox_contacts.delete(0, tk.END)
        for u in self.all_users:
            if u != self.username:
                status = "🟢" if u in self.online_users else "⚪"
                self.listbox_contacts.insert(tk.END, f"{status} {u}")

    def register(self):
        u = self.entry_user.get()
        p = self.entry_pass.get()
        
        #gera as chaves Ed25519 e a local_key (aes) pra proteger o sqlite do pc
        priv_bytes, pub_bytes = self.sec.generate_signature_keypair()
        local_aes = os.urandom(64) 
        
        self.save_local_keys(u, priv_bytes.hex(), pub_bytes.hex(), local_aes.hex())
        self.send_data({"type": "register", "user": u, "pass": p, "pub_key": pub_bytes.hex()})

    def login(self):
        self.username = self.entry_user.get()
        keys = self.get_local_keys(self.username)
        
        if keys:
            #login normal: puxa minha aes local e peço desafio pro server
            self.local_aes_keys = bytes.fromhex(keys[2])
            self.send_data({"type": "login_request", "user": self.username})
        else:
            #defesa: login novo pc! gero chaves novas do zero e mando p server atualizar la.
            p = self.entry_pass.get()
            priv_bytes, pub_bytes = self.sec.generate_signature_keypair()
            local_aes = os.urandom(64)
            
            self.save_local_keys(self.username, priv_bytes.hex(), pub_bytes.hex(), local_aes.hex())
            self.local_aes_keys = local_aes
            
            self.send_data({"type": "login_new_device", "user": self.username, "pass": p, "pub_key": pub_bytes.hex()})

    def receive_loop(self):
        #thread infinita escutando as fofocas do servidor
        while True:
            try:
                data = self.sock.recv(16384)
                if not data: break
                for msg_str in data.decode('utf-8').split('\n'):
                    if not msg_str.strip(): continue
                    payload = json.loads(msg_str)
                    
                    #se for cifrado, tira as camadas antes de ler
                    if "ciphertext" in payload:
                        pt = self.sec.verify_mac_and_decrypt(self.session_key1, self.session_key2, bytes.fromhex(payload["iv"]), bytes.fromhex(payload["ciphertext"]), bytes.fromhex(payload["mac"]))
                        if not pt: continue
                        res = json.loads(pt)
                    else: 
                        res = payload

                    if res["type"] == "session_expired":
                        #defesa: server gritou q estourou 100 msgs ou 60min. a gente renova o DHE na camuflagem (transparente pro user)
                        self.do_handshake()

                    elif res["type"] == "register_ack":
                        m = "Registrado com sucesso." if res["success"] else "Falha no registro (Usuário já existe)."
                        self.root.after(0, lambda m=m: messagebox.showinfo("Aviso", m))
                        
                    elif res["type"] == "login_challenge":
                        #responde o desafio do server assinando o nonce com a priv key
                        keys = self.get_local_keys(self.username)
                        if keys:
                            sig = self.sec.sign_nonce(bytes.fromhex(keys[0]), bytes.fromhex(res["nonce"]))
                            self.send_data({"type": "login_verify", "user": self.username, "signature": sig.hex()})
                            
                    elif res["type"] == "login_ack":
                        if res["success"]: self.root.after(0, self.setup_chat_ui)
                        else: self.root.after(0, lambda: messagebox.showerror("Erro", "Login falhou."))
                        
                    elif res["type"] == "status_update":
                        self.all_users = res["all"]
                        self.online_users = res["online"]
                        self.root.after(0, self.refresh_contact_list)
                        
                    elif res["type"] == "pub_key_res": 
                        #recebi pub key do amiguinho, ja chamo a e2ee pra negociar o chat
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
                        if self.current_chat == res["sender"]:
                            status = "Digitando..." if res["status"] else ""
                            self.root.after(0, lambda s=status: self.lbl_typing.config(text=s))
            except Exception as e: 
                break

    def select_contact(self, event):
        #clicou num mano da listbox
        selection = self.listbox_contacts.curselection()
        if selection:
            contact_str = self.listbox_contacts.get(selection[0])
            self.current_chat = contact_str.split(" ", 1)[1].strip() #arranca o emoji da bolinha
            self.lbl_chat_with.config(text=self.current_chat)
            self.load_history()
            
            #se nunca falei c ele, peço a pub key pro server
            if self.current_chat not in self.peer_sessions: 
                self.send_data({"type": "get_pub_key", "target": self.current_chat})

    def init_e2ee(self, target):
        #defesa: Diffie-Hellman Efêmero agora ENTRE OS CLIENTES (o server so roteia)
        priv, pub = self.sec.generate_dh_keypair()
        salt = os.urandom(16)
        self.peer_sessions[target] = {"dh_priv": priv, "salt": salt, "auth": False}
        self.send_data({"type": "e2ee_handshake_init", "sender": self.username, "recipient": target, "pub_key": pub.hex(), "salt": salt.hex()})

    def handle_e2ee_init(self, res):
        #amigo iniciou handshake, eu respondo e calculo hkdf
        target = res["sender"]
        priv, pub = self.sec.generate_dh_keypair()
        shared = self.sec.compute_shared_secret(priv, bytes.fromhex(res["pub_key"]))
        k1, k2 = self.sec.derive_keys_hkdf(shared, bytes.fromhex(res["salt"]))
        self.peer_sessions[target] = {"k1": k1, "k2": k2, "auth": False}
        self.send_data({"type": "e2ee_handshake_res", "sender": self.username, "recipient": target, "pub_key": pub.hex()})
        
        #ja mando meu nonce pra gente se autenticar
        nonce = secrets.token_hex(16)
        self.peer_sessions[target]["nonce"] = nonce
        self.send_data({"type": "e2ee_auth_req", "sender": self.username, "recipient": target, "nonce": nonce})

    def handle_e2ee_res(self, res):
        #amigo me devolveu a pub key dele, termino meu calculo hkdf
        target = res["sender"]
        if target in self.peer_sessions and "dh_priv" in self.peer_sessions[target]:
            s = self.peer_sessions[target]
            shared = self.sec.compute_shared_secret(s["dh_priv"], bytes.fromhex(res["pub_key"]))
            s["k1"], s["k2"] = self.sec.derive_keys_hkdf(shared, s["salt"])
            
            #mando o nonce pra ele tbm
            nonce = secrets.token_hex(16)
            s["nonce"] = nonce
            self.send_data({"type": "e2ee_auth_req", "sender": self.username, "recipient": target, "nonce": nonce})

    def handle_peer_auth_req(self, res):
        #defesa: autenticação MÚTUA. amg mandou nonce, eu assino p provar q sou eu msm
        target = res["sender"]
        keys = self.get_local_keys(self.username)
        if keys:
            sig = self.sec.sign_nonce(bytes.fromhex(keys[0]), bytes.fromhex(res["nonce"]))
            self.send_data({"type": "e2ee_auth_res", "sender": self.username, "recipient": target, "signature": sig.hex()})

    def encrypt_local_db(self, plaintext):
        #corta 64 bytes em k1(AES) e k2(HMAC) pra proteger o sqlite do nosso app
        k1_loc = self.local_aes_keys[:32]
        k2_loc = self.local_aes_keys[32:]
        iv, ct, mac = self.sec.encrypt_and_mac(k1_loc, k2_loc, plaintext)
        return json.dumps({"iv": iv.hex(), "ct": ct.hex(), "mac": mac.hex()}) #json salva facil como string
        
    def decrypt_local_db(self, ciphertext_json):
        #desfaz a cripto local na hora de puxar do bd pra tela
        k1_loc = self.local_aes_keys[:32]
        k2_loc = self.local_aes_keys[32:]
        try:
            data = json.loads(ciphertext_json)
            pt = self.sec.verify_mac_and_decrypt(k1_loc, k2_loc, bytes.fromhex(data["iv"]), bytes.fromhex(data["ct"]), bytes.fromhex(data["mac"]))
            return pt if pt else "[Mensagem corrompida]"
        except:
            return "[Erro: Formato inválido]"

    def send_msg(self):
        if not self.current_chat: return
        txt = self.entry_msg.get()
        
        if txt:
            #se ja ta negociado a e2ee c o mano
            if self.current_chat in self.peer_sessions and "k1" in self.peer_sessions[self.current_chat]:
                s = self.peer_sessions[self.current_chat]
                ts = datetime.now().strftime("%H:%M")
                
                #defesa da cebola criptografica: cifro primeiro E2EE
                iv, ct, mac = self.sec.encrypt_and_mac(s["k1"], s["k2"], txt)
                msg = {"type": "msg", "sender": self.username, "recipient": self.current_chat, "timestamp": ts, "iv": iv.hex(), "ct": ct.hex(), "mac": mac.hex()}
                self.send_data(msg) #dps dentro do send_data cifra dnv com as keys do server
                
                #defesa: cifra com a nossa chave mestre antes do insert no bd local
                enc_txt = self.encrypt_local_db(txt)
                self.c.execute("INSERT INTO local_history (contact, sender, timestamp, text) VALUES (?, ?, ?, ?)", (self.current_chat, self.username, ts, enc_txt))
                self.conn.commit()
                
                self.display_msg(self.username, txt, ts)
                self.entry_msg.delete(0, tk.END)
                self.send_data({"type": "typing", "sender": self.username, "recipient": self.current_chat, "status": False})
            else:
                #trava de seguranca caso os 2 nunca tenham ficado on ao msm tempo p trocar as chaves
                messagebox.showwarning("Segurança E2EE", "A mensagem não pôde ser entregue.\n\nPor questão de segurança, vocês precisam estar online ao mesmo tempo pelo menos uma vez para gerar a chave de segurança ponta-a-ponta.")

    def handle_incoming_msg(self, res):
        sender = res["sender"]
        #se a chave e2ee dele existe cmg
        if sender in self.peer_sessions and "k1" in self.peer_sessions[sender]:
            s = self.peer_sessions[sender]
            #descriptografa E2EE
            txt = self.sec.verify_mac_and_decrypt(s["k1"], s["k2"], bytes.fromhex(res["iv"]), bytes.fromhex(res["ct"]), bytes.fromhex(res["mac"]))
            
            if txt:
                #agora q li em texto plano, cifro c/ a chave do pc e guardo no BD
                enc_txt = self.encrypt_local_db(txt)
                self.c.execute("INSERT INTO local_history (contact, sender, timestamp, text) VALUES (?, ?, ?, ?)", (sender, sender, res["timestamp"], enc_txt))
                self.conn.commit()
                
                #so joga na tela se for no chat aberto no momento
                if self.current_chat == sender: 
                    self.root.after(0, self.display_msg, sender, txt, res["timestamp"])

    def display_msg(self, sender, text, ts):
        #printa na caixona de msgs (habilita edicao, bota string e desabilita dnv)
        self.text_msgs.config(state=tk.NORMAL)
        prefix = "Você" if sender == self.username else sender
        self.text_msgs.insert(tk.END, f"[{ts}] {prefix}: {text}\n")
        self.text_msgs.config(state=tk.DISABLED)
        self.text_msgs.see(tk.END) #joga barrinha p final

    def load_history(self):
        self.text_msgs.config(state=tk.NORMAL)
        self.text_msgs.delete(1.0, tk.END)
        self.c.execute("SELECT sender, timestamp, text FROM local_history WHERE contact=? ORDER BY rowid ASC", (self.current_chat,))
        for row in self.c.fetchall(): 
            prefix = "Você" if row[0] == self.username else row[0]
            
            #defesa: puxa criptografado do BD e desfaz o embaralhamento pra ler liso na tela
            dec_txt = self.decrypt_local_db(row[2])
            
            self.text_msgs.insert(tk.END, f"[{row[1]}] {prefix}: {dec_txt}\n")
            
        self.text_msgs.config(state=tk.DISABLED)
        self.text_msgs.see(tk.END)

    def on_typing(self, event):
        #chama qdo clica tecla no input
        if self.current_chat and event.keysym != 'Return':
            self.send_data({"type": "typing", "sender": self.username, "recipient": self.current_chat, "status": True})
            if self.typing_timer: self.root.after_cancel(self.typing_timer)
            self.typing_timer = self.root.after(2000, self.stop_typing) #se passar 2 segs, para

    def stop_typing(self):
        #manda falso p sumir a label do amigo
        if self.current_chat:
            self.send_data({"type": "typing", "sender": self.username, "recipient": self.current_chat, "status": False})

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop() #mantem a UI ligada