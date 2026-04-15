import socket #pra conexao de rede via TCP
import threading #pra rodar processos em paralelo (ouvir servidor sem travar tela)
import sqlite3 #banco de dados local pra salvar historico
import json #pra empacotar/desempacotar msgs pro servidor
from datetime import datetime #pra pegar a hora exata da msg
import tkinter as tk #biblioteca da interface grafica
from tkinter import messagebox, simpledialog #caixinhas de alerta e input

#Configs do servidor
HOST = '127.0.0.1' #localhost (rodando no meu proprio pc)
PORT = 5000 #porta aberta pro servidor

#Cores do app (estilo dark mode pra deixar bonito)
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
        
        #tenta puxar a imagem do icone, se der erro passa direto
        try:
            icone_img = tk.PhotoImage(file="icone.png")
            self.root.iconphoto(False, icone_img)
        except:
            pass
            
        #conecta no servidor usando socket TCP
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))
        
        #variaveis de estado (quem eu sou, com quem to falando agora)
        self.username = None
        self.current_chat = None
        self.typing_timer = None
        self.online_users = []

        #chama configs iniciais
        self.init_db()
        self.setup_login_ui()
        
        #cria a thread q fica ouvindo o servidor o tempo todo
        threading.Thread(target=self.receive_loop, daemon=True).start()

    def init_db(self):
        #cria e conecta no SQLite pra historico e contatos
        self.conn = sqlite3.connect("client_db.sqlite", check_same_thread=False)
        self.c = self.conn.cursor()
        #tabelas
        self.c.execute("CREATE TABLE IF NOT EXISTS local_history (contact TEXT, sender TEXT, timestamp TEXT, text TEXT)")
        self.c.execute("CREATE TABLE IF NOT EXISTS contacts (username TEXT UNIQUE)")
        self.conn.commit()

    def setup_login_ui(self):
        #Cria e posiciona tela de Login no meio da tela
        self.login_frame = tk.Frame(self.root, bg=BG_COLOR)
        self.login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        tk.Label(self.login_frame, text="Chat Login", font=("Segoe UI", 20, "bold"), bg=BG_COLOR, fg=TEXT_COLOR).pack(pady=15)

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
        self.chat_frame = tk.Frame(self.root, bg=BG_COLOR)
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

        #Barra lateral esquerda (area dos contatos)
        left_frame = tk.Frame(self.chat_frame, bg=SEC_BG, width=250)
        left_frame.pack(side=tk.LEFT, fill=tk.Y)
        left_frame.pack_propagate(False)

        top_left_frame = tk.Frame(left_frame, bg=SEC_BG)
        top_left_frame.pack(fill=tk.X, pady=10, padx=10)
        
        tk.Label(top_left_frame, text="Meus Contatos", font=("Segoe UI", 12, "bold"), bg=SEC_BG, fg=TEXT_COLOR).pack(side=tk.LEFT)
        tk.Button(top_left_frame, text="+", command=self.add_contact, bg=BTN_BG, fg=BTN_FG, relief=tk.FLAT, font=("Segoe UI", 10, "bold")).pack(side=tk.RIGHT)

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
        
        self.lbl_chat_with = tk.Label(header_frame, text="Selecione um contato para conversar", font=("Segoe UI", 14, "bold"), bg=SEC_BG, fg=TEXT_COLOR, pady=10)
        self.lbl_chat_with.pack(side=tk.LEFT, padx=15)

        #Aviso de alguem digitando
        self.lbl_typing = tk.Label(header_frame, text="", fg=ACCENT_COLOR, bg=SEC_BG, font=("Segoe UI", 10, "italic"))
        self.lbl_typing.pack(side=tk.RIGHT, padx=15)

        #Barra debaixo: input e botao
        bottom_frame = tk.Frame(self.right_frame, bg=BG_COLOR, pady=10, padx=15)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        #input do texto q vou mandar
        self.entry_msg = tk.Entry(bottom_frame, bg=SEC_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief=tk.FLAT, font=("Segoe UI", 12))
        self.entry_msg.pack(fill=tk.BOTH, side=tk.LEFT, expand=True, ipady=8, padx=(0, 10))
        self.entry_msg.bind("<KeyRelease>", self.on_typing) #evento pra disparar q to digitando
        self.entry_msg.bind("<Return>", lambda e: self.send_msg()) #enter funciona q nem o botao

        tk.Button(bottom_frame, text="Enviar", command=self.send_msg, bg=ACCENT_COLOR, fg=BG_COLOR, font=("Segoe UI", 11, "bold"), relief=tk.FLAT, width=10).pack(side=tk.RIGHT, ipady=4)

        #A caixa gigante do meio q contem o historico das msg
        #state=tk.DISABLED p ngm editar as msgs na mao lá dentro
        self.text_msgs = tk.Text(self.right_frame, state=tk.DISABLED, bg=BG_COLOR, fg=TEXT_COLOR, relief=tk.FLAT, font=("Segoe UI", 11), padx=15, pady=15, height=1)
        self.text_msgs.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.refresh_contact_list()

    def add_contact(self):
        #popup pedindo nome
        new_contact = simpledialog.askstring("Novo Contato", "Digite o nome de usuário do contato:", parent=self.root)
        if new_contact:
            #trava pra n add a mim msm
            if new_contact == self.username:
                messagebox.showwarning("Aviso", "Você não pode adicionar a si mesmo.")
                return
            #salva contato no bd
            try:
                self.c.execute("INSERT INTO contacts (username) VALUES (?)", (new_contact,))
                self.conn.commit()
                self.refresh_contact_list()
            except sqlite3.IntegrityError:
                messagebox.showinfo("Info", "este usuário já está na sua lista de contatos.")

    def refresh_contact_list(self):
        #atualiza a barra lateral (ve quem ta on pra por a bolinha verde)
        if not hasattr(self, 'listbox_contacts'): return
        
        self.listbox_contacts.delete(0, tk.END)
        self.c.execute("SELECT username FROM contacts ORDER BY username ASC")
        for row in self.c.fetchall():
            contact_name = row[0]
            status = "🟢" if contact_name in self.online_users else "⚪"
            self.listbox_contacts.insert(tk.END, f"{status} {contact_name}")

    def send_data(self, data):
        #funcao helper: json.dumps vira texto, encode('utf-8') vira bytes pro socket
        self.sock.send(json.dumps(data).encode('utf-8'))

    def register(self):
        #botao de registro
        self.send_data({"type": "register", "user": self.entry_user.get(), "pass": self.entry_pass.get()})

    def login(self):
        #botao de logar
        self.username = self.entry_user.get()
        self.send_data({"type": "login", "user": self.username, "pass": self.entry_pass.get()})

    def receive_loop(self):
        #Thread roda isso infinito (esperando infos do server)
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                    
                #Tratamento se pacotes JSON chegarem colados (ex: }{ vira }\n{)
                msgs = data.decode('utf-8').replace('}{', '}\n{').split('\n')
                for msg_str in msgs:
                    if not msg_str: continue
                    res = json.loads(msg_str)

                    #IFs definindo oq q o servidor respondeu
                    if res["type"] == "register_ack":
                        #retorno do botao registrar
                        if res["success"]: messagebox.showinfo("OK", "Registrado com sucesso.")
                        else: messagebox.showerror("Erro", "Usuário já existe.")

                    elif res["type"] == "login_ack":
                        #se foi sucesso entra no app, senao da erro
                        if res["success"]: self.root.after(0, self.setup_chat_ui)
                        else: messagebox.showerror("Erro", "Credenciais incorretas.")

                    elif res["type"] == "status_update":
                        #alguem logou/saiu (atualiza bolinhas na interface)
                        self.online_users = res["online"]
                        self.root.after(0, self.refresh_contact_list)

                    elif res["type"] == "msg":
                        #msg nova chegando: salva no bd local
                        self.c.execute("INSERT INTO local_history (contact, sender, timestamp, text) VALUES (?, ?, ?, ?)",
                                       (res["sender"], res["sender"], res["timestamp"], res["text"]))
                        self.conn.commit()
                        
                        #se eu to com a tela da pessoa aberta, ja plota lá
                        if self.current_chat == res["sender"]:
                            self.root.after(0, self.display_msg, res["sender"], res["text"], res["timestamp"])

                    elif res["type"] == "typing":
                        #aparece q a pessoa ta digitando... no topo da tela
                        if self.current_chat == res["sender"]:
                            status = "Digitando..." if res["status"] else ""
                            self.root.after(0, lambda s=status: self.lbl_typing.config(text=s))
            except Exception:
                break

    def select_contact(self, event):
        #evento de clicar num contato da listbox da esq
        selection = self.listbox_contacts.curselection()
        if selection:
            contact_str = self.listbox_contacts.get(selection[0])
            self.current_chat = contact_str[2:] #corta a bolinha (🟢 ), pega só o nome
            self.lbl_chat_with.config(text=self.current_chat)
            self.load_history()

    def load_history(self):
        #puxa msg antigas do sql pro painel
        self.text_msgs.config(state=tk.NORMAL) #libera edicao
        self.text_msgs.delete(1.0, tk.END) #limpa lixo
        self.c.execute("SELECT sender, timestamp, text FROM local_history WHERE contact=? ORDER BY rowid ASC", (self.current_chat,))
        for row in self.c.fetchall():
            prefix = "Você" if row[0] == self.username else row[0] #muda pra "Você" se fui eu
            self.text_msgs.insert(tk.END, f"[{row[1]}] {prefix}: {row[2]}\n")
        self.text_msgs.config(state=tk.DISABLED) #trava edicao dnv
        self.text_msgs.see(tk.END) #joga barra rolagem pro fim

    def send_msg(self):
        #trava: exige escolher alguem antes
        if not self.current_chat:
            messagebox.showwarning("Aviso", "Por favor, adicione e selecione um contato na lista à esquerda antes de enviar.")
            return

        text = self.entry_msg.get()
        if text:
            ts = datetime.now().strftime("%H:%M") #pega so hr:min
            msg_data = {"type": "msg", "sender": self.username, "recipient": self.current_chat, "timestamp": ts, "text": text}
            self.send_data(msg_data) #joga json pro server
            
            #salva pra mim mesmo
            self.c.execute("INSERT INTO local_history (contact, sender, timestamp, text) VALUES (?, ?, ?, ?)",
                           (self.current_chat, self.username, ts, text))
            self.conn.commit()
            
            #atualiza tela e limpa box
            self.display_msg(self.username, text, ts)
            self.entry_msg.delete(0, tk.END)
            self.send_data({"type": "typing", "sender": self.username, "recipient": self.current_chat, "status": False}) #para de digitar

    def display_msg(self, sender, text, ts):
        #funcao helper pra plotar textinho no painel grande
        self.text_msgs.config(state=tk.NORMAL)
        prefix = "Você" if sender == self.username else sender
        self.text_msgs.insert(tk.END, f"[{ts}] {prefix}: {text}\n")
        self.text_msgs.config(state=tk.DISABLED)
        self.text_msgs.see(tk.END)

    def on_typing(self, event):
        #dispara status true pra digitando se n foi enter (return)
        if self.current_chat and event.keysym != 'Return':
            self.send_data({"type": "typing", "sender": self.username, "recipient": self.current_chat, "status": True})
            
            #se ta digitando para de contar
            if self.typing_timer:
                self.root.after_cancel(self.typing_timer)
            #depois de 2 segs se nada ocorrer, chama função de parar
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