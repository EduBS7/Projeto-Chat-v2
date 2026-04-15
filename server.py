import socket #pra fazer a conexao de rede (o servidor ouvindo)
import threading #MUITO IMPORTANTE: pra cada cliente q entra, o server cria uma thread nova e nao trava os outros
import sqlite3 #banco de dados pra guardar logins e msgs de quem ta offline
import json #pra entender os pacotinhos de texto q o cliente manda
import time #pra dar uns delays estrategicos e nao engasgar o envio de msgs

#Configs de rede
HOST = '127.0.0.1' #roda local
PORT = 5000 #mesma porta do cliente

#Dicionario pra guardar quem ta online no momento. Ex: {'joao': <objeto_socket_do_joao>}
clients = {} 

#Trava de segurança do Banco de Dados (Mutex)
#Defesa pro professor: "Como tem varias threads rodando, se 2 clientes tentarem salvar algo no BD na mesma hora, ele corrompe. O lock organiza a fila."
db_lock = threading.Lock() 

def init_db():
    #Cria o banco do servidor
    with sqlite3.connect("server_db.sqlite") as conn:
        c = conn.cursor()
        #Tabela pra logins (UNIQUE garante q ninguem crie conta com msm nome)
        c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)")
        #Tabela inteligente: so guarda a msg se o destinatario estiver offline. Quando ele logar, recebe e apaga daqui.
        c.execute("CREATE TABLE IF NOT EXISTS offline_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, recipient TEXT, timestamp TEXT, text TEXT)")
        conn.commit()

def broadcast_status():
    #Pega a lista de chaves do dict (quem ta com socket aberto = online)
    online_users = list(clients.keys())
    
    #Puxa todo mundo q tem conta no BD pra mostrar na lista geral
    with sqlite3.connect("server_db.sqlite") as conn:
        c = conn.cursor()
        c.execute("SELECT username FROM users")
        all_users = [row[0] for row in c.fetchall()]
        
    #Monta o JSON e avisa GERAL q o status de alguem mudou (entrou ou saiu)
    msg = json.dumps({"type": "status_update", "online": online_users, "all": all_users}).encode('utf-8')
    for user, sock in clients.items():
        try:
            sock.send(msg)
        except:
            pass #se der erro pra mandar pra um, ignora e segue a vida

def handle_client(conn_socket, addr):
    #Essa funcao roda em paralelo (thread) pra CADA cliente q conecta.
    current_user = None
    try:
        while True:
            #Fica ouvindo oq o cliente mandou (ate 4096 bytes)
            data = conn_socket.recv(4096)
            if not data:
                break #se vier vazio, o cliente desconectou
            
            #Transforma o texto q chegou de volta num dicionario Python
            request = json.loads(data.decode('utf-8'))

            #IFs que decidem oq o servidor faz baseado no tipo de pacote q chegou
            
            if request["type"] == "register":
                u = request["user"]
                p = request["pass"]
                with db_lock: #Trava o BD pra registrar sem conflito
                    with sqlite3.connect("server_db.sqlite") as conn_db:
                        c = conn_db.cursor()
                        try:
                            #Tenta criar a conta
                            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (u, p))
                            conn_db.commit()
                            conn_socket.send(json.dumps({"type": "register_ack", "success": True}).encode('utf-8'))
                        except sqlite3.IntegrityError:
                            #Se cair aqui, o UNIQUE barrou pq o nome ja existe
                            conn_socket.send(json.dumps({"type": "register_ack", "success": False}).encode('utf-8'))

            elif request["type"] == "login":
                u = request["user"]
                p = request["pass"]
                with sqlite3.connect("server_db.sqlite") as conn_db:
                    c = conn_db.cursor()
                    #Verifica se user e senha batem
                    c.execute("SELECT * FROM users WHERE username=? AND password=?", (u, p))
                    
                    if c.fetchone(): #Se achou no BD
                        current_user = u
                        clients[u] = conn_socket #Salva o socket do cara no dicionario de onlines
                        conn_socket.send(json.dumps({"type": "login_ack", "success": True}).encode('utf-8'))
                        broadcast_status() #Avisa geral q ele entrou

                        #VERIFICA MSGS OFFLINE: Se alguem mandou msg enquanto ele tava fora, descarrega agora
                        c.execute("SELECT id, sender, timestamp, text FROM offline_messages WHERE recipient=?", (u,))
                        offline_msgs = c.fetchall()
                        for msg in offline_msgs:
                            msg_data = {"type": "msg", "sender": msg[1], "recipient": u, "timestamp": msg[2], "text": msg[3]}
                            conn_socket.send(json.dumps(msg_data).encode('utf-8'))
                            time.sleep(0.05) #Defesa: delayzinho curto pra nao colar os JSONs no socket e quebrar o cliente
                        
                        #Limpou a caixa postal, deleta as msgs do BD pra nao mandar repetido depois
                        c.execute("DELETE FROM offline_messages WHERE recipient=?", (u,))
                        conn_db.commit()
                    else:
                        #Senha errada ou user nao existe
                        conn_socket.send(json.dumps({"type": "login_ack", "success": False}).encode('utf-8'))

            elif request["type"] == "msg":
                recipient = request["recipient"]
                #Se o cara ta no dicionario, ta online -> manda a msg direto pra ele
                if recipient in clients:
                    try:
                        clients[recipient].send(json.dumps(request).encode('utf-8'))
                    except:
                        pass
                else:
                    #Se nao ta no dict, ta offline -> guarda no BD pro futuro
                    with db_lock:
                        with sqlite3.connect("server_db.sqlite") as conn_db:
                            c = conn_db.cursor()
                            c.execute("INSERT INTO offline_messages (sender, recipient, timestamp, text) VALUES (?, ?, ?, ?)",
                                      (request["sender"], recipient, request["timestamp"], request["text"]))
                            conn_db.commit()

            elif request["type"] == "typing":
                recipient = request["recipient"]
                #Se o cara ta online, repassa o aviso q o amigo ta digitando. 
                #Obs: Se ele ta offline, a gente ignora. Nao faz sentido guardar "digitando..." no BD.
                if recipient in clients:
                    try:
                        clients[recipient].send(json.dumps(request).encode('utf-8'))
                    except:
                        pass
    except Exception:
        #Se der qualquer erro bizarro de rede (cabo solto, fechou no X da janela), ignora e cai no finally
        pass
    finally:
        #Isso aqui roda sempre q o cliente desconectar (por erro ou de proposito)
        if current_user in clients:
            del clients[current_user] #Tira o cara da lista de onlines
            broadcast_status() #Avisa o resto q a bolinha dele ficou cinza (offline)
        conn_socket.close() #Mata a conexao com segurança

def start_server():
    #Configura banco e sobe o servidor
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen() #Fica escutando quem bater na porta
    
    #Loop infinito do servidor
    while True:
        conn, addr = server.accept() #Quando alguem chega, ele aceita
        #Joga esse cliente novo pra uma Thread separada cuidar dele, e volta a ficar escutando a porta
        threading.Thread(target=handle_client, args=(conn, addr)).start()

#Se eu der play neste arquivo, ele inicia o servidor
if __name__ == "__main__":
    start_server()