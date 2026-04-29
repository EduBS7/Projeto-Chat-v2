import socket #pra escutar a rede
import threading #pra cada cliente rodar numa linha paralela sem travar o server
import sqlite3 #banco de dados leve pra guardar logins e msgs presas
import json #pra entender os pacotinhos
import secrets #pra gerar o desafio do login (nonce) bem seguro
import time #IMPORTANTE: pra cronometrar os 60 minutos de vida da sessao
from security import SecurityEngine #nosso motor criptografico

HOST = '127.0.0.1'
PORT = 5000

#dict p guardar {usuario: socket} de quem ta online agorinha
clients = {} 

#defesa: guarda as chaves da sessao do Diffie-Hellman e os contadores de expiração (100 msgs ou 1h)
client_sessions = {} # Formato: {socket: {'k1': AES, 'k2': HMAC, 'count': 0, 'start': timestamp}}

db_lock = threading.Lock() #trava p nao dar pau no SQLite se 2 threads tentarem salvar ao msm tempo
sec = SecurityEngine()

#guarda os desafios de login q o server mandou ate o cliente responder
pending_challenges = {}

def init_db():
    #cria o BD do server
    with sqlite3.connect("server_db.sqlite") as conn:
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password_hash TEXT, public_key TEXT)")
        #defesa: essa tabela so guarda lixo ininteligivel (msg cifrada e2ee) ate o cara logar
        c.execute("CREATE TABLE IF NOT EXISTS offline_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, recipient TEXT, timestamp TEXT, payload TEXT)")
        conn.commit()

def secure_send(sock, data_dict):
    #defesa: TD que o server envia sai cifrado usando as chaves AES e HMAC exclusivas daquele socket
    sess = client_sessions.get(sock)
    if sess:
        pt = json.dumps(data_dict)
        iv, ct, mac = sec.encrypt_and_mac(sess["k1"], sess["k2"], pt)
        payload = {"iv": iv.hex(), "ciphertext": ct.hex(), "mac": mac.hex()}
        try: sock.send((json.dumps(payload) + '\n').encode('utf-8'))
        except: pass
    else:
        #se a sessao nao foi criada ainda (tipo no meio do handshake), manda em texto plano msm
        try: sock.send((json.dumps(data_dict) + '\n').encode('utf-8'))
        except: pass

def broadcast_status():
    #fofoca pra geral quem ta online e quem ta off
    online_users = list(clients.keys())
    with sqlite3.connect("server_db.sqlite") as conn:
        c = conn.cursor()
        c.execute("SELECT username FROM users")
        all_users = [row[0] for row in c.fetchall()]
    msg_dict = {"type": "status_update", "online": online_users, "all": all_users}
    for user, sock in clients.items():
        secure_send(sock, msg_dict)

def handle_client(conn_socket, addr):
    #essa thread cuida de um cliente so do inicio ao fim
    current_user = None
    try:
        while True:
            data = conn_socket.recv(16384)
            if not data: break
            msgs = data.decode('utf-8').split('\n')
            for msg_str in msgs:
                if not msg_str.strip(): continue
                payload = json.loads(msg_str)
                
                # 1. TRATAMENTO DA CRIPTOGRAFIA DE SESSÃO
                # se o pacote veio blindado, a gente tenta abrir
                if "ciphertext" in payload:
                    sess = client_sessions.get(conn_socket)
                    if not sess: continue
                    
                    # DEFESA: VERIFICA EXPIRAÇÃO (60 MINUTOS OU 100 MENSAGENS)
                    # "qdo a msg bate aqui, o server checa a idade da chave. se passou de 1h ou 100 msgs, ele bloqueia e manda o cliente renovar o DHE pra manter o sigilo perfeito adiante."
                    if time.time() - sess["start"] > 3600 or sess["count"] >= 100:
                        try: conn_socket.send((json.dumps({"type": "session_expired"}) + '\n').encode('utf-8'))
                        except: pass
                        continue #pula o resto, a sessao venceu e essa msg ta morta

                    #abre o pacote se o HMAC validar
                    plaintext = sec.verify_mac_and_decrypt(sess["k1"], sess["k2"], bytes.fromhex(payload["iv"]), bytes.fromhex(payload["ciphertext"]), bytes.fromhex(payload["mac"]))
                    if not plaintext: continue #MAC falhou, joga fora
                    
                    request = json.loads(plaintext)
                    sess["count"] += 1 #mais uma msg pra conta do limite de 100
                else: 
                    request = payload

                # 2. ROTAS E NEGOCIAÇÕES
                if request["type"] == "dh_exchange":
                    #cliente mandou handshake. o server gera o lado dele, acha o segredo e roda o HKDF
                    dh_priv, dh_pub = sec.generate_dh_keypair()
                    shared = sec.compute_shared_secret(dh_priv, bytes.fromhex(request["pub_key"]))
                    k1, k2 = sec.derive_keys_hkdf(shared, bytes.fromhex(request["salt"]))
                    
                    #salva as chaves novas e zera o relogio/contador de expiracao
                    client_sessions[conn_socket] = {"k1": k1, "k2": k2, "count": 0, "start": time.time()}
                    conn_socket.send((json.dumps({"type": "dh_exchange_ack", "pub_key": dh_pub.hex()}) + '\n').encode('utf-8'))

                elif request["type"] == "register":
                    try:
                        #defesa: hasheia com Argon2. dps dessa linha a senha some da memoria e o BD nunca ve ela crua
                        pwd_hash = sec.hash_password(request["pass"])
                        with db_lock:
                            with sqlite3.connect("server_db.sqlite") as conn_db:
                                c = conn_db.cursor()
                                c.execute("INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)", (request["user"], pwd_hash, request["pub_key"]))
                                conn_db.commit()
                                secure_send(conn_socket, {"type": "register_ack", "success": True})
                    except: secure_send(conn_socket, {"type": "register_ack", "success": False})

                elif request["type"] == "login_request":
                    #defesa: comeco do desafio! o server gera um nonce(numero aleatorio) e manda pro cliente assinar
                    with sqlite3.connect("server_db.sqlite") as conn_db:
                        c = conn_db.cursor()
                        c.execute("SELECT public_key FROM users WHERE username=?", (request["user"],))
                        row = c.fetchone()
                        if row:
                            nonce = secrets.token_hex(32)
                            pending_challenges[conn_socket] = {"user": request["user"], "nonce": nonce, "pub_key": row[0]}
                            secure_send(conn_socket, {"type": "login_challenge", "nonce": nonce})
                        else: secure_send(conn_socket, {"type": "login_ack", "success": False})

                elif request["type"] == "login_verify":
                    #defesa: o cliente devolveu assinado. a gente bate a assinatura c/ a pub key q ta no bd. se der true, é ele msm
                    ch = pending_challenges.get(conn_socket)
                    if ch and sec.verify_signature(bytes.fromhex(ch["pub_key"]), bytes.fromhex(request["signature"]), bytes.fromhex(ch["nonce"])):
                        current_user = request["user"]
                        clients[current_user] = conn_socket
                        secure_send(conn_socket, {"type": "login_ack", "success": True})
                        broadcast_status()
                        
                        # DEFESA: ENTREGA DE MENSAGENS OFFLINE 
                        # "assim q o login da certo, o servidor vomita tds as msgs q ficaram presas na caixa postal dele."
                        with sqlite3.connect("server_db.sqlite") as conn_db:
                            c = conn_db.cursor()
                            c.execute("SELECT id, payload FROM offline_messages WHERE recipient=?", (current_user,))
                            for row in c.fetchall():
                                # o row[1] ja é o JSON cifrado ponta a ponta, é so cuspir pro cliente
                                secure_send(conn_socket, json.loads(row[1]))
                                time.sleep(0.05) #delayzim p tcp nao aglutinar tudo num pacote so
                            
                            #apagou as q entregou p nao floodar dps
                            c.execute("DELETE FROM offline_messages WHERE recipient=?", (current_user,))
                            conn_db.commit()
                    else: secure_send(conn_socket, {"type": "login_ack", "success": False})

                elif request["type"] == "login_new_device":
                    # DEFESA: LOGIN DE NOVO DISPOSITIVO
                    # "caso de pc formatado. o cliente manda senha plana, eu verifico no Argon2. se bater, aceito a pub_key nova."
                    u = request["user"]
                    p_plain = request["pass"]
                    new_pub = request["pub_key"]
                    
                    with db_lock:
                        with sqlite3.connect("server_db.sqlite") as conn_db:
                            c = conn_db.cursor()
                            c.execute("SELECT password_hash FROM users WHERE username=?", (u,))
                            row = c.fetchone()
                            
                            #verifica com argon2
                            if row and sec.verify_password(row[0], p_plain):
                                #atualiza chave publica
                                c.execute("UPDATE users SET public_key=? WHERE username=?", (new_pub, u))
                                # DEFESA CRITICA: apaga msgs offline! a priv key velha foi pro espaço, entao oq tem no bd ngm nunca mais vai ler, é lixo
                                c.execute("DELETE FROM offline_messages WHERE recipient=?", (u,))
                                conn_db.commit()
                                
                                current_user = u
                                clients[u] = conn_socket
                                secure_send(conn_socket, {"type": "login_ack", "success": True})
                                broadcast_status()
                            else:
                                secure_send(conn_socket, {"type": "login_ack", "success": False})

                elif request["type"] == "get_pub_key":
                    #distribuicao de chaves pub (um cliente pedindo a do amiguinho p iniciar e2ee)
                    with sqlite3.connect("server_db.sqlite") as conn_db:
                        c = conn_db.cursor()
                        c.execute("SELECT public_key FROM users WHERE username=?", (request["target"],))
                        row = c.fetchone()
                        if row: secure_send(conn_socket, {"type": "pub_key_res", "target": request["target"], "pub_key": row[0]})

                elif request["type"] in ["e2ee_handshake_init", "e2ee_handshake_res", "e2ee_auth_req", "e2ee_auth_res", "msg", "typing"]:
                    # DEFESA: O CARTEIRO CEGO
                    # "se cair aqui, o server atua so como roteador. o pacote e2ee ta trancado e o server nao tem a chave, ele so pega e repassa pro destino."
                    target = request.get("recipient") or request.get("target")
                    if target in clients: secure_send(clients[target], request)
                    elif request["type"] == "msg":
                        # se o mano ta off, guarda o pacote as cegas no sqlite
                        with db_lock:
                            with sqlite3.connect("server_db.sqlite") as conn_db:
                                c = conn_db.cursor()
                                c.execute("INSERT INTO offline_messages (sender, recipient, timestamp, payload) VALUES (?, ?, ?, ?)", (request["sender"], target, request["timestamp"], json.dumps(request)))
                                conn_db.commit()
    except: pass
    finally:
        #se deu ruim na conexao ou o kra fechou o app, tira da lista de onlines
        if current_user in clients: del clients[current_user]
        broadcast_status()
        conn_socket.close()

def start_server():
    #liga o banco e sobe o socket tcp
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    
    #loop infinito caçando cliente
    while True:
        conn, addr = server.accept()
        #joga o cliente numa thread paralela e volta a caçar o prox
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()