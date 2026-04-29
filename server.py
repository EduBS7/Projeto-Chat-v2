import socket
import threading
import sqlite3
import json
import secrets
from security import SecurityEngine

HOST = '127.0.0.1'
PORT = 5000

clients = {}
client_sessions = {}
db_lock = threading.Lock()
sec = SecurityEngine()
pending_challenges = {}

def init_db():
    #Cria o banco do servidor
    with sqlite3.connect("server_db.sqlite") as conn:
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password_hash TEXT, public_key TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS offline_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, recipient TEXT, timestamp TEXT, payload TEXT)")
        conn.commit()

def secure_send(sock, data_dict):
    keys = client_sessions.get(sock)
    if keys:
        pt = json.dumps(data_dict)
        iv, ct, mac = sec.encrypt_and_mac(keys[0], keys[1], pt)
        payload = {"iv": iv.hex(), "ciphertext": ct.hex(), "mac": mac.hex()}
        try: sock.send((json.dumps(payload) + '\n').encode('utf-8'))
        except: pass
    else:
        try: sock.send((json.dumps(data_dict) + '\n').encode('utf-8'))
        except: pass

def broadcast_status():
    #Pega a lista de chaves do dict (quem ta com socket aberto = online)
    online_users = list(clients.keys())
    
    #Puxa todo mundo q tem conta no BD pra mostrar na lista geral
    with sqlite3.connect("server_db.sqlite") as conn:
        c = conn.cursor()
        c.execute("SELECT username FROM users")
        all_users = [row[0] for row in c.fetchall()]
    msg_dict = {"type": "status_update", "online": online_users, "all": all_users}
    for user, sock in clients.items():
        secure_send(sock, msg_dict)

def handle_client(conn_socket, addr):
    #Essa funcao roda em paralelo (thread) pra CADA cliente q conecta.
    current_user = None
    try:
        while True:
            data = conn_socket.recv(16384)
            if not data: break
            msgs = data.decode('utf-8').split('\n')
            for msg_str in msgs:
                if not msg_str.strip(): continue
                payload = json.loads(msg_str)
                if "ciphertext" in payload:
                    keys = client_sessions.get(conn_socket)
                    if not keys: continue
                    plaintext = sec.verify_mac_and_decrypt(keys[0], keys[1], bytes.fromhex(payload["iv"]), bytes.fromhex(payload["ciphertext"]), bytes.fromhex(payload["mac"]))
                    if not plaintext: continue
                    request = json.loads(plaintext)
                else: request = payload

                if request["type"] == "dh_exchange":
                    dh_priv, dh_pub = sec.generate_dh_keypair()
                    shared = sec.compute_shared_secret(dh_priv, bytes.fromhex(request["pub_key"]))
                    k1, k2 = sec.derive_keys_hkdf(shared, bytes.fromhex(request["salt"]))
                    client_sessions[conn_socket] = (k1, k2)
                    conn_socket.send((json.dumps({"type": "dh_exchange_ack", "pub_key": dh_pub.hex()}) + '\n').encode('utf-8'))

                elif request["type"] == "register":
                    try:
                        pwd_hash = sec.hash_password(request["pass"])
                        with db_lock:
                            with sqlite3.connect("server_db.sqlite") as conn_db:
                                c = conn_db.cursor()
                                c.execute("INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)", (request["user"], pwd_hash, request["pub_key"]))
                                conn_db.commit()
                                secure_send(conn_socket, {"type": "register_ack", "success": True})
                    except: secure_send(conn_socket, {"type": "register_ack", "success": False})

                elif request["type"] == "login_request":
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
                    ch = pending_challenges.get(conn_socket)
                    if ch and sec.verify_signature(bytes.fromhex(ch["pub_key"]), bytes.fromhex(request["signature"]), bytes.fromhex(ch["nonce"])):
                        current_user = request["user"]
                        clients[current_user] = conn_socket
                        secure_send(conn_socket, {"type": "login_ack", "success": True})
                        broadcast_status()
                    else: secure_send(conn_socket, {"type": "login_ack", "success": False})

                elif request["type"] == "get_pub_key":
                    with sqlite3.connect("server_db.sqlite") as conn_db:
                        c = conn_db.cursor()
                        c.execute("SELECT public_key FROM users WHERE username=?", (request["target"],))
                        row = c.fetchone()
                        if row: secure_send(conn_socket, {"type": "pub_key_res", "target": request["target"], "pub_key": row[0]})

                elif request["type"] in ["e2ee_handshake_init", "e2ee_handshake_res", "e2ee_auth_req", "e2ee_auth_res", "msg", "typing"]:
                    target = request.get("recipient") or request.get("target")
                    if target in clients: secure_send(clients[target], request)
                    elif request["type"] == "msg":
                        with db_lock:
                            with sqlite3.connect("server_db.sqlite") as conn_db:
                                c = conn_db.cursor()
                                c.execute("INSERT INTO offline_messages (sender, recipient, timestamp, payload) VALUES (?, ?, ?, ?)", (request["sender"], target, request["timestamp"], json.dumps(request)))
                                conn_db.commit()
    except: pass
    finally:
        if current_user in clients: del clients[current_user]
        broadcast_status()
        conn_socket.close()

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