import socket
import threading
import sqlite3
import json
import time

HOST = '127.0.0.1'
PORT = 5000

clients = {}
db_lock = threading.Lock()

def init_db():
    with sqlite3.connect("server_db.sqlite") as conn:
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS offline_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, recipient TEXT, timestamp TEXT, text TEXT)")
        conn.commit()

def broadcast_status():
    online_users = list(clients.keys())
    with sqlite3.connect("server_db.sqlite") as conn:
        c = conn.cursor()
        c.execute("SELECT username FROM users")
        all_users = [row[0] for row in c.fetchall()]
    msg = json.dumps({"type": "status_update", "online": online_users, "all": all_users}).encode('utf-8')
    for user, sock in clients.items():
        try:
            sock.send(msg)
        except:
            pass

def handle_client(conn_socket, addr):
    current_user = None
    try:
        while True:
            data = conn_socket.recv(4096)
            if not data:
                break
            request = json.loads(data.decode('utf-8'))

            if request["type"] == "register":
                u = request["user"]
                p = request["pass"]
                with db_lock:
                    with sqlite3.connect("server_db.sqlite") as conn_db:
                        c = conn_db.cursor()
                        try:
                            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (u, p))
                            conn_db.commit()
                            conn_socket.send(json.dumps({"type": "register_ack", "success": True}).encode('utf-8'))
                        except sqlite3.IntegrityError:
                            conn_socket.send(json.dumps({"type": "register_ack", "success": False}).encode('utf-8'))

            elif request["type"] == "login":
                u = request["user"]
                p = request["pass"]
                with sqlite3.connect("server_db.sqlite") as conn_db:
                    c = conn_db.cursor()
                    c.execute("SELECT * FROM users WHERE username=? AND password=?", (u, p))
                    if c.fetchone():
                        current_user = u
                        clients[u] = conn_socket
                        conn_socket.send(json.dumps({"type": "login_ack", "success": True}).encode('utf-8'))
                        broadcast_status()

                        c.execute("SELECT id, sender, timestamp, text FROM offline_messages WHERE recipient=?", (u,))
                        offline_msgs = c.fetchall()
                        for msg in offline_msgs:
                            msg_data = {"type": "msg", "sender": msg[1], "recipient": u, "timestamp": msg[2], "text": msg[3]}
                            conn_socket.send(json.dumps(msg_data).encode('utf-8'))
                            time.sleep(0.05)
                        c.execute("DELETE FROM offline_messages WHERE recipient=?", (u,))
                        conn_db.commit()
                    else:
                        conn_socket.send(json.dumps({"type": "login_ack", "success": False}).encode('utf-8'))

            elif request["type"] == "msg":
                recipient = request["recipient"]
                if recipient in clients:
                    try:
                        clients[recipient].send(json.dumps(request).encode('utf-8'))
                    except:
                        pass
                else:
                    with db_lock:
                        with sqlite3.connect("server_db.sqlite") as conn_db:
                            c = conn_db.cursor()
                            c.execute("INSERT INTO offline_messages (sender, recipient, timestamp, text) VALUES (?, ?, ?, ?)",
                                      (request["sender"], recipient, request["timestamp"], request["text"]))
                            conn_db.commit()

            elif request["type"] == "typing":
                recipient = request["recipient"]
                if recipient in clients:
                    try:
                        clients[recipient].send(json.dumps(request).encode('utf-8'))
                    except:
                        pass
    except Exception:
        pass
    finally:
        if current_user in clients:
            del clients[current_user]
            broadcast_status()
        conn_socket.close()

def start_server():
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()