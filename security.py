import os
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.hmac import HMAC

class SecurityEngine:
    def __init__(self):
        #defesa: usei argon2 pq ganhou o camp. de hash e aguenta ataque de GPU. ele msm ja faz o salt junto
        self.ph = PasswordHasher()

    #hashing senhas (argon2)
    def hash_password(self, password):
        #gera hash (salt entra no automatico)
        return self.ph.hash(password)

    def verify_password(self, hashed_password, plain_password):
        #ve se a senha digitada bate com o hash salvo
        try:
            return self.ph.verify(hashed_password, plain_password)
        except:
            return False

    #assinatura e autenticacao (ECC - Ed25519)
    #defesa: escolhi ECC ao inves de RSA pq a chave é bem menor (32 bytes), entao a rede fica mais rapida
    
    def generate_signature_keypair(self):
        #gera as chaves do cliente
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        #transforma em bytes p mandar facil no socket
        priv_bytes = private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        pub_bytes = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return priv_bytes, pub_bytes

    def sign_nonce(self, private_key_bytes, nonce_bytes):
        #defesa: so assina o desafio quem tem a chave privada (prova q é a pessoa msm)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        return private_key.sign(nonce_bytes)

    def verify_signature(self, public_key_bytes, signature, message):
        #verifica se a assinatura é valida usando a pub key
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        try:
            public_key.verify(signature, message)
            return True
        except:
            return False

    #DHE + HKDF (pra derivar as chaves)
    #defesa: o DHE apaga as chaves dps de um tempo (forward secrecy). se o bd vazar no futuro, ngm le as msgs antigas
    
    def generate_dh_keypair(self):
        #gera chaves pro diffie-hellman efemero
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def compute_shared_secret(self, my_private_key, other_public_bytes):
        #calcula o segredo q so os dois vao saber
        other_public_key = x25519.X25519PublicKey.from_public_bytes(other_public_bytes)
        return my_private_key.exchange(other_public_key)

    def derive_keys_hkdf(self, shared_secret, salt):
        #defesa: HKDF "bate no liquidificador" o segredo com o salt p extrair exatos 64 bytes perfeitos
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64, #total de 64 bytes
            salt=salt,
            info=b'chat_session_keys'
        )
        derived_material = hkdf.derive(shared_secret)
        
        #corta no meio: 32 bytes p cada
        chave1_aes = derived_material[:32]  #aes pra confidencialidade
        chave2_hmac = derived_material[32:] #hmac pra integridade
        return chave1_aes, chave2_hmac

    #cripto da msg (AES + HMAC)
    #defesa principal: uso Encrypt-then-MAC. cifro primeiro e dps tiro o HMAC. isso evita ataque de padding oracle pq bloqueia pacote zoado antes msm de tentar descriptografar

    def encrypt_and_mac(self, chave1_aes, chave2_hmac, plaintext: str):
        #iv aleatorio pra msgs iguais nao ficarem com o msm codigo
        iv = os.urandom(16) 
        
        #ajusta o tamanho (padding) pq o AES so engole blocos de 16
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        
        #cifra tudo com AES-256-CBC
        cipher = Cipher(algorithms.AES(chave1_aes), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        #gera o mac juntando o IV com a msg cifrada
        h = HMAC(chave2_hmac, hashes.SHA256())
        h.update(iv + ciphertext)
        mac = h.finalize()
        
        return iv, ciphertext, mac

    def verify_mac_and_decrypt(self, chave1_aes, chave2_hmac, iv, ciphertext, mac):
        #1. checa o HMAC primeiro de tudo (muito importante)
        h = HMAC(chave2_hmac, hashes.SHA256())
        h.update(iv + ciphertext)
        try:
            h.verify(mac) #se a msg foi adulterada no caminho, explode um erro aqui
        except:
            return None #rejeita a msg e vaza na hora
            
        #2. descriptografa o AES so dps q passou no teste de cima
        cipher = Cipher(algorithms.AES(chave1_aes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        #3. arranca o padding fora
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        return plaintext.decode('utf-8')