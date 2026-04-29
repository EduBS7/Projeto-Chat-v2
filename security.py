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
        self.ph = PasswordHasher()

    # ARGON2 (senhas)
    def hash_password(self, password):
        """Gera o hash Argon2 (o salt é gerado automaticamente pela biblioteca)"""
        return self.ph.hash(password)

    def verify_password(self, hashed_password, plain_password):
        """Verifica se a senha em texto puro bate com o hash salvo"""
        try:
            return self.ph.verify(hashed_password, plain_password)
        except:
            return False

    # ECC / Ed25519 (assinaturas digitais)
    def generate_signature_keypair(self):
        """Gera as chaves de assinatura do cliente"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        #serializando para enviar pelo socket
        priv_bytes = private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        pub_bytes = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return priv_bytes, pub_bytes

    def sign_nonce(self, private_key_bytes, nonce_bytes):
        """Assina o desafio (nonce) do servidor com a chave privada ECC"""
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        return private_key.sign(nonce_bytes)

    def verify_signature(self, public_key_bytes, signature, message):
        """Servidor usa para verificar se a assinatura do cliente é válida"""
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        try:
            public_key.verify(signature, message)
            return True
        except:
            return False
    #DHE + HKDF (Derivação de Chaves)
    
    def generate_dh_keypair(self):
        """Gera as chaves X25519 para o Diffie-Hellman Efêmero"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def compute_shared_secret(self, my_private_key, other_public_bytes):
        """Calcula o segredo compartilhado (DH)"""
        other_public_key = x25519.X25519PublicKey.from_public_bytes(other_public_bytes)
        return my_private_key.exchange(other_public_key)

    def derive_keys_hkdf(self, shared_secret, salt):
        """Usa HKDF com SHA256 para gerar Chave 1 (AES) e Chave 2 (HMAC)"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64, # 64 bytes totais
            salt=salt,
            info=b'chat_session_keys'
        )
        derived_material = hkdf.derive(shared_secret)
        chave1_aes = derived_material[:32]  # primeiros 32 bytes
        chave2_hmac = derived_material[32:] # ultimos 32 bytes
        return chave1_aes, chave2_hmac

    #AES-256 + HMAC criptografia de msg
    def encrypt_and_mac(self, chave1_aes, chave2_hmac, plaintext: str):
        """Cifra a mensagem com AES e assina com HMAC"""
        iv = os.urandom(16) #vetor q inicializa o AES
        
        #padding (O AES requer blocos de 16 bytes)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        
        #AES-256-CBC
        cipher = Cipher(algorithms.AES(chave1_aes), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        #gera mac
        h = HMAC(chave2_hmac, hashes.SHA256())
        h.update(iv + ciphertext)
        mac = h.finalize()
        
        return iv, ciphertext, mac

    def verify_mac_and_decrypt(self, chave1_aes, chave2_hmac, iv, ciphertext, mac):
        """Verifica o HMAC. Se válido, descriptografa o AES"""
        # 1. Verificar HMAC
        h = HMAC(chave2_hmac, hashes.SHA256())
        h.update(iv + ciphertext)
        try:
            h.verify(mac) #vai dar erro se a mensagem for errada
        except:
            return None #msg corrompida ou atacada
            
        #descriptografar
        cipher = Cipher(algorithms.AES(chave1_aes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        #remover padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        return plaintext.decode('utf-8')