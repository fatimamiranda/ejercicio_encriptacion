import os
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv

load_dotenv()

class Criptografia:
    def __init__(self):
        # Generar una clave simétrica al crear la instancia
        self.clave_simetrica = self.generar_clave_simetrica()

        # Generar un par de claves asimétricas
        self.clave_publica_asimetrica, self.clave_privada_asimetrica = self.generar_par_claves_asimetricas()

        # Obtener el salt del archivo .env
        self.salt = os.environ.get("SALT").encode()

    @staticmethod
    def generar_clave_simetrica():
        # Generar una clave simétrica
        return Fernet.generate_key()

    @staticmethod
    def generar_par_claves_asimetricas():
        # Generar un par de claves asimétricas RSA
        clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        clave_publica = clave_privada.public_key()
        return clave_publica, clave_privada

    def cifrar_nombre_asimetrico(self, nombre):
        nombre_codificado = nombre.encode()
        nombre_cifrado = self.clave_publica_asimetrica.encrypt(
            nombre_codificado,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return nombre_cifrado

    def descifrar_nombre_asimetrico(self, nombre_cifrado):
        nombre_descifrado = self.clave_privada_asimetrica.decrypt(
            nombre_cifrado,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return nombre_descifrado.decode()

    def cifrar_nombre_con_salt(self, nombre):
        nombre_completo = nombre
        nombre_completo_codificado = nombre_completo.encode()
        entrada_con_salt = nombre_completo_codificado + self.salt
        hash_objeto = hashlib.sha256(entrada_con_salt)
        hash_hex = hash_objeto.hexdigest()
        return hash_hex

    def cifrar_nombre_simetrico(self, nombre):
        f = Fernet(self.clave_simetrica)
        nombre_codificado = nombre.encode()
        nombre_cifrado = f.encrypt(nombre_codificado)
        return nombre_cifrado

    def descifrar_nombre_simetrico(self, nombre_cifrado):
        f = Fernet(self.clave_simetrica)
        nombre_descifrado = f.decrypt(nombre_cifrado)
        nombre_original = nombre_descifrado.decode()
        return nombre_original



    