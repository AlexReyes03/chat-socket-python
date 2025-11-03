import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SERVER_HOST = os.getenv('SERVER_HOST', 'localhost')
    SERVER_PORT = int(os.getenv('SERVER_PORT', '5555'))

    TIPO_CIFRADO = os.getenv('TIPO_CIFRADO', 'simetrico').lower()

    # Simetrico
    CLAVE_SECRETA = os.getenv('CLAVE_SECRETA', os.getenv('SYMMETRIC_SECRET_KEY', 'mi_clave_super_secreta_2025_chat_grupal'))
    SALT = os.getenv('SALT', os.getenv('SYMMETRIC_SALT', 'salt_estatico_12345')).encode('utf-8')
    PBKDF2_ITERATIONS = int(os.getenv('PBKDF2_ITERATIONS', '100000'))

    # Asimetrico
    CLAVE_PRIVADA_PEM = os.getenv('CLAVE_PRIVADA_PEM', '').encode('utf-8')
    CLAVE_PUBLICA_PEM = os.getenv('CLAVE_PUBLICA_PEM', '').encode('utf-8')
    RSA_KEY_SIZE = int(os.getenv('RSA_KEY_SIZE', '2048'))
    RSA_PRIVATE_KEY_PATH = os.getenv('RSA_PRIVATE_KEY_PATH', 'keys/rsa_private.pem')
    RSA_PUBLIC_KEY_PATH = os.getenv('RSA_PUBLIC_KEY_PATH', 'keys/rsa_public.pem')

    # SSL/TLS
    SSL_AUTO_GENERAR = os.getenv('SSL_AUTO_GENERAR', 'True').lower() == 'true'
    SSL_CERT_FILE = os.getenv('SSL_CERT_FILE', os.getenv('SSL_CERT_PATH', 'certs/server.crt'))
    SSL_KEY_FILE = os.getenv('SSL_KEY_FILE', os.getenv('SSL_KEY_PATH', 'certs/server.key'))
    SSL_CERT_VALIDITY_DAYS = int(os.getenv('SSL_CERT_VALIDITY_DAYS', os.getenv('SSL_CERT_DAYS', '365')))

    @staticmethod
    def validar_configuracion():
        errores = []

        if Config.TIPO_CIFRADO not in ['simetrico', 'asimetrico']:
            errores.append(f"TIPO_CIFRADO invalido: '{Config.TIPO_CIFRADO}'. Debe ser 'simetrico' o 'asimetrico'")

        if Config.TIPO_CIFRADO == 'simetrico':
            if not Config.CLAVE_SECRETA or len(Config.CLAVE_SECRETA) < 8:
                errores.append('CLAVE_SECRETA debe tener al menos 8 caracteres')
            if not Config.SALT or len(Config.SALT) < 8:
                errores.append('SALT debe tener al menos 8 caracteres')

        if Config.TIPO_CIFRADO == 'asimetrico':
            if not Config.CLAVE_PRIVADA_PEM or b'BEGIN PRIVATE KEY' not in Config.CLAVE_PRIVADA_PEM:
                errores.append('CLAVE_PRIVADA_PEM no esta configurada correctamente')
            if not Config.CLAVE_PUBLICA_PEM or b'BEGIN PUBLIC KEY' not in Config.CLAVE_PUBLICA_PEM:
                errores.append('CLAVE_PUBLICA_PEM no esta configurada correctamente')

        if Config.SERVER_PORT < 1024 or Config.SERVER_PORT > 65535:
            errores.append(f'SERVER_PORT invalido: {Config.SERVER_PORT}. Debe estar entre 1024 y 65535')

        return errores

    @staticmethod
    def mostrar_configuracion():
        print("\nConfiguracion cargada desde .env:")
        print(f"  Servidor: {Config.SERVER_HOST}:{Config.SERVER_PORT}")
        print(f"  Tipo de cifrado: {Config.TIPO_CIFRADO}")
        print(f"  SSL auto-generar: {Config.SSL_AUTO_GENERAR}")

        if Config.TIPO_CIFRADO == 'simetrico':
            print(f"  PBKDF2 iteraciones: {Config.PBKDF2_ITERATIONS}")
        else:
            print(f"  RSA key size: {Config.RSA_KEY_SIZE}")


if __name__ == "__main__":
    print("Validando configuracion...")
    errores = Config.validar_configuracion()

    if errores:
        print("\nErrores encontrados:")
        for error in errores:
            print(f"  - {error}")
    else:
        print("\nConfiguracion valida")
        Config.mostrar_configuracion()


