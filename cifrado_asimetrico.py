from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64

# Si estas claves estan vacías, ejecuta este archivo con:
# python cifrado_asimetrico.py
# Y copia las claves generadas aqui

CLAVE_PRIVADA_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCwU1EGUaEXLLYI
ikz8UN+Ro8YHfMVgLzU8xkEWI48HTB3YrhJd0E4XTLGPmtRWfJ0Se9uvCrU2717c
mHD14SFzsFYGS5FBxhNMqshq47QNIFoNT21JXh45B4AYx4ehCw7GX6AjAyGcXmC9
M+PlBLI41Vtn350h+cUdGX+nJOD5yoetvLEefNBU7CfCzI/CIRqAH+sTZFvOOYP9
Vj+bqgFSSNkxEQc6OoZlMXWkj4ogY1O8ae7mVUojp92wYYZ6e5iZcGznqGeuOlqU
CRmIrwb1xEIgrY60Epwa2i8yC2rQoZMVBGaVP5lgzjhdmgKzPnfpQ+BIX7MGZcXr
YSXBWmPBAgMBAAECggEABGNYIcDNzZqFJDTEnaHgm5zdB/NQSAPl4yr7eOUcAUwX
0Q6bFsNhKP3sXphZ/qhLUkNCeYOaBtY2QOXLA00wGlNWkUrAyZClnTzdPaEs/Iek
HhN3oK95CyWAdaH6/badadYzdep1NkhBbGv6axtBEAwXhskjvY2J08ysC0cAbQXM
PQInGuUpAbSFgP8GJIDb/RwV/hXdMVvPBdNiPpUKNPYDvJwlV63ckocEOXzoV9eh
/6NdxkdiqQ+ydYvYSRMlpOUQ5lOcs7OZLLMe/wh8D8nDaQVpq0Wm2gWkYeGVj/XV
ZtOupq8a9wVutPU5cD10z69KwlAai3yh7KALv721PQKBgQDdjVZEJsBjY+IuVrvr
8yNqs23tvG5+usCrGR9W2Rphx1YqKbnLMR1Pc1NB7kv2JKWh+fpirwSvZIRIiXjb
F9EhmtEGVMWMeRVcJD88vGisqozUwZq5d8xDgWpmsyD6Bf8V0vsPv09ZD4BQWjDh
MLWjvvcMBL4Iq7kUH3KbxRg7TQKBgQDLvccOst3NEvjYA6+uwJyeMlbP45ZqMfNX
YcyOY3+EaRrKSXUH/DYPLYiKG5t22ZxunwXO24GKms1Z3EmGXEqdvD67n/8LGWHe
sGkdaglErJ3gLacQtNVMBUx+LRCuVhKnqy1IC9IGGSw5eLkJECAdmItalccrCyPD
sGl4s9gIRQKBgQCGQzTYMDO/B7T2KBHSN5JrAznHLL45hqtkBOF9HCxkvQx2mLrD
bIw6rcTy25qlHChUNM2MKExKjjusScM34wMVvmCV2aGuM2LCaCT6haNZoDGgbYN6
iiL7dd4pRrzhR+kCLM2BCYroigBUsZOVpJMvHHdSjT0svAR5MWWfCJ5asQKBgQCS
1BumbiUGa4vGMTHk4I5+O4zwmPWHZqQV7zc5zl7Rj+Vsru+WZ56V5Zym2yp4xm7E
EfpfjzWWK+WdwvGB0PU9I7KaCL4Gw64SjFPUjNxND5FfQ8dIdOnatV7g950z5nff
Oa+SYmJjXrTOXkALVgGvEoYrLBGy5X5KwtHf2MvxeQKBgQC9e5JQXsRt9YpkPCOk
ocPCYdkiYHK0S1CrKNLSONGQiS8XHmYG/6QMQd3c0PKfz+gJHJdlpYstouVVB639
U86cYUrjBbWTgk2MprFkQqSJf2/WQTKvWx9dn9pZDEONWu4sRxxQylgf/z661l8L
vKkcjBSp5QDf1FNV/qWng2MOHw==
-----END PRIVATE KEY-----"""

CLAVE_PUBLICA_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsFNRBlGhFyy2CIpM/FDf
kaPGB3zFYC81PMZBFiOPB0wd2K4SXdBOF0yxj5rUVnydEnvbrwq1Nu9e3Jhw9eEh
c7BWBkuRQcYTTKrIauO0DSBaDU9tSV4eOQeAGMeHoQsOxl+gIwMhnF5gvTPj5QSy
ONVbZ9+dIfnFHRl/pyTg+cqHrbyxHnzQVOwnwsyPwiEagB/rE2RbzjmD/VY/m6oB
UkjZMREHOjqGZTF1pI+KIGNTvGnu5lVKI6fdsGGGenuYmXBs56hnrjpalAkZiK8G
9cRCIK2OtBKcGtovMgtq0KGTFQRmlT+ZYM44XZoCsz536UPgSF+zBmXF62ElwVpj
wQIDAQAB
-----END PUBLIC KEY-----"""


class Cifrador:
    
    def __init__(self, es_servidor=False):
        self.es_servidor = es_servidor
        
        if es_servidor:
            self.clave_privada = self._cargar_clave_privada()
            self.clave_publica = self._cargar_clave_publica()
        else:
            self.clave_publica = self._cargar_clave_publica()
            self.clave_privada = None
    
    def _cargar_clave_privada(self):
        try:
            clave_privada = serialization.load_pem_private_key(
                CLAVE_PRIVADA_PEM,
                password=None,
                backend=default_backend()
            )
            return clave_privada
        except Exception as e:
            print(f"Error cargando clave privada: {e}")
            return None
    
    def _cargar_clave_publica(self):
        try:
            clave_publica = serialization.load_pem_public_key(
                CLAVE_PUBLICA_PEM,
                backend=default_backend()
            )
            return clave_publica
        except Exception as e:
            print(f"Error cargando clave publica: {e}")
            return None
    
    def obtener_clave_publica_pem(self):
        return CLAVE_PUBLICA_PEM.decode('utf-8')
    
    def cifrar_mensaje(self, mensaje):
        try:
            mensaje_bytes = mensaje.encode('utf-8')
            bloque_max = 190
            bloques_cifrados = []
            
            for i in range(0, len(mensaje_bytes), bloque_max):
                bloque = mensaje_bytes[i:i+bloque_max]
                bloque_cifrado = self._cifrar_rsa(bloque)
                if bloque_cifrado:
                    bloques_cifrados.append(base64.b64encode(bloque_cifrado).decode('utf-8'))
            
            return "|||".join(bloques_cifrados)
        except Exception as e:
            print(f"Error cifrando mensaje: {e}")
            return None
    
    def descifrar_mensaje(self, mensaje_cifrado):
        try:
            if not self.es_servidor:
                print("Error: Solo el servidor puede descifrar mensajes")
                return None
            
            bloques = mensaje_cifrado.split("|||")
            mensaje_completo = ""
            
            for bloque_b64 in bloques:
                bloque_cifrado = base64.b64decode(bloque_b64.encode('utf-8'))
                bloque_descifrado_bytes = self._descifrar_rsa(bloque_cifrado)
                if bloque_descifrado_bytes:
                    mensaje_completo += bloque_descifrado_bytes.decode('utf-8')
            
            return mensaje_completo
        except Exception as e:
            print(f"Error descifrando mensaje: {e}")
            return None
    
    def cifrar_datos_usuario(self, nombre, ip, puerto):
        try:
            nombre_cifrado = self.cifrar_mensaje(nombre)
            ip_cifrada = self.cifrar_mensaje(ip)
            puerto_cifrado = self.cifrar_mensaje(str(puerto))
            return nombre_cifrado, ip_cifrada, puerto_cifrado
        except Exception as e:
            print(f"Error cifrando datos de usuario: {e}")
            return None, None, None
    
    def descifrar_datos_usuario(self, nombre_cifrado, ip_cifrada, puerto_cifrado):
        try:
            if not self.es_servidor:
                print("Error: Solo el servidor puede descifrar datos")
                return None, None, None
            
            nombre = self.descifrar_mensaje(nombre_cifrado)
            ip = self.descifrar_mensaje(ip_cifrada)
            puerto = int(self.descifrar_mensaje(puerto_cifrado))
            return nombre, ip, puerto
        except Exception as e:
            print(f"Error descifrando datos de usuario: {e}")
            return None, None, None

    @staticmethod
    def _generar_par_claves_rsa():
        try:
            clave_privada = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            clave_publica = clave_privada.public_key()
            return clave_privada, clave_publica
        except Exception as e:
            print(f"Error generando claves RSA: {e}")
            return None, None
    
    def _cifrar_rsa(self, datos_planos):
        try:
            datos_cifrados = self.clave_publica.encrypt(
                datos_planos,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return datos_cifrados
        except Exception as e:
            print(f"Error en cifrado RSA: {e}")
            return None

    def _descifrar_rsa(self, datos_cifrados):
        try:
            if not self.clave_privada:
                print("Error: No hay clave privada para descifrar")
                return None
            
            datos_descifrados = self.clave_privada.decrypt(
                datos_cifrados,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return datos_descifrados
        except Exception as e:
            print(f"Error en descifrado RSA: {e}")
            return None
    
    def _validar_puede_descifrar(self):
        return self.es_servidor and self.clave_privada is not None


def generar_claves_para_servidor():
    print("Generando nuevo par de claves RSA...")
    
    clave_privada, clave_publica = Cifrador._generar_par_claves_rsa()
    
    if clave_privada and clave_publica:
        pem_privada = clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        pem_publica = clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        print("\n" + "="*70)
        print("CLAVE PRIVADA (Copia esto en CLAVE_PRIVADA_PEM):")
        print("="*70)
        print(pem_privada.decode('utf-8'))
        
        print("\n" + "="*70)
        print("CLAVE PUBLICA (Copia esto en CLAVE_PUBLICA_PEM):")
        print("="*70)
        print(pem_publica.decode('utf-8'))
        
        print("\nCopia estas claves en las constantes del archivo")
    else:
        print("Error generando claves")


if __name__ == "__main__":
    print("Selecciona una opcion:")
    print("1. Generar nuevas claves RSA")
    print("2. Probar cifrado/descifrado")
    opcion = input("Opcion: ")
    
    if opcion == "1":
        generar_claves_para_servidor()
    elif opcion == "2":
        print("\nProbando modulo de cifrado asimetrico...")
        
        cifrador_servidor = Cifrador(es_servidor=True)
        cifrador_cliente = Cifrador(es_servidor=False)
        
        mensaje_original = "Hola desde el cliente!"
        mensaje_cifrado = cifrador_cliente.cifrar_mensaje(mensaje_original)
        print(f"Mensaje original: {mensaje_original}")
        print(f"Mensaje cifrado: {mensaje_cifrado[:50]}...")
        
        mensaje_descifrado = cifrador_servidor.descifrar_mensaje(mensaje_cifrado)
        print(f"Mensaje descifrado: {mensaje_descifrado}")
        print(f"Coinciden: {mensaje_original == mensaje_descifrado}")
        
        nombre, ip, puerto = "Usuario1", "127.0.0.1", 54321
        nombre_c, ip_c, puerto_c = cifrador_cliente.cifrar_datos_usuario(nombre, ip, puerto)
        nombre_d, ip_d, puerto_d = cifrador_servidor.descifrar_datos_usuario(nombre_c, ip_c, puerto_c)
        
        print(f"\nDatos originales: {nombre}, {ip}, {puerto}")
        print(f"Datos descifrados: {nombre_d}, {ip_d}, {puerto_d}")
        print(f"Coinciden: {nombre == nombre_d and ip == ip_d and puerto == puerto_d}")
    else:
        print("Opcion invalida")