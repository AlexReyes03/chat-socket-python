import socket
import threading

# ============================================================================
# SELECCIONA EL TIPO DE CIFRADO QUE VAS A USAR:
# Descomenta UNA de las siguientes líneas (deja la otra comentada)
# IMPORTANTE: Debe ser el MISMO tipo que el Servidor.py
# ============================================================================

# Cifrado Simétrico (Fernet/AES)
from cifrado_simetrico import Cifrador

# Cifrado Asimétrico (RSA)
# from cifrado_asimetrico import Cifrador

# ===================== Línea separadora de dependencias =====================

class ClienteChat:
    def __init__(self, host='localhost', puerto=5555):
        self.host = host
        self.puerto = puerto
        self.cliente = None
        self.nombre = ""
        self.conectado = False
        
        # Para simétrico
        self.cifrador = Cifrador()
        # Descomentar para asimétrico
        # self.cifrador = Cifrador(es_servidor=False)
        
    def conectar(self):
        """Conecta al servidor de chat"""
        try:
            self.cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.cliente.connect((self.host, self.puerto))
            
            print("Conectando al servidor...")
            
            respuesta = self.cliente.recv(1024).decode('utf-8')
            if respuesta == "NOMBRE_USUARIO":
                while True:
                    self.nombre = input("Ingresa tu nombre: ").strip()
                    if not self.nombre:
                        print("Por favor ingresa un nombre válido.")
                        continue
                    
                    nombre_cifrado = self.cifrador.cifrar_mensaje(self.nombre)
                    if not nombre_cifrado:
                        print("Error al cifrar el nombre. Intenta de nuevo.")
                        continue
                        
                    self.cliente.send(nombre_cifrado.encode('utf-8'))
                    
                    confirmacion = self.cliente.recv(1024).decode('utf-8')
                    
                    if confirmacion == "CONECTADO":
                        print("¡Bienvenido al chat!")
                        print(f"Tipo de cifrado: {'Simétrico (Fernet)' if 'simetrico' in str(type(self.cifrador).__module__) else 'Asimétrico (RSA)'}")
                        print("Comandos disponibles: /hist, /list, /quit, /help")
                        print("Escribe tus mensajes:")
                        print("-" * 50)
                        self.conectado = True
                        return True
                        
                    elif confirmacion == "NOMBRE_INVALIDO":
                        print("Nombre inválido. Use solo letras, números, guiones y acentos (2-20 caracteres).")
                        continue
                        
                    elif confirmacion == "NOMBRE_EN_USO":
                        print("Ese nombre ya está en uso. Por favor elige otro.")
                        continue
                        
                    else:
                        print("Error inesperado del servidor")
                        return False
            else:
                print("Error en la comunicación con el servidor")
                return False
                    
        except ConnectionRefusedError:
            print("Error: No se pudo conectar al servidor. ¿Está el servidor ejecutándose?")
            return False
        except Exception as e:
            print(f"Error de conexión: {e}")
            return False
    
    def escuchar_servidor(self):
        """Escucha mensajes del servidor en un hilo separado"""
        while self.conectado:
            try:
                mensaje = self.cliente.recv(1024).decode('utf-8')
                if not mensaje:
                    break
                    
                if mensaje == "SPAM_DETECTADO":
                    print("Anti-spam: Espera 2 segundos entre mensajes")
                elif mensaje == "MENSAJE_INVALIDO":
                    print("Mensaje inválido")
                elif mensaje.startswith("COMANDO_RESPUESTA:"):
                    respuesta = mensaje.replace("COMANDO_RESPUESTA:", "")
                    print(respuesta)
                elif mensaje.startswith("MENSAJE_CHAT:"):
                    try:
                        datos_cifrados = mensaje.replace("MENSAJE_CHAT:", "")
                        partes = datos_cifrados.split("|||")
                        
                        if len(partes) == 4:
                            ip_cifrada, puerto_cifrado, nombre_cifrado, mensaje_cifrado = partes
                            
                            ip = self.cifrador.descifrar_mensaje(ip_cifrada)
                            puerto = self.cifrador.descifrar_mensaje(puerto_cifrado)
                            nombre = self.cifrador.descifrar_mensaje(nombre_cifrado)
                            mensaje_texto = self.cifrador.descifrar_mensaje(mensaje_cifrado)
                            
                            if mensaje_texto == "DESCONEXION_CLIENTE":
                                continue
                            
                            if ip and puerto and nombre and mensaje_texto:
                                print(f"[{ip}, {puerto}, {nombre}] {mensaje_texto}")
                            else:
                                print("Error al descifrar mensaje del servidor")
                        else:
                            print("Formato de mensaje incorrecto")
                    except Exception as e:
                        print(f"Error procesando mensaje cifrado: {e}")
                        
                elif mensaje == "El servidor se está cerrando. Conexión terminada.":
                    print("\n " + mensaje)
                    self.conectado = False
                    break
                else:
                    print(f"Sistema: {mensaje}")
                    
            except Exception as e:
                if self.conectado:
                    print(f"Error recibiendo mensaje: {e}")
                break
        
        print("\n Conexión con el servidor perdida.")
    
    def enviar_mensajes(self):
        """Permite al usuario enviar mensajes"""
        while self.conectado:
            try:
                mensaje = input()
                
                if mensaje.strip() == "":
                    continue
                    
                if mensaje.lower() == "/quit":
                    self.desconectar()
                    break
                
                mensaje_cifrado = self.cifrador.cifrar_mensaje(mensaje)
                
                if not mensaje_cifrado:
                    print("Error al cifrar mensaje. Intenta de nuevo.")
                    continue
                    
                self.cliente.send(mensaje_cifrado.encode('utf-8'))
                
                if not mensaje.startswith('/'):
                    print(f"Tu: {mensaje}")
                
            except KeyboardInterrupt:
                print("\n\nDesconectando...")
                self.desconectar()
                break
            except Exception as e:
                if self.conectado:
                    print(f"Error enviando mensaje: {e}")
                break
    
    def desconectar(self):
        """Desconecta del servidor"""
        if self.conectado and self.cliente:
            try:
                mensaje_desconexion_cifrado = self.cifrador.cifrar_mensaje("DESCONEXION_CLIENTE")
                self.cliente.send(mensaje_desconexion_cifrado.encode('utf-8'))
            except:
                pass
        
        self.conectado = False
        if self.cliente:
            try:
                self.cliente.close()
            except:
                pass
        print("Desconectado del servidor")
    
    def iniciar(self):
        """Inicia el cliente de chat"""
        if not self.conectar():
            return
        
        hilo_escucha = threading.Thread(target=self.escuchar_servidor)
        hilo_escucha.daemon = True
        hilo_escucha.start()
        
        try:
            self.enviar_mensajes()
        except KeyboardInterrupt:
            self.desconectar()

if __name__ == "__main__":
    try:
        cliente = ClienteChat()
        cliente.iniciar()
    except KeyboardInterrupt:
        print("\nPrograma interrumpido por el usuario.")
    except Exception as e:
        print(f"Error fatal: {e}")
    finally:
        print("Cliente terminado.")