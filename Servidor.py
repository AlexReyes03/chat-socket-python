import socket
import threading
import time
from utils import validar_mensaje, es_comando, procesar_comando

# ============================================================================
# SELECCIONA EL TIPO DE CIFRADO QUE VAS A USAR:
# Descomenta UNA de las siguientes líneas (deja la otra comentada)
# IMPORTANTE: Debe ser el MISMO tipo que en Clientes.py
# ============================================================================

# OPCION 1: Cifrado Simétrico (Fernet/AES)
from cifrado_simetrico import Cifrador

# OPCION 2: Cifrado Asimétrico (RSA)
# from cifrado_asimetrico import Cifrador

# ===================== Línea separadora de dependencias =====================

class ServidorChat:
    def __init__(self, host='localhost', puerto=5555):
        self.host = host
        self.puerto = puerto
        self.clientes = {}  # {socket: {'nombre': str, 'ip': str, 'ultimo_mensaje': float}}
        self.historial = []  # Lista de mensajes [(timestamp, nombre, mensaje)]
        self.lock = threading.Lock()
        self.servidor_activo = True
        self.servidor = None
        
        # Para simétrico
        self.cifrador = Cifrador()
        # Descomentar para asimétrico
        # self.cifrador = Cifrador(es_servidor=True)
        
    def iniciar_servidor(self):
        """Inicia el servidor y escucha conexiones"""
        self.servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.servidor.bind((self.host, self.puerto))
            self.servidor.listen(5)
            print(f"Servidor principal:")
            print(f"Escuchando en el puerto {self.puerto}")
            print(f"Tipo de cifrado: {'Simétrico (Fernet)' if 'simetrico' in str(type(self.cifrador).__module__) else 'Asimétrico (RSA)'}")
            print("Comandos del servidor: /shutdown - Cerrar servidor")
            print("-" * 50)
            
            hilo_comandos = threading.Thread(target=self.manejar_comandos_servidor)
            hilo_comandos.daemon = True
            hilo_comandos.start()
            
            while self.servidor_activo:
                try:
                    self.servidor.settimeout(1.0)
                    cliente, direccion = self.servidor.accept()
                    
                    if not self.servidor_activo:
                        cliente.close()
                        break
                    
                    print(f"Nueva conexión desde {direccion[0]}:{direccion[1]} - Procesando registro...")
                    
                    hilo_registro = threading.Thread(
                        target=self.procesar_nuevo_cliente,
                        args=(cliente, direccion)
                    )
                    hilo_registro.daemon = True
                    hilo_registro.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.servidor_activo:
                        print(f"Error aceptando conexión: {e}")
                
        except Exception as e:
            print(f"Error en el servidor: {e}")
        finally:
            self.cerrar_servidor()
    
    def manejar_comandos_servidor(self):
        """Maneja los comandos del administrador del servidor"""
        while self.servidor_activo:
            try:
                comando = input().strip()
                
                if comando.lower() == "/shutdown":
                    self.procesar_shutdown()
                elif comando.lower() == "/help":
                    print("Comandos disponibles:")
                    print("/shutdown - Cerrar servidor ordenadamente")
                    print("/help - Mostrar esta ayuda")
                elif comando.strip() and comando.startswith("/"):
                    print(f"Comando '{comando}' no reconocido. Use /help para ver comandos disponibles.")
                    
            except (EOFError, KeyboardInterrupt):
                self.procesar_shutdown()
                break
            except Exception as e:
                if self.servidor_activo:
                    print(f"Error procesando comando: {e}")
    
    def procesar_nuevo_cliente(self, cliente, direccion):
        """Procesa el registro de un nuevo cliente"""
        ip = direccion[0]
        puerto_cliente = direccion[1]
        
        try:
            cliente.send("NOMBRE_USUARIO".encode('utf-8'))
            
            cliente.settimeout(30.0)
            
            nombre_cifrado = cliente.recv(1024).decode('utf-8').strip()
            
            if not nombre_cifrado or not self.servidor_activo:
                cliente.close()
                return
            
            nombre = self.cifrador.descifrar_mensaje(nombre_cifrado)
            
            if not nombre:
                cliente.send("NOMBRE_INVALIDO".encode('utf-8'))
                cliente.close()
                print(f"Registro rechazado desde {ip}: error al descifrar nombre")
                return
            
            from utils import validar_nombre_usuario
            if not validar_nombre_usuario(nombre):
                cliente.send("NOMBRE_INVALIDO".encode('utf-8'))
                cliente.close()
                print(f"Registro rechazado desde {ip}: nombre inválido '{nombre}'")
                return
            
            with self.lock:
                nombres_en_uso = [info['nombre'].lower() for info in self.clientes.values()]
                if nombre.lower() in nombres_en_uso:
                    cliente.send("NOMBRE_EN_USO".encode('utf-8'))
                    cliente.close()
                    print(f"Registro rechazado desde {ip}: nombre '{nombre}' ya está en uso")
                    return
                
                # Registrar cliente exitosamente
                self.clientes[cliente] = {
                    'nombre': nombre,
                    'ip': ip,
                    'puerto': puerto_cliente,
                    'ultimo_mensaje': 0
                }
            
            print(f"Cliente registrado exitosamente: {nombre} desde {ip}:{puerto_cliente}")
            
            cliente.send("CONECTADO".encode('utf-8'))
            
            mensaje_conexion = f"{nombre} se ha unido al chat"
            self.enviar_a_todos(mensaje_conexion, excluir=cliente)
            
            cliente.settimeout(None)
            self.manejar_cliente(cliente)
            
        except socket.timeout:
            print(f"Timeout en registro desde {ip} - conexión cerrada")
            try:
                cliente.close()
            except:
                pass
        except Exception as e:
            print(f"Error procesando nuevo cliente desde {ip}: {e}")
            try:
                cliente.close()
            except:
                pass

    def procesar_shutdown(self):
        """Procesa el comando de cierre del servidor con confirmación"""
        try:
            print("\n¿Está seguro de que desea cerrar el servidor? (y/Y para confirmar, cualquier otra tecla para cancelar)")
            confirmacion = input("Confirmación: ").strip()
            
            if confirmacion.lower() == 'y':
                print("Cerrando servidor...")
                self.servidor_activo = False
                
                mensaje_cierre = "El servidor se está cerrando. Conexión terminada."
                self.enviar_a_todos(mensaje_cierre)
                
                time.sleep(1)
                
                with self.lock:
                    for cliente in list(self.clientes.keys()):
                        try:
                            cliente.close()
                        except:
                            pass
                    self.clientes.clear()
                
                print("Servidor cerrado exitosamente.")
                
            else:
                print("Cierre de servidor cancelado.")
                
        except (EOFError, KeyboardInterrupt):
            print("\nForzando cierre del servidor...")
            self.servidor_activo = False
        except Exception as e:
            print(f"Error durante el cierre: {e}")
            self.servidor_activo = False
    
    def manejar_cliente(self, cliente):
        """Maneja los mensajes de un cliente específico"""
        try:
            while self.servidor_activo:
                try:
                    cliente.settimeout(1.0)
                    
                    mensaje_cifrado = cliente.recv(1024).decode('utf-8')
                    if not mensaje_cifrado:
                        break
                    
                    mensaje = self.cifrador.descifrar_mensaje(mensaje_cifrado)
                    
                    if not mensaje:
                        cliente.send("MENSAJE_INVALIDO".encode('utf-8'))
                        continue
                    
                    if mensaje == "DESCONEXION_CLIENTE":
                        break
                        
                    with self.lock:
                        if cliente not in self.clientes:
                            break
                            
                        info_cliente = self.clientes[cliente]
                        nombre = info_cliente['nombre']
                        ip = info_cliente['ip']
                        puerto = info_cliente['puerto']
                        
                        tiempo_actual = time.time()
                        if tiempo_actual - info_cliente['ultimo_mensaje'] < 2:
                            cliente.send("SPAM_DETECTADO".encode('utf-8'))
                            continue
                        
                        if es_comando(mensaje):
                            respuesta = procesar_comando(mensaje, self.clientes, self.historial)
                            cliente.send(f"COMANDO_RESPUESTA:{respuesta}".encode('utf-8'))
                            continue
                        
                        mensaje_limpio = validar_mensaje(mensaje)
                        if not mensaje_limpio:
                            cliente.send("MENSAJE_INVALIDO".encode('utf-8'))
                            continue
                        
                        info_cliente['ultimo_mensaje'] = tiempo_actual
                        
                        nombre_cifrado, ip_cifrada, puerto_cifrado = self.cifrador.cifrar_datos_usuario(
                            nombre, ip, puerto
                        )
                        mensaje_cifrado_enviar = self.cifrador.cifrar_mensaje(mensaje_limpio)
                        
                        print("\n\nDATOS CIFRADOS:")
                        print(f"[{ip_cifrada[:20]}..., {puerto_cifrado[:20]}..., {nombre_cifrado[:20]}...] {mensaje_cifrado_enviar[:30]}...")
                        print("\nDATOS DESCIFRADOS:")
                        print(f"[{ip}, {puerto}, {nombre}] {mensaje_limpio}")
                        
                        self.historial.append((tiempo_actual, nombre, ip, puerto, mensaje_limpio))
                        if len(self.historial) > 10:
                            self.historial.pop(0)
                        
                        mensaje_completo_cifrado = f"MENSAJE_CHAT:{ip_cifrada}|||{puerto_cifrado}|||{nombre_cifrado}|||{mensaje_cifrado_enviar}"
                        self.enviar_a_todos(mensaje_completo_cifrado, excluir=cliente)
                        
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    break
                except Exception as e:
                    if self.servidor_activo:
                        if "10054" not in str(e) and "forcibly closed" not in str(e).lower():
                            print(f"Error recibiendo mensaje de cliente: {e}")
                    break
                    
        except Exception as e:
            if self.servidor_activo:
                print(f"Error manejando cliente: {e}")
        finally:
            self.desconectar_cliente(cliente)
    
    def enviar_a_todos(self, mensaje, excluir=None):
        clientes_a_eliminar = []
        
        for cliente in list(self.clientes.keys()):
            if cliente == excluir:
                continue
                
            try:
                cliente.send(mensaje.encode('utf-8'))
            except:
                clientes_a_eliminar.append(cliente)
        
        for cliente in clientes_a_eliminar:
            self.desconectar_cliente(cliente)
    
    def desconectar_cliente(self, cliente):
        try:
            with self.lock:
                if cliente in self.clientes:
                    info_cliente = self.clientes[cliente]
                    nombre = info_cliente['nombre']
                    print(f"Cliente desconectado: {nombre}")
                    
                    if self.servidor_activo:
                        mensaje_desconexion = f"{nombre} ha salido del chat"
                        self.enviar_a_todos(mensaje_desconexion, excluir=cliente)
                    
                    del self.clientes[cliente]
            
            cliente.close()
        except:
            pass
    
    def cerrar_servidor(self):
        if self.servidor:
            try:
                self.servidor.close()
            except:
                pass
        print("Recursos del servidor liberados.")

if __name__ == "__main__":
    try:
        servidor = ServidorChat()
        servidor.iniciar_servidor()
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.")
    except Exception as e:
        print(f"Error fatal: {e}")
    finally:
        print("Programa terminado.")