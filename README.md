# Sistema de Chat con Cifrado

## Descripción del Proyecto

Sistema de chat multiusuario cliente-servidor desarrollado en Python con soporte para cifrado simétrico (Fernet/AES) y cifrado asimétrico (RSA). Permite comunicación segura entre múltiples clientes a través de una red con validación de integridad de mensajes mediante SHA-256.

---

## Historial de Versiones

### Versión 1.0 - Sistema Base
**Fecha:** 28/09/2025
**Estado:** Deprecado

#### Características
- Chat multiusuario
- Comunicación cliente-servidor
- Comandos básicos (/hist, /list, /help, /quit)
- Anti-spam (2 segundos entre mensajes)
- Validación de nombres de usuario
- Historial de mensajes (últimos 10)

#### Archivos
- `Servidor.py` - 9d3deefc1dcd0126cd27e2dd2b141538  - Servidor principal
- `Clientes.py` - bbeff2536122ffa41fb3f54a23091a50  - Cliente de chat
- `utils.py` - 23a938ee4a1cd187f1861f056f49e20d - Utilidades y validaciones

---

### Versión 2.0 - Sistema con Cifrado
**Fecha:** 11/10/2025
**Estado:** Deprecado

#### Cambios Principales
- Implementación de cifrado simétrico usando Fernet (AES-128)
- Implementación de cifrado asimétrico usando RSA-2048
- Uso de PBKDF2 con SHA-256 para derivación de claves
- Uso de OAEP con SHA-256 para padding en RSA
- Separación de módulos de cifrado en archivos independientes

#### Archivos Nuevos
- `cifrado_simetrico.py` - becf298b6719bc19cd714dce1a2103ab - Módulo de cifrado simétrico con Fernet
- `cifrado_asimetrico.py` - a3d1edbafb7c7a01fdda8c5a35bac0e4 - Módulo de cifrado asimétrico con RSA
- `pruebas_cifrado.py` - Suite de pruebas automatizadas
- `requirements.txt` - e6afd56cd80effd76d645f19ce47deb2 - Dependencias del proyecto

#### Archivos Modificados
- `Servidor.py` - 407dbf61eb3ae05be7295d79015fc26c - Integración con módulos de cifrado
- `Clientes.py` - 937c31e7b3f797e6ea203fe98326e669 - Integración con módulos de cifrado
- `utils.py` - 41e9af505672b77256b01e0dfca8e32a - Mejoras en validación de datos

#### Características
- **Cifrado Simétrico:** Fernet (AES-128 CBC + HMAC SHA-256)
- **Cifrado Asimétrico:** RSA-2048 con OAEP SHA-256
- **Hash:** SHA-256 para integridad
- **KDF:** PBKDF2 con 100,000 iteraciones

---

### Versión 3.0 - Sistema con Validación de Integridad
**Fecha:** 23/10/2025  
**Estado:** Producción

#### Cambios Principales
- Implementación de validación de integridad con SHA-256
- Detección automática de mensajes modificados en tránsito
- Protección contra ataques Man-in-the-Middle (MITM)
- Validación de nombres de usuario, mensajes y comandos
- Logs detallados de eventos de integridad en servidor
- Protección contra inyección de comandos maliciosos
- Protección contra corrupción de datos en transmisión
- Protección contra replay attacks (combinado con anti-spam)

#### Archivos Nuevos
- `validacion_integridad.py` - Módulo de validación SHA-256

#### Archivos Modificados
- `Servidor.py` - Integración con validación de integridad
- `Clientes.py` - Integración con validación de integridad
- `pruebas_cifrado.py` - Pruebas de validación SHA-256 agregadas

#### Características de Seguridad
- **Validación de Integridad:** SHA-256 hash verification
- **Detección de Modificaciones:** Rechazo automático de mensajes alterados
- **Formato Seguro:** `mensaje_cifrado|||HASH|||hash_sha256`
- **Overhead Mínimo:** ~0.001ms por mensaje
- **Logs de Auditoría:** Registro de intentos de modificación

---

## Requisitos del Sistema

### Requisitos de Software
- **Python:** 3.8 o superior
- **Sistema Operativo:** Windows, Linux, macOS
- **Red:** Conexión TCP/IP

### Dependencias
- `cryptography>=41.0.0` - Librería de criptografía

---

## Instalación

### 1. Instalar Python

#### Windows
```bash
# Descargar desde https://www.python.org/downloads/
# Durante la instalacion, marcar "Add Python to PATH"

# Verificar instalacion
python --version
pip --version
```

#### Linux/macOS
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip

# macOS (con Homebrew)
brew install python3

# Verificar instalacion
python3 --version
pip3 --version
```

### 2. Instalar Dependencias

```bash
# Metodo recomendado
pip install -r requirements.txt

# Metodo alternativo
pip install cryptography>=41.0.0
```

### 3. Verificar Instalación
```bash
python -c "from cryptography.fernet import Fernet; print('Cryptography instalado correctamente')"
python -c "from validacion_integridad import ValidadorIntegridad; print('Validacion de integridad instalada correctamente')"
```

---

## Configuración

### Cifrado Simétrico (Fernet)
Editar en `cifrado_simetrico.py`:
```python
CLAVE_SECRETA = "mi_clave_super_secreta_2025_chat_grupal"  # Cambiar
SALT = b'salt_estatico_12345'  # Cambiar
```

### Cifrado Asimétrico (RSA)
Generar claves nuevas:
```bash
python cifrado_asimetrico.py
# Seleccionar opcion 1
# Copiar claves generadas en las constantes del archivo
```

### Seleccionar Tipo de Cifrado
En `Servidor.py` y `Clientes.py`, descomentar UNA opción:

```python
# Opcion 1: Cifrado Simetrico
from cifrado_simetrico import Cifrador

# Opcion 2: Cifrado Asimetrico
# from cifrado_asimetrico import Cifrador
```

**IMPORTANTE:** Servidor y clientes DEBEN usar el mismo tipo de cifrado.

### Validación de Integridad
La validación SHA-256 está activa por defecto en ambos modos de cifrado.
No requiere configuración adicional.

---

## Uso

### Iniciar el Servidor
```bash
python Servidor.py
```

Salida esperada:
```
Servidor principal:
Escuchando en el puerto 5555
Tipo de cifrado: Simétrico (Fernet)
Validacion de integridad: SHA-256 activa
Comandos del servidor: /shutdown - Cerrar servidor
```

Comandos del servidor:
- `/shutdown` - Cerrar servidor ordenadamente
- `/help` - Ver ayuda

### Iniciar Cliente
```bash
python Clientes.py
```

Comandos del cliente:
- `/hist` - Ver historial de mensajes
- `/list` - Ver usuarios conectados
- `/quit` - Salir del chat
- `/help` - Ver ayuda

### Mensajes de Error
El cliente puede recibir:
- `"Su mensaje no pudo ser enviado (error de integridad)"` - Hash no coincide
- `"Error de integridad en la comunicación"` - Formato inválido

El servidor registra:
- `[INTEGRIDAD] Registro rechazado desde {ip}: formato de hash invalido`
- `[INTEGRIDAD] Mensaje rechazado de {nombre}: hash SHA-256 no coincide`

---

## Licencia
Proyecto personal - Todos los derechos reservados

## Autores
Administrador: @AlexReyes03

## Contacto
Para soporte o consultas, contactar al administrador del proyecto.

---

## Notas Adicionales

### Cumplimiento
Este sistema implementa estándares criptográficos modernos:
- NIST SP 800-132 (PBKDF2)
- RFC 3447 (RSA PKCS #1)
- RFC 8017 (PKCS #1 v2.2)
- FIPS 180-4 (SHA-256)

### Rendimiento
- Overhead por mensaje: ~75 caracteres (hash + separadores)
- Tiempo de cálculo SHA-256: ~0.001ms
- Impacto en rendimiento: Mínimo (<1%)

### Compatibilidad
- Compatible con cifrado simétrico y asimétrico
- Compatible con todos los comandos existentes
- Compatible con caracteres especiales (UTF-8)
- Retrocompatible con versión 2.0 (mediante configuración)

---

**Última actualización:** 23 Octubre 2025  
**Versión del documento:** 2.0