# Sistema de Chat con Cifrado

## Descripción del Proyecto

Sistema de chat multiusuario cliente-servidor desarrollado en Python con soporte para cifrado simétrico (Fernet/AES) y cifrado asimétrico (RSA). Permite comunicación segura entre múltiples clientes a través de una red.

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
- `Servidor.py` - Servidor principal
- `Clientes.py` - Cliente de chat
- `utils.py` - Utilidades y validaciones

---

### Versión 2.0 - Sistema con Cifrado (Actual)
**Fecha:** 2025-01-XX  
**Estado:** Producción

#### Cambios Principales
- Implementación de cifrado simétrico usando Fernet (AES-128)
- Implementación de cifrado asimétrico usando RSA-2048
- Uso de PBKDF2 con SHA-256 para derivación de claves
- Uso de OAEP con SHA-256 para padding en RSA
- Separación de módulos de cifrado en archivos independientes

#### Archivos Nuevos
- `cifrado_simetrico.py` - Módulo de cifrado simétrico con Fernet
- `cifrado_asimetrico.py` - Módulo de cifrado asimétrico con RSA
- `pruebas_cifrado.py` - Suite de pruebas automatizadas
- `requirements.txt` - Dependencias del proyecto

#### Archivos Modificados
- `Servidor.py` - Integración con módulos de cifrado
- `Clientes.py` - Integración con módulos de cifrado
- `utils.py` - Mejoras en validación de datos

#### Características Técnicas
- **Cifrado Simétrico:** Fernet (AES-128 CBC + HMAC SHA-256)
- **Cifrado Asimétrico:** RSA-2048 con OAEP SHA-256
- **Hash:** SHA-256 para integridad
- **KDF:** PBKDF2 con 100,000 iteraciones

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
# from cifrado_simetrico import Cifrador

# Opcion 2: Cifrado Asimetrico
from cifrado_asimetrico import Cifrador
```

**IMPORTANTE:** Servidor y clientes DEBEN usar el mismo tipo de cifrado.

---

## Uso

### Iniciar el Servidor
```bash
python Servidor.py
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

---

**Última actualización:** Octubre 2025
**Versión del documento:** 1.0
