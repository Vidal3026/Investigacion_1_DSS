"""
cifrado.py
Módulo de cifrado polimórfico tipo OTP para IoT.
Clave de 64 bits (8 bytes) y generación de keystream pseudoaleatorio con HMAC-SHA256.

Este archivo contiene:
- la implementación HMAC-CTR-like para generar un keystream (hmac_keystream)
- XOR del keystream con el mensaje (xor_cifrar_descifrar)
- funciones para añadir/verificar un TAG HMAC (integridad)
- utilidades para empaquetar/parsear mensajes del "protocolo" simple
- funciones de evaluación de calidad de llaves (entropía, colisiones, chi-cuadrado)
"""

import hmac
import hashlib
import struct
import secrets
import math
from collections import Counter
from typing import Tuple

# -------------------------
# CONFIGURACIÓN / CONSTANTES
# -------------------------
# Clave secreta fija de 64 bits (8 bytes).
# !!! En producción esto NO debe hacerse: las claves nunca deben ir en el código,
# sino negociarse dinámicamente (por ejemplo con Diffie-Hellman o TLS).


CLAVE_SECRETA: bytes = b"ABCDEFGH"  # Ejemplo de clave fija (64 bits = 8 bytes)

# Longitud del TAG que se usa para verificar integridad (SHA-256 produce 32 bytes = 256 bits)
TAG_LEN = 32

# Longitud fija para el campo que identifica el tipo de mensaje (ejemplo: "DATA|")
MSG_TYPE_LEN = 5


# -------------------------
# K E Y S T R E A M  (HMAC)
# -------------------------
def hmac_keystream(key: bytes, length: int) -> bytes:
    """
    Genera un keystream pseudoaleatorio de 'length' bytes usando HMAC-SHA256
    en modo contador (CTR-like).

    - Se concatena un prefijo fijo (b"POLY") con un contador de 8 bytes (big-endian).
    - Cada bloque generado es de 32 bytes (output de SHA-256).
    - Se van concatenando bloques hasta alcanzar la longitud deseada.

|   Nota: aunque se use HMAC-SHA256, la clave base es de solo 64 bits, lo cual
    no es seguro frente a ataques de fuerza bruta en escenarios reales.
    """
    out = bytearray()   # Aquí se irán acumulando los bytes del keystream
    counter = 1         # Contador inicial
    while len(out) < length:
        ctr_b = struct.pack(">Q", counter)  # Convertir contador a 8 bytes big-endian
        # HMAC(key, b"POLY" || contador)
        block = hmac.new(key, b"POLY" + ctr_b, hashlib.sha256).digest()
        out.extend(block)   # Añadimos el bloque al keystream
        counter += 1        # Incrementamos el contador
    return bytes(out[:length])  # Recortar exactamente a la longitud pedida


def xor_cifrar_descifrar(datos: bytes, clave: bytes = CLAVE_SECRETA) -> bytes:
    """
    Cifra o descifra un mensaje aplicando XOR con el keystream generado a partir de la clave.
    La operación es reversible: aplicar dos veces devuelve el texto original.
    """
    ks = hmac_keystream(clave, len(datos))  # Generamos un keystream del mismo tamaño que los datos
    # Aplicamos XOR byte a byte
    return bytes(d ^ k for d, k in zip(datos, ks))


# -------------------------
# INTEGRIDAD: TAG HMAC
# -------------------------
def derive_mac_key(key: bytes) -> bytes:
    """
    Deriva una subclave para autenticación (MAC) a partir de la clave principal.
    - Para simplicidad: HMAC(key, b"MAC")
    - Devuelve 32 bytes (resultado SHA-256).
    """
    return hmac.new(key, b"MAC", hashlib.sha256).digest()


def encrypt_with_tag(plaintext: bytes, key: bytes = CLAVE_SECRETA) -> bytes:
    """
    Cifra un mensaje y añade un TAG HMAC-SHA256 para garantizar integridad.

    Flujo:
    1. Se cifra el plaintext con XOR y keystream.
    2. Se genera una clave de MAC derivada de la clave principal.
    3. Se calcula HMAC(ciphertext).
    4. Se devuelve ciphertext || tag.
    """
    ciphertext = xor_cifrar_descifrar(plaintext, key)  # Cifrar
    mac_key = derive_mac_key(key)                      # Subclave para MAC
    tag = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()  # Tag
    return ciphertext + tag


def verify_and_decrypt(data: bytes, key: bytes = CLAVE_SECRETA) -> bytes:
    """
    Verifica el TAG y descifra el mensaje si la integridad es válida.

    - Entrada: data = ciphertext || tag
    - Se recalcula HMAC(ciphertext) y se compara con el tag recibido.
    - Si no coinciden -> error.
    - Si coinciden -> descifra y devuelve plaintext.
    """
    if len(data) < TAG_LEN:
        raise ValueError("PAQUETE_DEMASIADO_CORTO")
    ciphertext = data[:-TAG_LEN]   # Separar datos y tag
    tag = data[-TAG_LEN:]
    mac_key = derive_mac_key(key)
    expected = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    # Comparación segura (evita ataques de tiempo)
    if not hmac.compare_digest(tag, expected):
        raise ValueError("TAG_INVALIDO")
    plaintext = xor_cifrar_descifrar(ciphertext, key)
    return plaintext


# -------------------------
# EMPAQUETADO / PARSING DE MENSAJES
# -------------------------
def package_message(msg_type: str, payload: bytes, key: bytes = CLAVE_SECRETA,
                    auth: bool = True) -> bytes:
    """
    Construye un paquete con encabezado y cuerpo.

    - msg_type: identificador ASCII del mensaje (máx 5 caracteres).
                Se rellena con espacios si es corto, o se trunca si es largo.
    - payload: contenido del mensaje (bytes).
    - auth=True: cifra y añade tag HMAC al payload.
    - auth=False: payload se envía sin cifrar (ejemplo: mensajes de handshake).

    Retorna: msg_type (5 bytes) || body (cifrado+tag o raw).
    """
    # Normalizar tipo de mensaje a longitud fija
    t = msg_type.encode("ascii", errors="replace")[:MSG_TYPE_LEN]
    if len(t) < MSG_TYPE_LEN:
        t = t.ljust(MSG_TYPE_LEN, b" ")
    # Procesar cuerpo según flag de autenticación
    if auth:
        body = encrypt_with_tag(payload, key)
    else:
        body = payload
    return t + body


def parse_message(packet: bytes, key: bytes = CLAVE_SECRETA) -> Tuple[str, bytes]:
    """
    Separa un paquete en:
    - tipo (str de longitud 5)
    - cuerpo (bytes: puede estar cifrado+tag o raw)

    La verificación del TAG no se hace aquí, el consumidor debe llamar
    a `verify_and_decrypt` si corresponde.
    """
    if len(packet) < MSG_TYPE_LEN:
        raise ValueError("PAQUETE_MUY_CORTO")
    tipo = packet[:MSG_TYPE_LEN].decode("ascii", errors="replace")
    body = packet[MSG_TYPE_LEN:]
    return tipo, body


# -------------------------
# EVALUACIÓN DE LLAVES (PUNTO b)
# -------------------------
def generar_llaves(n: int = 100, length: int = 8) -> list:
    """
    Genera n llaves aleatorias seguras usando secrets.token_bytes.
    - n: cantidad de llaves a generar.
    - length: longitud de cada llave en bytes (por defecto 8 bytes = 64 bits).
    """
    return [secrets.token_bytes(length) for _ in range(n)]


def shannon_entropy(data_bytes: bytes) -> float:
    """
    Calcula la entropía de Shannon en bits por símbolo para un arreglo de bytes.
    - Máximo teórico para bytes = 8 bits/símbolo (distribución perfectamente uniforme).
    - Valores más bajos indican menor aleatoriedad.
    """
    if not data_bytes:
        return 0.0
    freq = Counter(data_bytes)     # Frecuencias de cada byte
    L = len(data_bytes)            # Longitud total
    ent = -sum((c/L) * math.log2(c/L) for c in freq.values())
    return ent


def chi_square_uniform(data_bytes: bytes) -> float:
    """
    Test estadístico chi-cuadrado:
    - Compara la distribución observada de bytes contra una distribución uniforme.
    - Valores bajos ~ más aleatorio.
    - Valores altos ~ sesgo o patrones.
    """
    if not data_bytes:
        return 0.0
    freq = Counter(data_bytes)
    L = len(data_bytes)
    expected = L / 256.0   # Valor esperado por byte si fuera uniforme
    chi2 = 0.0
    for b in range(256):
        observed = freq.get(b, 0)
        chi2 += (observed - expected) ** 2 / expected
    return chi2


def evaluar_llaves(n: int = 100, length: int = 8) -> dict:
    """
    Genera n llaves y evalúa su calidad con métricas básicas:
    - total: cantidad de llaves generadas
    - unicas: cuántas fueron diferentes
    - colisiones: cuántas se repitieron
    - entropia_bits_por_simbolo: entropía promedio
    - chi2_uniform: estadístico chi-cuadrado
    """
    llaves = generar_llaves(n, length)
    concat = b"".join(llaves)   # Concatenar todas las llaves para análisis
    ent = shannon_entropy(concat)
    chi2 = chi_square_uniform(concat)
    uniques = len(set(llaves))  # Contar cuántas son únicas
    return {
        "total": n,
        "longitud_bytes": length,
        "unicas": uniques,
        "colisiones": n - uniques,
        "entropia_bits_por_simbolo": ent,
        "chi2_uniform": chi2
    }
