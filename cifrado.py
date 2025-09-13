"""
cifrado.py
Módulo de cifrado polimórfico tipo OTP para IoT.
Clave de 64 bits (8 bytes) y generación de keystream pseudoaleatorio con HMAC-SHA256.

Este módulo contiene:
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
# Clave secreta de 64 bits (8 bytes). Requerimiento del enunciado.
# EN PRODUCCIÓN: NO usar clave fija en el código; negociar con protocolo seguro (DH/TLS).
CLAVE_SECRETA: bytes = b"ABCDEFGH"  # 8 bytes = 64 bits

# Longitud del TAG HMAC-SHA256 que añadimos para integridad
TAG_LEN = 32

# Longitud del prefijo que indicará el tipo de mensaje (ejemplo: b"DATA|")
MSG_TYPE_LEN = 5


# -------------------------
# K E Y S T R E A M  (HMAC)
# -------------------------
def hmac_keystream(key: bytes, length: int) -> bytes:
    """
    Genera un keystream de `length` bytes usando HMAC-SHA256 en modo contador.
    - key: clave de entrada (8 bytes en nuestra implementación)
    - Se concatena un prefijo fijo b"POLY" con un contador de 8 bytes big-endian.
    Retorna exactamente `length` bytes.

    Nota de diseño:
    - Usamos HMAC-SHA256 como PRF para expandir la clave.
    - HMAC garantiza resistencia a ataques conocidos del PRF si la clave es secreta.
    - Limitación: clave de 64 bits es débil ante brute-force en entornos reales;
      se mantiene por la especificación académica del ejercicio.
    """
    out = bytearray()
    counter = 1
    while len(out) < length:
        ctr_b = struct.pack(">Q", counter)  # 8 bytes big-endian
        block = hmac.new(key, b"POLY" + ctr_b, hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def xor_cifrar_descifrar(datos: bytes, clave: bytes = CLAVE_SECRETA) -> bytes:
    """
    Cifra o descifra aplicando XOR con keystream derivado de 'clave'.
    La operación es simétrica: aplicar la misma función dos veces recupera el original.
    """
    ks = hmac_keystream(clave, len(datos))
    return bytes(d ^ k for d, k in zip(datos, ks))


# -------------------------
# INTEGRIDAD: TAG HMAC
# -------------------------
def derive_mac_key(key: bytes) -> bytes:
    """
    Deriva una subclave para MAC a partir de la clave principal.
    - En producción preferir HKDF con salt/labels; aquí usamos HMAC(key, b"MAC") para demo.
    - Se devuelve 32 bytes (sha256).
    """
    return hmac.new(key, b"MAC", hashlib.sha256).digest()


def encrypt_with_tag(plaintext: bytes, key: bytes = CLAVE_SECRETA) -> bytes:
    """
    Cifra plaintext y anexa un TAG HMAC-SHA256 sobre el ciphertext.
    Retorna ciphertext || tag
    """
    ciphertext = xor_cifrar_descifrar(plaintext, key)
    mac_key = derive_mac_key(key)
    tag = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    return ciphertext + tag


def verify_and_decrypt(data: bytes, key: bytes = CLAVE_SECRETA) -> bytes:
    """
    Verifica el TAG y devuelve el plaintext.
    - data: ciphertext || tag
    - Si el tag no coincide lanza ValueError("TAG_INVALIDO")
    """
    if len(data) < TAG_LEN:
        raise ValueError("PAQUETE_DEMASIADO_CORTO")
    ciphertext = data[:-TAG_LEN]
    tag = data[-TAG_LEN:]
    mac_key = derive_mac_key(key)
    expected = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    # Compare de forma segura
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
    Empaqueta un mensaje listo para enviar por TCP:
    - msg_type: string de longitud <= MSG_TYPE_LEN (p.ej. "DATA|" o "HELO|").
                Si es más corto se rellenará con espacios; si más largo se truncará.
    - payload: bytes (si auth=True se incluirá tag)
    - auth: si True cifra+tag, si False se envía raw (ej: HELO sin cifrar para handshake demo)

    Retorna: msg_type_bytes + body
    """
    # Normalizar msg_type a MSG_TYPE_LEN bytes
    t = msg_type.encode("ascii", errors="replace")[:MSG_TYPE_LEN]
    if len(t) < MSG_TYPE_LEN:
        t = t.ljust(MSG_TYPE_LEN, b" ")
    if auth:
        body = encrypt_with_tag(payload, key)
    else:
        body = payload
    return t + body


def parse_message(packet: bytes, key: bytes = CLAVE_SECRETA) -> Tuple[str, bytes]:
    """
    Parse simple: separa los primeros MSG_TYPE_LEN bytes y devuelve (tipo_str, payload_bytes)
    - No intenta verificar tag aquí: el consumidor decide si debe llamar a verify_and_decrypt.
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
    """Genera n llaves aleatorias de 'length' bytes usando CSPRNG (secrets.token_bytes)."""
    return [secrets.token_bytes(length) for _ in range(n)]


def shannon_entropy(data_bytes: bytes) -> float:
    """
    Calcula la entropía de Shannon en bits por símbolo para un array de bytes.
    Valor máximo por símbolo para un byte es 8 bits.
    """
    if not data_bytes:
        return 0.0
    freq = Counter(data_bytes)
    L = len(data_bytes)
    ent = -sum((c/L) * math.log2(c/L) for c in freq.values())
    return ent


def chi_square_uniform(data_bytes: bytes) -> float:
    """
    Estadístico chi-cuadrado para comparar la distribución de bytes con la distribución uniforme.
    - Retorna el valor chi2; valores altos indican desviación de uniformidad.
    """
    if not data_bytes:
        return 0.0
    freq = Counter(data_bytes)
    L = len(data_bytes)
    expected = L / 256.0
    chi2 = 0.0
    for b in range(256):
        observed = freq.get(b, 0)
        chi2 += (observed - expected) ** 2 / expected
    return chi2


def evaluar_llaves(n: int = 100, length: int = 8) -> dict:
    """
    Genera n llaves y devuelve estadísticas:
    - total, unicas, colisiones, entropia_promedio (bits/simbolo), chi2
    NOTA: entropia se calcula sobre la concatenación de llaves (sensible para N pequeño).
    """
    llaves = generar_llaves(n, length)
    concat = b"".join(llaves)
    ent = shannon_entropy(concat)
    chi2 = chi_square_uniform(concat)
    uniques = len(set(llaves))
    return {
        "total": n,
        "longitud_bytes": length,
        "unicas": uniques,
        "colisiones": n - uniques,
        "entropia_bits_por_simbolo": ent,
        "chi2_uniform": chi2
    }
