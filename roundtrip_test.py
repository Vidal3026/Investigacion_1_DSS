"""
roundtrip_test.py

Pruebas unitarias rápidas:
- roundtrip con encrypt_with_tag/verify_and_decrypt indirectamente usando package_message.
- detección de corrupción (flip 1 byte en ciphertext -> verify falla).
"""

from cifrado import (
    encrypt_with_tag,
    verify_and_decrypt,
    package_message,
    parse_message,
    CLAVE_SECRETA,
)
import binascii

def test_roundtrip_text(txt: str):
    paquete = package_message("DATA|", txt.encode(), CLAVE_SECRETA, auth=True)
    tipo, body = parse_message(paquete)
    try:
        claro = verify_and_decrypt(body, CLAVE_SECRETA)
        ok = claro.decode() == txt
        print(f"Roundtrip '{txt[:30]}...' -> OK={ok}")
    except Exception as e:
        print(f"Roundtrip '{txt[:30]}...' -> ERROR {e}")

def test_corruption(txt: str):
    paquete = package_message("DATA|", txt.encode(), CLAVE_SECRETA, auth=True)
    tipo, body = parse_message(paquete)
    # Corromper un byte del ciphertext (si hay al menos 1 byte)
    if len(body) > 0:
        corrupted = bytearray(body)
        corrupted[0] ^= 0x01
        try:
            verify_and_decrypt(bytes(corrupted), CLAVE_SECRETA)
            print("CORRUPTION test FAILED: no detectó corrupción")
        except Exception as e:
            print("CORRUPTION test OK: detectó corrupción ->", e)
    else:
        print("CORRUPTION test SKIPPED: body vacío")

if __name__ == "__main__":
    test_roundtrip_text("Hola mundo")
    test_roundtrip_text("")
    test_roundtrip_text("áéíóú ñ")
    test_roundtrip_text("A"*1024)
    test_corruption("Mensaje para corromper")
