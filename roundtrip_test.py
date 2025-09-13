"""
roundtrip_test.py

Pruebas unitarias rápidas:
- Verifica que un mensaje cifrado con `package_message` pueda ser descifrado correctamente
  con `verify_and_decrypt` (roundtrip).
- Verifica que la corrupción de un byte en el ciphertext sea detectada (integridad fallida).
"""

from cifrado import (
    encrypt_with_tag,      # Función que cifra y genera tag de autenticación
    verify_and_decrypt,    # Función que verifica el tag y descifra
    package_message,       # Empaqueta mensaje con prefijo (ej: "DATA|") + payload
    parse_message,         # Extrae tipo y body de un paquete
    CLAVE_SECRETA,         # Clave compartida usada en el cifrado
)
import binascii


def test_roundtrip_text(txt: str):
    """
    Prueba roundtrip:
    1. Empaqueta un mensaje en claro con `package_message`.
    2. Lo parsea para extraer tipo y body (ciphertext+tag).
    3. Intenta descifrar con `verify_and_decrypt` usando la misma clave.
    4. Comprueba si el texto descifrado coincide con el original.
    """
    paquete = package_message("DATA|", txt.encode(), CLAVE_SECRETA, auth=True)
    tipo, body = parse_message(paquete)
    try:
        claro = verify_and_decrypt(body, CLAVE_SECRETA)
        ok = claro.decode() == txt
        print(f"Roundtrip '{txt[:30]}...' -> OK={ok}")
    except Exception as e:
        print(f"Roundtrip '{txt[:30]}...' -> ERROR {e}")


def test_corruption(txt: str):
    """
    Prueba detección de corrupción:
    1. Genera un paquete con el mensaje original.
    2. Extrae el body (ciphertext+tag).
    3. Corrompe el primer byte del ciphertext (flip con XOR).
    4. Intenta verificar y descifrar.
       - Si no lanza excepción → ERROR (falló en detectar corrupción).
       - Si lanza excepción → OK (detectó corrupción).
    """
    paquete = package_message("DATA|", txt.encode(), CLAVE_SECRETA, auth=True)
    tipo, body = parse_message(paquete)

    # Solo se intenta corromper si hay al menos un byte en el body
    if len(body) > 0:
        corrupted = bytearray(body)
        corrupted[0] ^= 0x01  # Flip de 1 bit en el primer byte
        try:
            verify_and_decrypt(bytes(corrupted), CLAVE_SECRETA)
            print("CORRUPTION test FAILED: no detectó corrupción")
        except Exception as e:
            print("CORRUPTION test OK: detectó corrupción ->", e)
    else:
        print("CORRUPTION test SKIPPED: body vacío")


if __name__ == "__main__":
    # Pruebas de roundtrip con diferentes casos
    test_roundtrip_text("Hola mundo")        # Texto normal
    test_roundtrip_text("")                  # Cadena vacía
    test_roundtrip_text("áéíóú ñ")           # Texto con caracteres UTF-8 especiales
    test_roundtrip_text("A"*1024)            # Texto largo (1 KB de 'A')

    # Prueba de corrupción
    test_corruption("Mensaje para corromper")
