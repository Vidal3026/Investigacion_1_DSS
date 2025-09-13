"""
cliente_gui.py

Cliente con interfaz que:
- cifra mensajes (DATA) con tag y los envía
- permite enviar HELO (handshake) sin cifrar para demo
- muestra en cliente: mensaje claro, payload cifrado (hex), paquete enviado (hex)
- recibe respuesta del servidor y la procesa (ACK/ERR)
"""

import socket
import binascii
import tkinter as tk
from tkinter import scrolledtext
from cifrado import package_message, parse_message, verify_and_decrypt, CLAVE_SECRETA

HOST = "127.0.0.1"
PUERTO = 9000
RECV_TIMEOUT = 1.5  # segundos para esperar respuesta


class ClienteApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cliente de Mensajes")
        self.root.geometry("700x520")

        self.texto = scrolledtext.ScrolledText(root, wrap="word", width=90, height=28)
        self.texto.pack(padx=10, pady=10)

        frame = tk.Frame(root)
        frame.pack(pady=5)
        self.entrada = tk.Entry(frame, width=60)
        self.entrada.pack(side="left", padx=5)
        tk.Button(frame, text="Enviar DATA", command=self.enviar_data).pack(side="left", padx=5)
        tk.Button(frame, text="Enviar HELO", command=self.enviar_helo).pack(side="left", padx=5)

    def append(self, texto: str):
        self.texto.insert("end", texto)
        self.texto.see("end")

    def enviar_data(self):
        mensaje = self.entrada.get()
        if not mensaje:
            return
        # Empaquetamos con autenticación (ciphertext + tag)
        paquete = package_message("DATA|", mensaje.encode(), CLAVE_SECRETA, auth=True)
        # Para mostrar: extraer ciphertext y tag
        payload = paquete[5:]
        payload_hex = binascii.hexlify(payload).decode()
        paquete_hex = binascii.hexlify(paquete).decode()

        # Enviar y esperar respuesta breve
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(RECV_TIMEOUT)
                s.connect((HOST, PUERTO))
                s.sendall(paquete)
                # intentar recibir respuesta
                try:
                    resp = s.recv(8192)
                    if resp:
                        self._procesar_respuesta(resp)
                except socket.timeout:
                    pass
        except Exception as e:
            self.append(f"[!] Error enviando: {e}\n")

        # Mostrar en cliente
        self.append(f"Mensaje claro: {mensaje}\n")
        self.append(f"Payload (ciphertext+tag) hex: {payload_hex}\n")
        self.append(f"Paquete enviado (tipo+payload) hex: {paquete_hex}\n\n")
        self.entrada.delete(0, "end")

    def enviar_helo(self):
        # HELO sin auth en este demo (handshake simple)
        paquete = package_message("HELO|", b"", CLAVE_SECRETA, auth=False)
        paquete_hex = binascii.hexlify(paquete).decode()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(RECV_TIMEOUT)
                s.connect((HOST, PUERTO))
                s.sendall(paquete)
                try:
                    resp = s.recv(8192)
                    if resp:
                        self._procesar_respuesta(resp)
                except socket.timeout:
                    pass
        except Exception as e:
            self.append(f"[!] Error HELO: {e}\n")

        self.append(f"Enviado HELO (sin cifrar). Paquete hex: {paquete_hex}\n\n")

    def _procesar_respuesta(self, resp: bytes):
        """
        Procesa respuestas del servidor (ACK_|, ERR_|, ...).
        Para ACK y ERR intentamos verificar y descifrar (esperamos tag).
        """
        try:
            tipo, body = parse_message(resp)
        except Exception as e:
            self.append(f"[Resp] paquete inválido: {e}\n")
            return
        tipo = tipo.strip()
        if tipo == "ACK_|":
            try:
                claro = verify_and_decrypt(body, CLAVE_SECRETA)
                self.append(f"[Servidor] ACK -> {claro.decode(errors='replace')}\n\n")
            except ValueError as ve:
                self.append(f"[Servidor] ACK con TAG inválido: {ve}\n\n")
        elif tipo == "ERR_|":
            try:
                claro = verify_and_decrypt(body, CLAVE_SECRETA)
                self.append(f"[Servidor] ERR -> {claro.decode(errors='replace')}\n\n")
            except ValueError:
                self.append(f"[Servidor] ERR recibido con TAG inválido.\n\n")
        else:
            # Otros tipos o respuestas en claro
            self.append(f"[Servidor] Respuesta tipo={tipo} len={len(body)} bytes\n\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = ClienteApp(root)
    root.mainloop()
