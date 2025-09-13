"""
servidor_gui.py

Servidor TCP con interfaz Tkinter que:
- muestra la clave compartida (solo para demo)
- muestra mensajes recibidos: cifrado (hex) y descifrado
- evalúa calidad de generación de llaves y lo muestra en el panel
- responde ACKs y ERRs, y detecta TAG inválido (integridad)
"""

import socket
import threading
import binascii
import tkinter as tk
from tkinter import scrolledtext, simpledialog
from cifrado import (
    CLAVE_SECRETA,
    package_message,
    parse_message,
    verify_and_decrypt,
    evaluar_llaves,
)

HOST = "127.0.0.1"
PUERTO = 9000


class ServidorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Servidor de Mensajes")
        self.root.geometry("700x520")

        # Área de texto (scroll)
        self.texto = scrolledtext.ScrolledText(root, wrap="word", width=90, height=28)
        self.texto.pack(padx=10, pady=10)

        # Botones: evaluar llaves en tiempo real
        frame = tk.Frame(root)
        frame.pack(pady=5)
        tk.Button(frame, text="Evaluar llaves (200)", command=self.eval_200).pack(side="left", padx=5)
        tk.Button(frame, text="Evaluar llaves (1000)", command=self.eval_1000).pack(side="left", padx=5)
        tk.Button(frame, text="Evaluar N...", command=self.eval_custom).pack(side="left", padx=5)

        # Mostrar clave compartida 
        self.append_text(f"[+] Clave compartida (hex): {CLAVE_SECRETA.hex()}\n\n")

        # Evaluación inicial
        self.mostrar_evaluacion(200)

        # Iniciar servidor en hilo
        self.hilo = threading.Thread(target=self.iniciar_servidor, daemon=True)
        self.hilo.start()

    # -------- Interacción segura con Tkinter desde hilos -------
    def append_text(self, texto: str):
        """Inserta texto en el widget desde cualquier hilo de forma segura."""
        def task():
            self.texto.insert("end", texto)
            self.texto.see("end")
        self.texto.after(0, task)

    # -------- Evaluación de llaves y despliegue ----------
    def mostrar_evaluacion(self, n: int):
        stats = evaluar_llaves(n)
        s = (
            f"[+] Evaluación de llaves (n={stats['total']}, length={stats['longitud_bytes']} bytes)\n"
            f"    Únicas: {stats['unicas']} - Colisiones: {stats['colisiones']}\n"
            f"    Entropía (bits/símbolo): {stats['entropia_bits_por_simbolo']:.6f} (máx 8)\n"
            f"    Chi-cuadrado (bytes vs uniforme): {stats['chi2_uniform']:.2f}\n\n"
        )
        self.append_text(s)

    def eval_200(self):
        self.mostrar_evaluacion(200)

    def eval_1000(self):
        self.mostrar_evaluacion(1000)

    def eval_custom(self):
        n = simpledialog.askinteger("Evaluar N", "Número de llaves a generar:", minvalue=10, maxvalue=100000)
        if n:
            self.mostrar_evaluacion(n)

    # -------- Servidor TCP ----------
    def iniciar_servidor(self):
        """Arranca el servidor y acepta conexiones; cada cliente en un hilo."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PUERTO))
            s.listen()
            self.append_text(f"[+] Servidor escuchando en {HOST}:{PUERTO}\n\n")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.manejar_cliente, args=(conn, addr), daemon=True).start()

    def manejar_cliente(self, conn: socket.socket, addr):
        """
        Maneja un cliente: lee en bucle, parsea tipo de mensaje y procesa:
         - HELO| : mensaje de saludo (sin autenticación) -> responde ACK_| con tag
         - DATA| : payload cifrado+tag -> verificar tag, descifrar y ACK
         - ACK_| : ack cifrado -> verificar y mostrar
         - ERR_| : error cifrado -> verificar y mostrar
        """
        with conn:
            self.append_text(f"[+] Conexión desde {addr}\n")
            try:
                while True:
                    datos = conn.recv(8192)
                    if not datos:
                        self.append_text(f"[{addr}] Cliente desconectó.\n\n")
                        break

                    # Parse simple del tipo
                    try:
                        tipo, body = parse_message(datos)
                    except Exception as e:
                        self.append_text(f"[{addr}] Paquete inválido: {e}\n")
                        # responder error simple (sin autenticación)
                        conn.sendall(package_message("ERR_|", b"PAQUETE_INVALIDO", CLAVE_SECRETA, auth=True))
                        continue

                    tipo = tipo.strip()  # quitar posibles espacios
                    # Mostrar raw recibido en hex
                    self.append_text(f"[{addr}] Recibido tipo='{tipo}' - paquetelen={len(body)} bytes\n")
                    if tipo == "HELO|":
                        # HELO se envía en claro para handshake demo; servidor responde ACK cifrado
                        self.append_text(f"[{addr}] HELO (handshake) recibido (sin cifrar).\n")
                        # Responder ACK cifrado con tag
                        resp = package_message("ACK_|", b"HELLO_OK", CLAVE_SECRETA, auth=True)
                        conn.sendall(resp)

                    elif tipo == "DATA|":
                        # Mostrar ciphertext (hex)
                        self.append_text(f"[{addr}] Cifrado (hex): {binascii.hexlify(body).decode()}\n")
                        # Verificar tag y descifrar
                        try:
                            claro = verify_and_decrypt(body, CLAVE_SECRETA)
                            # Mostrar texto descifrado (utf-8 con replace)
                            txt = claro.decode(errors="replace")
                            self.append_text(f"[{addr}] Descifrado: {txt}\n\n")
                            # Responder ACK cifrado
                            ack = package_message("ACK_|", b"RECEIVED", CLAVE_SECRETA, auth=True)
                            conn.sendall(ack)
                        except ValueError as ve:
                            self.append_text(f"[{addr}] ERROR: {ve}\n")
                            # Responder error cifrado para evidenciar falla
                            err = package_message("ERR_|", str(ve).encode(), CLAVE_SECRETA, auth=True)
                            conn.sendall(err)

                    elif tipo == "ACK_|":
                        # Acknowledge: verificar tag y mostrar contenido
                        try:
                            claro = verify_and_decrypt(body, CLAVE_SECRETA)
                            txt = claro.decode(errors="replace")
                            self.append_text(f"[{addr}] ACK recibido -> {txt}\n\n")
                        except ValueError as ve:
                            self.append_text(f"[{addr}] ACK con TAG inválido: {ve}\n\n")

                    elif tipo == "ERR_|":
                        # Mensaje de error desde cliente (verificar)
                        try:
                            claro = verify_and_decrypt(body, CLAVE_SECRETA)
                            txt = claro.decode(errors="replace")
                            self.append_text(f"[{addr}] ERR recibido -> {txt}\n\n")
                        except ValueError:
                            self.append_text(f"[{addr}] ERR recibido con TAG inválido.\n\n")

                    else:
                        self.append_text(f"[{addr}] Tipo desconocido: '{tipo}'\n\n")

            except Exception as e:
                self.append_text(f"[{addr}] Excepción en handler: {e}\n\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = ServidorApp(root)
    root.mainloop()
