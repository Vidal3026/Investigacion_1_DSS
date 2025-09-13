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

# Dirección y puerto en los que el servidor escuchará
HOST = "127.0.0.1"
PUERTO = 9000


class ServidorApp:
    def __init__(self, root):
        """
        Inicializa la ventana principal del servidor:
        - Configura el área de texto para mostrar logs y resultados
        - Crea botones para evaluar llaves
        - Muestra la clave compartida
        - Ejecuta una primera evaluación de llaves
        - Lanza el hilo del servidor TCP
        """
        self.root = root
        self.root.title("Servidor de Mensajes")
        self.root.geometry("700x550")

        # Área de texto con scroll para mostrar mensajes de log
        self.texto = scrolledtext.ScrolledText(root, wrap="word", width=90, height=28)
        self.texto.pack(padx=10, pady=10)

        # Frame con botones para evaluar la calidad de generación de llaves
        frame = tk.Frame(root)
        frame.pack(pady=5)
        tk.Button(frame, text="Evaluar llaves (200)", command=self.eval_200).pack(side="left", padx=5)
        tk.Button(frame, text="Evaluar llaves (1000)", command=self.eval_1000).pack(side="left", padx=5)
        tk.Button(frame, text="Evaluar N...", command=self.eval_custom).pack(side="left", padx=5)

        # Mostrar en pantalla la clave compartida (en hex), solo con fines de demostración
        self.append_text(f"[+] Clave compartida (hex): {CLAVE_SECRETA.hex()}\n\n")

        # Realizar evaluación inicial con 200 llaves
        self.mostrar_evaluacion(200)

        # Iniciar el servidor en un hilo independiente para no bloquear la interfaz
        self.hilo = threading.Thread(target=self.iniciar_servidor, daemon=True)
        self.hilo.start()

    # -------- Interacción segura con Tkinter desde hilos -------
    def append_text(self, texto: str):
        """
        Inserta texto en el widget ScrolledText desde cualquier hilo.
        Se usa .after(0, ...) para asegurar que Tkinter procese la inserción
        en el hilo principal de la GUI.
        """
        def task():
            self.texto.insert("end", texto)
            self.texto.see("end")
        self.texto.after(0, task)

    # -------- Evaluación de llaves y despliegue ----------
    def mostrar_evaluacion(self, n: int):
        """
        Genera n llaves aleatorias, calcula estadísticas de calidad
        (unicidad, colisiones, entropía, chi-cuadrado) y las muestra en la interfaz.
        """
        stats = evaluar_llaves(n)
        s = (
            f"[+] Evaluación de llaves (n={stats['total']}, length={stats['longitud_bytes']} bytes)\n"
            f"    Únicas: {stats['unicas']} - Colisiones: {stats['colisiones']}\n"
            f"    Entropía (bits/símbolo): {stats['entropia_bits_por_simbolo']:.6f} (máx 8)\n"
            f"    Chi-cuadrado (bytes vs uniforme): {stats['chi2_uniform']:.2f}\n\n"
        )
        self.append_text(s)

    def eval_200(self):
        """Botón para evaluar 200 llaves."""
        self.mostrar_evaluacion(200)

    def eval_1000(self):
        """Botón para evaluar 1000 llaves."""
        self.mostrar_evaluacion(1000)

    def eval_custom(self):
        """
        Abre un diálogo para que el usuario ingrese cuántas llaves
        quiere evaluar (entre 10 y 100000).
        """
        n = simpledialog.askinteger("Evaluar N", "Número de llaves a generar:", minvalue=10, maxvalue=100000)
        if n:
            self.mostrar_evaluacion(n)

    # -------- Servidor TCP ----------
    def iniciar_servidor(self):
        """
        Arranca el servidor TCP que:
        - Escucha en HOST:PUERTO
        - Acepta múltiples conexiones de clientes
        - Lanza un hilo separado para manejar cada cliente
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # permite reutilizar el puerto
            s.bind((HOST, PUERTO))
            s.listen()
            self.append_text(f"[+] Servidor escuchando en {HOST}:{PUERTO}\n\n")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.manejar_cliente, args=(conn, addr), daemon=True).start()

    def manejar_cliente(self, conn: socket.socket, addr):
        """
        Maneja la comunicación con un cliente específico en un hilo independiente.
        El protocolo soporta mensajes de tipo:
         - HELO| : handshake inicial sin autenticación, servidor responde con ACK_| cifrado
         - DATA| : mensaje de datos cifrado + tag, servidor verifica y responde ACK_| o ERR_|
         - ACK_| : acuse de recibo desde cliente, servidor lo muestra
         - ERR_| : error desde cliente, servidor lo muestra
        """
        with conn:
            self.append_text(f"[+] Conexión desde {addr}\n")
            try:
                while True:
                    datos = conn.recv(8192)
                    if not datos:
                        # Cliente cerró la conexión
                        self.append_text(f"[{addr}] Cliente desconectó.\n\n")
                        break

                    # Intentar extraer tipo y cuerpo del mensaje recibido
                    try:
                        tipo, body = parse_message(datos)
                    except Exception as e:
                        # Si el mensaje no cumple el formato esperado, se envía un error cifrado
                        self.append_text(f"[{addr}] Paquete inválido: {e}\n")
                        conn.sendall(package_message("ERR_|", b"PAQUETE_INVALIDO", CLAVE_SECRETA, auth=True))
                        continue

                    tipo = tipo.strip()  # limpiar espacios innecesarios
                    # Mostrar log con longitud del body recibido
                    self.append_text(f"[{addr}] Recibido tipo='{tipo}' - paquetelen={len(body)} bytes\n")

                    # ---- Procesamiento según tipo ----
                    if tipo == "HELO|":
                        # Mensaje en claro usado para handshake de demostración
                        self.append_text(f"[{addr}] HELO (handshake) recibido (sin cifrar).\n")
                        # Responder con un ACK cifrado y autenticado
                        resp = package_message("ACK_|", b"HELLO_OK", CLAVE_SECRETA, auth=True)
                        conn.sendall(resp)

                    elif tipo == "DATA|":
                        # Mostrar el payload cifrado en formato hexadecimal
                        self.append_text(f"[{addr}] Cifrado (hex): {binascii.hexlify(body).decode()}\n")
                        try:
                            # Verificar tag y descifrar contenido
                            claro = verify_and_decrypt(body, CLAVE_SECRETA)
                            txt = claro.decode(errors="replace")  # decodificar texto descifrado
                            self.append_text(f"[{addr}] Descifrado: {txt}\n\n")
                            # Responder con un ACK cifrado
                            ack = package_message("ACK_|", b"RECEIVED", CLAVE_SECRETA, auth=True)
                            conn.sendall(ack)
                        except ValueError as ve:
                            # Tag inválido o problema en descifrado
                            self.append_text(f"[{addr}] ERROR: {ve}\n")
                            err = package_message("ERR_|", str(ve).encode(), CLAVE_SECRETA, auth=True)
                            conn.sendall(err)

                    elif tipo == "ACK_|":
                        # Cliente envió un ACK, verificar autenticidad y mostrarlo
                        try:
                            claro = verify_and_decrypt(body, CLAVE_SECRETA)
                            txt = claro.decode(errors="replace")
                            self.append_text(f"[{addr}] ACK recibido -> {txt}\n\n")
                        except ValueError as ve:
                            self.append_text(f"[{addr}] ACK con TAG inválido: {ve}\n\n")

                    elif tipo == "ERR_|":
                        # Cliente envió un error, verificar autenticidad
                        try:
                            claro = verify_and_decrypt(body, CLAVE_SECRETA)
                            txt = claro.decode(errors="replace")
                            self.append_text(f"[{addr}] ERR recibido -> {txt}\n\n")
                        except ValueError:
                            self.append_text(f"[{addr}] ERR recibido con TAG inválido.\n\n")

                    else:
                        # Tipo de mensaje no reconocido
                        self.append_text(f"[{addr}] Tipo desconocido: '{tipo}'\n\n")

            except Exception as e:
                # Cualquier excepción en el hilo de cliente se muestra en logs
                self.append_text(f"[{addr}] Excepción en handler: {e}\n\n")


if __name__ == "__main__":
    # Crear la ventana principal y lanzar la aplicación servidor
    root = tk.Tk()
    app = ServidorApp(root)
    root.mainloop()
