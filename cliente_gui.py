"""
cliente_gui.py

Cliente con interfaz gráfica que:
- Cifra mensajes (tipo "DATA") con tag HMAC y los envía al servidor.
- Permite enviar mensajes "HELO" (handshake simple) sin cifrado (solo para demo).
- Muestra en pantalla: 
    • mensaje claro escrito por el usuario
    • payload cifrado (ciphertext + tag en hexadecimal)
    • paquete completo enviado (tipo + payload en hexadecimal)
- Recibe la respuesta del servidor, la procesa y la muestra.
"""

import socket
import binascii
import tkinter as tk
from tkinter import scrolledtext
# Importamos funciones del módulo de cifrado
from cifrado import package_message, parse_message, verify_and_decrypt, CLAVE_SECRETA

# -------------------------
# CONFIGURACIÓN DEL CLIENTE
# -------------------------
HOST = "127.0.0.1"     # Dirección del servidor (localhost en este caso)
PUERTO = 9000          # Puerto en el que escucha el servidor
RECV_TIMEOUT = 1.5     # Tiempo máximo de espera para recibir respuesta (segundos)


# -------------------------
# CLASE PRINCIPAL DE LA APP
# -------------------------
class ClienteApp:
    def __init__(self, root):
        """
        Inicializa la interfaz gráfica del cliente.
        - Ventana principal con área de texto de historial.
        - Campo de entrada para escribir mensajes.
        - Botones para enviar DATA (cifrado) y HELO (sin cifrar).
        """
        self.root = root
        self.root.title("Cliente de Mensajes")
        self.root.geometry("700x550")

        # Área de texto con scroll para mostrar la comunicación
        self.texto = scrolledtext.ScrolledText(root, wrap="word", width=90, height=28)
        self.texto.pack(padx=10, pady=10)

        # Frame inferior con campo de entrada y botones
        frame = tk.Frame(root)
        frame.pack(pady=5)
        self.entrada = tk.Entry(frame, width=60)
        self.entrada.pack(side="left", padx=5)
        tk.Button(frame, text="Enviar DATA", command=self.enviar_data).pack(side="left", padx=5)
        tk.Button(frame, text="Enviar HELO", command=self.enviar_helo).pack(side="left", padx=5)

    def append(self, texto: str):
        """
        Inserta texto en el área de historial y hace scroll hacia el final.
        """
        self.texto.insert("end", texto)
        self.texto.see("end")

    # -------------------------
    # MÉTODO: ENVIAR MENSAJE DATA
    # -------------------------
    def enviar_data(self):
        """
        Cifra y envía un mensaje tipo DATA:
        1. Toma el texto ingresado en la caja de entrada.
        2. Lo empaqueta con cifrado y tag HMAC.
        3. Lo envía al servidor mediante socket TCP.
        4. Intenta recibir y procesar la respuesta.
        5. Muestra en pantalla mensaje claro, payload cifrado y paquete enviado.
        """
        mensaje = self.entrada.get()
        if not mensaje:
            return

        # Construimos paquete con autenticación (ciphertext + tag)
        paquete = package_message("DATA|", mensaje.encode(), CLAVE_SECRETA, auth=True)

        # Extraemos solo el payload (ciphertext+tag) y el paquete completo
        payload = paquete[5:]  # después de los 5 bytes de tipo
        payload_hex = binascii.hexlify(payload).decode()
        paquete_hex = binascii.hexlify(paquete).decode()

        # Conectar con el servidor y enviar
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(RECV_TIMEOUT)  # límite de espera para respuesta
                s.connect((HOST, PUERTO))
                s.sendall(paquete)
                # Intentar recibir respuesta
                try:
                    resp = s.recv(8192)  # buffer grande por si acaso
                    if resp:
                        self._procesar_respuesta(resp)
                except socket.timeout:
                    # Si no responde en el tiempo límite, ignoramos
                    pass
        except Exception as e:
            self.append(f"[!] Error enviando: {e}\n")

        # Mostrar en cliente el resultado
        self.append(f"Mensaje claro: {mensaje}\n")
        self.append(f"Payload (ciphertext+tag) hex: {payload_hex}\n")
        self.append(f"Paquete enviado (tipo+payload) hex: {paquete_hex}\n\n")
        self.entrada.delete(0, "end")  # limpiar entrada

    # -------------------------
    # MÉTODO: ENVIAR MENSAJE HELO
    # -------------------------
    def enviar_helo(self):
        """
        Envía un mensaje tipo HELO sin cifrar (solo para demostración de handshake).
        1. Empaqueta el mensaje con auth=False (sin cifrar).
        2. Lo envía al servidor por socket.
        3. Procesa la respuesta si la hay.
        """
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

        # Mostrar en cliente el HELO enviado
        self.append(f"Enviado HELO (sin cifrar). Paquete hex: {paquete_hex}\n\n")

    # -------------------------
    # PROCESAR RESPUESTA DEL SERVIDOR
    # -------------------------
    def _procesar_respuesta(self, resp: bytes):
        """
        Procesa respuestas recibidas del servidor.
        - Usa parse_message para separar tipo y cuerpo.
        - Si tipo = ACK_| o ERR_| → intenta verificar y descifrar el body.
        - Si falla la verificación de integridad → muestra error.
        - Si es otro tipo → solo muestra tipo y longitud.
        """
        try:
            tipo, body = parse_message(resp)
        except Exception as e:
            self.append(f"[Resp] paquete inválido: {e}\n")
            return

        tipo = tipo.strip()  # limpiar espacios
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
            # Para otros tipos de mensajes o si vienen sin cifrado
            self.append(f"[Servidor] Respuesta tipo={tipo} len={len(body)} bytes\n\n")


# -------------------------
# INICIO DE LA APLICACIÓN
# -------------------------
if __name__ == "__main__":
    # Crear ventana principal de Tkinter y lanzar la aplicación
    root = tk.Tk()
    app = ClienteApp(root)
    root.mainloop()
