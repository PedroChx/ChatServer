import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext, StringVar, OptionMenu, messagebox, filedialog
import os
from pathlib import Path
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Diccionario para almacenar las ventanas de chat privado abiertas y los mensajes
private_chats = {}

# Lista de colores y diccionario de asignación de colores a usuarios
user_colors = ['red', 'green', 'blue', 'orange', 'magenta', 'cyan', 'brown', 'teal']
user_color_mapping = {}

# Clave y IV para encriptación AES (16 bytes cada uno para AES-128)
encryption_key = b'my_secret_key_123'  # Clave de 16 bytes
iv = b'initialvector123'  # IV de 16 bytes

# Asegurarse de que la clave y el IV tengan exactamente 16 bytes
encryption_key = encryption_key[:16]
iv = iv[:16]

# Variables globales para manejar la recepción de archivos
receiving_file = False
file_sender = None
file_size = 0
file_received = 0
file_path = None
file = None

# Funciones para encriptar y desencriptar mensajes
def encrypt_message(message):
    """
    Encripta un mensaje de texto utilizando AES en modo CBC.

    Parámetros:
    - message: El mensaje de texto a encriptar.

    Retorna:
    - El mensaje encriptado en bytes.
    """
    backend = default_backend()
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    # Padding del mensaje
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted

def decrypt_message(encrypted_message):
    """
    Desencripta un mensaje encriptado utilizando AES en modo CBC.

    Parámetros:
    - encrypted_message: El mensaje encriptado en bytes.

    Retorna:
    - El mensaje de texto desencriptado.
    """
    backend = default_backend()
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_message) + decryptor.finalize()
    # Remover padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode('utf-8')

def open_private_chat(recipient, client_socket, username):
    """
    Abre o enfoca una ventana de chat privado con un usuario específico.

    Parámetros:
    - recipient: Nombre de usuario del destinatario.
    - client_socket: Socket del cliente.
    - username: Nombre de usuario propio.

    Retorna:
    - La ventana de chat privado creada o enfocada.
    """
    # Verificar si el chat ya existe y si la ventana está abierta
    if recipient in private_chats and "window" in private_chats[recipient]:
        # Enfocar la ventana existente
        private_window = private_chats[recipient]["window"]
        private_window.deiconify()  # Traer la ventana al frente si ya está abierta
        return private_window

    # Si no existe, crear una nueva ventana para el chat privado
    private_window = tk.Toplevel()
    private_window.title(f"Chat privado con {recipient}")  # Título único

    # Área de texto para mostrar los mensajes del chat privado
    private_chat_window = scrolledtext.ScrolledText(private_window, wrap=tk.WORD, state=tk.DISABLED, width=50, height=20)
    private_chat_window.pack(padx=10, pady=10)

    # Mostrar mensajes anteriores si existen
    if recipient not in private_chats:
        private_chats[recipient] = {"messages": []}
    else:
        # Mostrar mensajes anteriores
        private_chat_window.config(state=tk.NORMAL)
        for msg in private_chats[recipient]["messages"]:
            private_chat_window.insert(tk.END, msg)
        private_chat_window.config(state=tk.DISABLED)
        private_chat_window.yview(tk.END)

    # Entrada para escribir mensajes privados
    private_message_entry = tk.Text(private_window, width=40, height=3)
    private_message_entry.pack(padx=10, pady=5, side=tk.LEFT)

    def send_private_message():
        """
        Envía un mensaje privado encriptado al destinatario.
        """
        message = private_message_entry.get("1.0", tk.END).strip()
        if message:
            try:
                # Encriptar el mensaje
                encrypted_message = encrypt_message(message)
                # Codificar en base64 para enviar como texto
                encoded_message = base64.b64encode(encrypted_message).decode('utf-8')
                # Enviar mensaje al servidor
                private_message = f"/private {recipient} {encoded_message}"
                client_socket.send(private_message.encode('utf-8'))
                private_message_entry.delete("1.0", tk.END)
                # Mostrar mensaje en la ventana propia
                private_chat_window.config(state=tk.NORMAL)
                private_chat_window.insert(tk.END, f"Tú (privado): {message}\n")
                private_chat_window.config(state=tk.DISABLED)
                private_chat_window.yview(tk.END)
                # Almacenar el mensaje
                private_chats[recipient]["messages"].append(f"Tú (privado): {message}\n")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo enviar el mensaje: {e}")

    # Botón para enviar mensajes privados
    send_button = tk.Button(private_window, text="Enviar", command=send_private_message)
    send_button.pack(padx=5, pady=5, side=tk.LEFT)

    def send_file():
        """
        Envía un archivo al destinatario.
        """
        file_path_to_send = filedialog.askopenfilename()
        if file_path_to_send:
            try:
                file_size_to_send = os.path.getsize(file_path_to_send)
                if file_size_to_send > 50 * 1024 * 1024:
                    messagebox.showerror("Error", "El archivo supera los 50 MB.")
                    return
                file_name_to_send = os.path.basename(file_path_to_send)
                # Codificar el nombre del archivo en Base64
                file_name_encoded = base64.b64encode(file_name_to_send.encode('utf-8')).decode('utf-8')
                # Enviar comando de inicio de archivo
                file_command = f"/file {recipient} {file_name_encoded} {file_size_to_send}"
                client_socket.send(file_command.encode('utf-8'))
                # Enviar el archivo en binario
                with open(file_path_to_send, 'rb') as f:
                    while True:
                        bytes_read = f.read(4096)
                        if not bytes_read:
                            # Enviar señal de fin de archivo
                            client_socket.send(b'EOF')
                            break
                        client_socket.send(bytes_read)
                # Informar al usuario
                private_chat_window.config(state=tk.NORMAL)
                private_chat_window.insert(tk.END, f"Tú has enviado el archivo {file_name_to_send}\n")
                private_chat_window.config(state=tk.DISABLED)
                private_chat_window.yview(tk.END)
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo enviar el archivo: {e}")

    # Botón para enviar archivos
    file_button = tk.Button(private_window, text="Enviar Archivo", command=send_file)
    file_button.pack(padx=5, pady=5, side=tk.LEFT)

    # Almacenar referencias de la ventana y área de texto en el diccionario
    private_chats[recipient]["window"] = private_window
    private_chats[recipient]["chat_window"] = private_chat_window

    def on_closing():
        """
        Maneja el evento de cierre de la ventana de chat privado.
        """
        private_window.destroy()
        if recipient in private_chats:
            if "window" in private_chats[recipient]:
                del private_chats[recipient]["window"]
            if "chat_window" in private_chats[recipient]:
                del private_chats[recipient]["chat_window"]

    private_window.protocol("WM_DELETE_WINDOW", on_closing)

    # Función para manejar la tecla ENTER y SHIFT+ENTER
    def on_enter_pressed(event):
        if event.state & 0x0001:  # Verifica si Shift está presionado
            private_message_entry.insert(tk.INSERT, '\n')
        else:
            send_private_message()
            return "break"  # Previene que se agregue una nueva línea

    private_message_entry.bind("<Return>", on_enter_pressed)

    return private_window

def receive_messages(client_socket, chat_window, username):
    """
    Maneja la recepción de mensajes desde el servidor.

    Parámetros:
    - client_socket: Socket del cliente.
    - chat_window: Área de texto para el chat grupal.
    - username: Nombre de usuario propio.
    """
    # Configurar etiquetas para estilos de texto
    chat_window.tag_configure('server', foreground='purple')
    chat_window.tag_configure('you', foreground='black')

    global receiving_file, file_sender, file_size, file_received, file_path, file

    while True:
        try:
            if not receiving_file:
                message = client_socket.recv(4096)
                if not message:
                    raise ConnectionError("Servidor desconectado.")
                message_decoded = message.decode('utf-8')

                # Manejo de mensajes privados y de archivos
                if message_decoded.startswith("/file"):
                    # Inicio de recepción de archivo
                    parts = message_decoded.split(" ", 3)  # /file {remitente} {nombre_archivo_codificado} {tamaño_archivo}
                    if len(parts) < 4:
                        print("Error: Formato incorrecto de /file")
                        continue
                    sender = parts[1]
                    file_name_encoded = parts[2]
                    file_size = int(parts[3])
                    # Decodificar el nombre del archivo desde Base64
                    file_name = base64.b64decode(file_name_encoded).decode('utf-8')
                    file_received = 0  # Reiniciar contador de bytes recibidos

                    if sender not in private_chats:
                        private_chats[sender] = {"messages": []}
                        open_private_chat(sender, client_socket, username)

                    private_chat_window = private_chats[sender]["chat_window"]
                    private_chat_window.config(state=tk.NORMAL)
                    private_chat_window.insert(tk.END, f"{sender} está enviando el archivo {file_name} ({file_size} bytes)\n")
                    private_chat_window.config(state=tk.DISABLED)
                    private_chat_window.yview(tk.END)

                    # Crear el directorio "Files" si no existe
                    files_dir = Path('Files')
                    files_dir.mkdir(exist_ok=True)

                    # Ruta completa del archivo
                    file_path = files_dir / f"recibido_{file_name}"

                    # Abrir archivo para escribir datos binarios
                    file = open(file_path, 'wb')

                    # Cambiar el estado a recibiendo archivo
                    receiving_file = True
                    file_sender = sender
                elif message_decoded.startswith("/private"):
                    # Mensaje privado recibido
                    parts = message_decoded.split(" ", 2)
                    sender = parts[1]
                    encrypted_content = parts[2]
                    try:
                        # Decodificar de base64 y desencriptar
                        encrypted_bytes = base64.b64decode(encrypted_content)
                        decrypted_message = decrypt_message(encrypted_bytes)
                    except Exception as e:
                        print(f"Error al desencriptar mensaje: {e}")
                        continue

                    if sender not in private_chats:
                        private_chats[sender] = {"messages": []}

                    # Almacenar el mensaje
                    private_chats[sender]["messages"].append(f"{sender} (privado): {decrypted_message}\n")

                    # Mostrar el mensaje si la ventana está abierta
                    if "chat_window" in private_chats[sender]:
                        private_chat_window = private_chats[sender]["chat_window"]
                        private_chat_window.config(state=tk.NORMAL)
                        private_chat_window.insert(tk.END, f"{sender} (privado): {decrypted_message}\n")
                        private_chat_window.config(state=tk.DISABLED)
                        private_chat_window.yview(tk.END)
                    else:
                        # Si la ventana no está abierta, abrirla
                        open_private_chat(sender, client_socket, username)

                elif message_decoded.startswith("Usuarios conectados:"):
                    # Actualizar la lista de usuarios conectados
                    users = message_decoded.split(": ")[1].split(", ")
                    user_list_var.set("Usuarios")  # Mostrar "Usuarios" por defecto
                    user_menu['menu'].delete(0, 'end')  # Limpiar el menú actual
                    user_menu['menu'].add_command(label="Usuarios", command=tk._setit(user_list_var, "Usuarios"))
                    for user in users:
                        if user != username:
                            user_menu['menu'].add_command(label=user, command=tk._setit(user_list_var, user))
                elif message_decoded.startswith("[SERVER]:"):
                    # Mensaje del servidor en morado
                    chat_window.config(state=tk.NORMAL)
                    chat_window.insert(tk.END, message_decoded + '\n', 'server')
                    chat_window.config(state=tk.DISABLED)
                    chat_window.yview(tk.END)
                elif "no está disponible" in message_decoded:
                    # Mostrar el mensaje en el chat grupal
                    chat_window.config(state=tk.NORMAL)
                    chat_window.insert(tk.END, message_decoded + '\n', 'server')
                    chat_window.config(state=tk.DISABLED)
                    chat_window.yview(tk.END)
                else:
                    # Mensajes grupales
                    if ':' in message_decoded:
                        sender_username, msg_content = message_decoded.split(':', 1)
                        sender_username = sender_username.strip()
                        msg_content = msg_content.strip()
                    else:
                        sender_username = ''
                        msg_content = message_decoded.strip()

                    if sender_username == username:
                        display_username = "Tú"
                        sender_tag = 'you'
                    else:
                        display_username = sender_username
                        # Asignar un color al usuario si no tiene uno
                        if sender_username not in user_color_mapping:
                            color = user_colors[len(user_color_mapping) % len(user_colors)]
                            user_color_mapping[sender_username] = color
                            # Configurar una nueva etiqueta para este usuario
                            chat_window.tag_configure('username_' + sender_username, foreground=color)
                        sender_tag = 'username_' + sender_username

                    # Insertar el mensaje con el nombre de usuario y el color asignado
                    chat_window.config(state=tk.NORMAL)
                    chat_window.insert(tk.END, f"{display_username}: ", sender_tag)
                    chat_window.insert(tk.END, msg_content + '\n')
                    chat_window.config(state=tk.DISABLED)
                    chat_window.yview(tk.END)
            else:
                # Recibiendo datos del archivo
                data = client_socket.recv(4096)
                if not data:
                    raise ConnectionError("Se perdió la conexión durante la recepción del archivo.")
                if data == b'EOF':
                    # Final de archivo recibido
                    file.close()
                    receiving_file = False
                    # Informar al usuario
                    private_chat_window = private_chats[file_sender]["chat_window"]
                    private_chat_window.config(state=tk.NORMAL)
                    private_chat_window.insert(tk.END, f"Archivo recibido: {file_path.name}\n")
                    private_chat_window.config(state=tk.DISABLED)
                    private_chat_window.yview(tk.END)
                    # Almacenar el mensaje
                    private_chats[file_sender]["messages"].append(f"Has recibido el archivo {file_path.name} de {file_sender}\n")
                else:
                    # Escribir datos en el archivo
                    file.write(data)
                    file_received += len(data)
        except ConnectionError as e:
            messagebox.showerror("Error", f"Se ha perdido la conexión con el servidor.")
            client_socket.close()
            break
        except Exception as e:
            print(f"Error al recibir mensaje: {e}")
            client_socket.close()
            break

def send_message(client_socket, message_entry, chat_window):
    """
    Envía un mensaje público desde la ventana principal.

    Parámetros:
    - client_socket: Socket del cliente.
    - message_entry: Campo de entrada de texto.
    - chat_window: Área de texto del chat grupal.
    """
    message = message_entry.get("1.0", tk.END).strip()
    if message:
        try:
            # Siempre envía mensajes públicos desde la ventana principal
            client_socket.send(message.encode('utf-8'))
            message_entry.delete("1.0", tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo enviar el mensaje: {e}")

def on_enter_pressed(event, send_function):
    """
    Maneja la tecla ENTER y SHIFT+ENTER en los campos de entrada.

    Parámetros:
    - event: Evento de tecla presionada.
    - send_function: Función a llamar para enviar el mensaje.
    """
    if event.state & 0x0001:  # Verifica si Shift está presionado
        return
    else:
        send_function()
        return "break"  # Previene que se agregue una nueva línea

def client_program():
    """
    Función principal del cliente.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(('localhost', 5555))
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo conectar al servidor: {e}")
        return

    root = tk.Tk()
    username = simpledialog.askstring("Nombre de usuario", "Por favor ingresa tu nombre de usuario:", parent=root)
    if not username:
        messagebox.showerror("Error", "Debes ingresar un nombre de usuario para continuar.")
        root.quit()
        return

    root.title(f"Cliente de Chat - {username}")
    try:
        client_socket.send(username.encode('utf-8'))

        # Esperar confirmación del servidor
        response = client_socket.recv(1024).decode('utf-8')
        if response != "OK":
            messagebox.showerror("Error", response)
            client_socket.close()
            root.quit()
            return
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo enviar el nombre de usuario: {e}")
        client_socket.close()
        root.quit()
        return

    # Área de texto para mensajes grupales
    chat_window = scrolledtext.ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED, width=50, height=20)
    chat_window.pack(padx=10, pady=10)

    # Entrada de texto para enviar mensajes
    message_entry = tk.Text(root, width=40, height=3)
    message_entry.pack(padx=10, pady=5, side=tk.LEFT)

    def send_public_message():
        send_message(client_socket, message_entry, chat_window)

    # Asociar la tecla ENTER y SHIFT+ENTER
    message_entry.bind("<Return>", lambda event: on_enter_pressed(event, send_public_message))

    send_button = tk.Button(root, text="Enviar", command=send_public_message)
    send_button.pack(padx=5, pady=5, side=tk.LEFT)

    # Menú desplegable para seleccionar usuarios conectados
    global user_list_var, user_menu
    user_list_var = StringVar(root)
    user_list_var.set("Usuarios")  # Mostrar "Usuarios" por defecto
    user_menu = OptionMenu(root, user_list_var, "Usuarios")
    user_menu.pack(padx=5, pady=5, side=tk.LEFT)

    def on_user_selected(*args):
        selected_user = user_list_var.get()
        if selected_user and selected_user != "Usuarios":
            open_private_chat(selected_user, client_socket, username)
            user_list_var.set("Usuarios")  # Restablecer el menú a "Usuarios"

    user_list_var.trace("w", on_user_selected)

    # Hilo para manejar la recepción de mensajes
    threading.Thread(target=receive_messages, args=(client_socket, chat_window, username), daemon=True).start()

    def on_closing():
        """
        Maneja el evento de cierre de la ventana principal del cliente.
        """
        try:
            client_socket.close()
        except Exception as e:
            print(f"Error al cerrar el socket: {e}")
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    root.mainloop()

if __name__ == "__main__":
    client_program()
