import socket
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext, StringVar, OptionMenu


# Función para recibir mensajes del servidor y mostrarlos en la ventana de chat
def receive_messages(client_socket, chat_window, user_list_var, username):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                raise ConnectionError("Servidor desconectado.")

            # Si el mensaje contiene la lista de usuarios conectados, actualizamos el menú desplegable
            if message.startswith("Usuarios conectados:"):
                users = message.split(": ")[1].split(", ")
                user_list_var.set("")  # Reiniciar la selección de usuarios
                user_menu['menu'].delete(0, 'end')
                user_menu['menu'].add_command(label="", command=tk._setit(user_list_var,
                                                                          ""))  # Opción vacía para no seleccionar a nadie
                for user in users:
                    user_menu['menu'].add_command(label=user, command=tk._setit(user_list_var, user))
            else:
                # Evitamos mostrar el mensaje privado que el propio usuario envió
                if f"(privado a {username})" in message:
                    continue
                # Si el mensaje es del propio usuario, lo mostramos como "Tú"
                if message.startswith(f"{username}:"):
                    message = message.replace(username, "Tú", 1)

                chat_window.config(state=tk.NORMAL)
                chat_window.insert(tk.END, message + '\n')
                chat_window.config(state=tk.DISABLED)
                chat_window.yview(tk.END)
        except ConnectionError as e:
            print(f"Conexión perdida: {e}")
            messagebox.showerror("Error", "Se ha perdido la conexión con el servidor.")
            client_socket.close()
            break
        except Exception as e:
            print(f"Error al recibir mensaje: {e}")
            client_socket.close()
            break


# Función para enviar mensajes (públicos o privados)
def send_message(client_socket, message_entry, chat_window, username, user_list_var):
    message = message_entry.get()
    if message:
        try:
            # Verificamos si es un mensaje privado seleccionando un usuario en el menú desplegable
            recipient = user_list_var.get()
            if recipient and recipient != username:  # Aseguramos que no se envíe a sí mismo
                private_message = f"/private {recipient} {message}"
                client_socket.send(private_message.encode('utf-8'))
                chat_window.config(state=tk.NORMAL)
                chat_window.insert(tk.END, f"Tú (privado a {recipient}): {message}\n")
            else:
                # Mensaje público
                client_socket.send(message.encode('utf-8'))
                chat_window.config(state=tk.NORMAL)
                chat_window.insert(tk.END, f"Tú: {message}\n")

            chat_window.config(state=tk.DISABLED)
            chat_window.yview(tk.END)
            message_entry.delete(0, tk.END)
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")
            messagebox.showerror("Error", "No se pudo enviar el mensaje.")
            client_socket.close()


# Función principal del cliente
def client_program():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(('localhost', 5555))
    except ConnectionRefusedError:
        print("El servidor no está disponible.")
        messagebox.showerror("Error", "No se pudo conectar al servidor.")
        return
    except Exception as e:
        print(f"Error de conexión: {e}")
        return

    # Configurar la ventana principal de Tkinter
    root = tk.Tk()

    # Solicitar el nombre de usuario en una ventana de diálogo
    username = simpledialog.askstring("Nombre de usuario", "Por favor ingresa tu nombre de usuario:", parent=root)
    if not username:
        messagebox.showerror("Error", "Debes ingresar un nombre de usuario para continuar.")
        root.quit()
        return

    # Actualizar el título de la ventana con el nombre del usuario
    root.title(f"Cliente de Chat - {username}")

    # Enviar el nombre de usuario al servidor
    client_socket.send(username.encode('utf-8'))

    # Área de chat (desplazable)
    chat_window = scrolledtext.ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED, width=50, height=20)
    chat_window.pack(padx=10, pady=10)

    # Entrada de texto para los mensajes
    message_entry = tk.Entry(root, width=40)
    message_entry.pack(padx=10, pady=5, side=tk.LEFT)

    # Botón para enviar mensajes
    send_button = tk.Button(root, text="Enviar",
                            command=lambda: send_message(client_socket, message_entry, chat_window, username,
                                                         user_list_var))
    send_button.pack(padx=10, pady=5, side=tk.LEFT)

    # Menú desplegable de usuarios conectados
    user_list_var = StringVar(root)
    user_list_var.set("")  # No seleccionar a ningún usuario por defecto
    global user_menu
    user_menu = OptionMenu(root, user_list_var, "")
    user_menu.pack(padx=10, pady=5)

    # Hilo para manejar la recepción de mensajes y actualización de usuarios
    threading.Thread(target=receive_messages, args=(client_socket, chat_window, user_list_var, username),
                     daemon=True).start()

    # Ejecutar la interfaz gráfica
    root.mainloop()

    # Cerrar el socket al cerrar la ventana
    client_socket.close()


if __name__ == "__main__":
    try:
        client_program()
    except Exception as e:
        print(f"Error al iniciar el cliente: {e}")
