import socket
import threading
import time

# Lista para gestionar los clientes conectados y sus nombres de usuario
clients = []      # Sockets de los clientes conectados
usernames = []    # Nombres de usuario correspondientes

# Variable global para rastrear transferencias de archivos
file_transfers = {}  # Clave: cliente remitente, Valor: cliente destinatario

def broadcast(message, sender_client=None, recipient=None, is_file=False):
    """
    Propaga mensajes a los destinatarios apropiados.

    Parámetros:
    - message: El mensaje a enviar.
    - sender_client: El socket del cliente que envía el mensaje.
    - recipient: El nombre de usuario del destinatario (para mensajes privados).
    - is_file: Indica si el mensaje es un archivo.
    """
    if recipient:
        if recipient in usernames:
            recipient_client = clients[usernames.index(recipient)]
            sender_username = usernames[clients.index(sender_client)]
            try:
                if is_file:
                    # Enviar comando de inicio de archivo al destinatario
                    recipient_client.send(message.encode('utf-8'))
                    # Agregar a file_transfers para rastrear la transferencia
                    file_transfers[sender_client] = recipient_client
                    file_transfers[recipient_client] = sender_client
                else:
                    # Enviar mensaje privado sin modificar (permite encriptación de extremo a extremo)
                    recipient_client.send(f"/private {sender_username} {message}".encode('utf-8'))
            except Exception as e:
                print(f"Error al enviar mensaje privado: {e}")
                remove_client(sender_client)
                remove_client(recipient_client)
        else:
            try:
                sender_client.send(f"El usuario {recipient} no está disponible.".encode('utf-8'))
            except Exception as e:
                print(f"Error al notificar al remitente sobre usuario no disponible: {e}")
    else:
        # Mensaje público: enviar a todos los clientes conectados
        for client in clients:
            try:
                client.send(message.encode('utf-8'))
            except Exception as e:
                print(f"Error al enviar mensaje público: {e}")
                remove_client(client)

def handle_client(client):
    """
    Maneja la comunicación con un cliente específico.

    Parámetros:
    - client: El socket del cliente.
    """
    try:
        index = clients.index(client)
        username = usernames[index]  # Obtener el nombre de usuario asociado al cliente

        while True:
            try:
                message = client.recv(4096)
                if not message:
                    # Si no se recibe mensaje, el cliente se ha desconectado
                    break

                # Decodificar el mensaje solo si es texto
                try:
                    message_decoded = message.decode('utf-8')
                except UnicodeDecodeError:
                    # Si no se puede decodificar, es posible que sean datos binarios (archivo)
                    message_decoded = None

                if message_decoded:
                    # Procesar mensajes de texto
                    if message_decoded.startswith("/private"):
                        parts = message_decoded.split(" ", 2)  # /private <destinatario> <mensaje>
                        if len(parts) < 3:
                            client.send("Formato incorrecto para mensaje privado.".encode('utf-8'))
                            continue
                        recipient = parts[1]
                        private_message = parts[2]
                        # Enviar mensaje privado
                        broadcast(private_message, client, recipient)
                    elif message_decoded.startswith("/file"):
                        # Manejar envío de archivo
                        parts = message_decoded.split(" ", 3)  # /file <destinatario> <nombre_archivo_codificado> <tamaño_archivo>
                        if len(parts) < 4:
                            client.send("Formato incorrecto para enviar archivo.".encode('utf-8'))
                            continue
                        recipient = parts[1]
                        file_name_encoded = parts[2]
                        file_size = parts[3]
                        # Reconstruir el mensaje para reenviarlo al destinatario
                        message_to_send = f"/file {username} {file_name_encoded} {file_size}"
                        # Notificar al destinatario que recibirá un archivo
                        broadcast(message_to_send, client, recipient, is_file=True)
                    else:
                        # Mensaje público
                        public_message = f"{username}: {message_decoded}"
                        broadcast(public_message)
                else:
                    # Datos binarios (posiblemente archivo)
                    # Si estamos en medio de una transferencia de archivo, reenviar los datos
                    if client in file_transfers:
                        recipient_client = file_transfers[client]
                        try:
                            recipient_client.send(message)
                        except Exception as e:
                            print(f"Error al reenviar datos del archivo: {e}")
                            remove_client(client)
                            remove_client(recipient_client)
                            break
                        if message == b'EOF':
                            # Transferencia de archivo terminada
                            del file_transfers[client]
                            del file_transfers[recipient_client]
                    else:
                        # Datos inesperados, ignorar o manejar según sea necesario
                        pass
            except Exception as e:
                print(f"Error al recibir mensaje de {username}: {e}")
                break
    except Exception as e:
        print(f"Error en handle_client: {e}")
    finally:
        # Al salir del bucle, eliminar al cliente
        remove_client(client)

def remove_client(client):
    """
    Remueve un cliente de las listas y notifica a los demás.

    Parámetros:
    - client: El socket del cliente a remover.
    """
    try:
        if client in clients:
            index = clients.index(client)
            client.close()
            username = usernames[index]
            del clients[index]
            del usernames[index]
            print(f"Cliente {username} desconectado.")
            broadcast(f"[SERVER]: {username} ha dejado el chat")
    except Exception as e:
        print(f"Error al remover cliente: {e}")

def server_program():
    """
    Función principal del servidor.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Permitir reutilizar la dirección y el puerto
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('localhost', 5555))
        server.listen()
        print("Servidor iniciado. Esperando conexiones...")

        while True:
            try:
                client, address = server.accept()
                print(f"Conexión establecida con {address}")

                # Recibir y agregar el nombre de usuario del cliente
                username = client.recv(1024).decode('utf-8')
                if username in usernames:
                    client.send("El nombre de usuario ya está en uso. Por favor elige otro.".encode('utf-8'))
                    client.close()
                    continue
                else:
                    client.send("OK".encode('utf-8'))  # Confirmación al cliente

                usernames.append(username)
                clients.append(client)
                print(f"Usuario {username} conectado")
                broadcast(f"[SERVER]: {username} se ha unido al chat")

                # Iniciar un hilo para manejar al cliente
                thread = threading.Thread(target=handle_client, args=(client,))
                thread.start()
            except Exception as e:
                print(f"Error al aceptar conexiones: {e}")
    except Exception as e:
        print(f"Error en el servidor: {e}")
    finally:
        server.close()

def update_users():
    """
    Actualiza la lista de usuarios conectados cada 5 segundos.
    """
    while True:
        time.sleep(5)
        try:
            user_list = ", ".join(usernames)
            broadcast(f"Usuarios conectados: {user_list}")
        except Exception as e:
            print(f"Error al actualizar lista de usuarios: {e}")

if __name__ == "__main__":
    try:
        # Iniciar hilos para el servidor y la actualización de usuarios
        server_thread = threading.Thread(target=server_program)
        update_thread = threading.Thread(target=update_users)

        server_thread.start()
        update_thread.start()
    except Exception as e:
        print(f"Error al iniciar el servidor: {e}")
