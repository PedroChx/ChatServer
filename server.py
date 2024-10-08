import socket
import threading
import time

clients = []  # Lista para gestionar los clientes conectados
usernames = []  # Lista para almacenar nombres de usuario


# Función para propagar mensajes a los destinatarios apropiados
def broadcast(message, sender_client, recipient=None):
    if recipient:
        # Mensaje privado: solo enviar al destinatario y al remitente
        recipient_client = clients[usernames.index(recipient)]
        try:
            sender_client.send(message)  # Enviar al remitente (para confirmación)
            recipient_client.send(message)  # Enviar al destinatario
        except Exception as e:
            print(f"Error al enviar mensaje privado: {e}")
            remove_client(sender_client)
            remove_client(recipient_client)
    else:
        # Mensaje público: enviar a todos los clientes excepto al remitente
        for client in clients:
            if client != sender_client:
                try:
                    client.send(message)
                except Exception as e:
                    print(f"Error al enviar mensaje público: {e}")
                    remove_client(client)


# Función para manejar a cada cliente individualmente
def handle_client(client):
    try:
        index = clients.index(client)
        username = usernames[index]  # Obtenemos el nombre de usuario asociado

        while True:
            try:
                message = client.recv(1024).decode('utf-8')
                if not message:
                    break
                # Verificar si es un mensaje privado
                if message.startswith("/private"):
                    parts = message.split(" ", 2)  # /private <destinatario> <mensaje>
                    recipient = parts[1]
                    private_message = f"{username} (privado): {parts[2]}".encode('utf-8')
                    broadcast(private_message, client, recipient)
                else:
                    # Mensaje público
                    public_message = f"{username}: {message}".encode('utf-8')
                    broadcast(public_message, client)
            except ConnectionResetError:
                print(f"El cliente {username} ha cerrado la conexión inesperadamente.")
                break
            except Exception as e:
                print(f"Error al recibir mensaje de {username}: {e}")
                break
    finally:
        # Eliminar el cliente en caso de error o desconexión
        remove_client(client)


# Función para remover clientes desconectados o con errores
def remove_client(client):
    try:
        index = clients.index(client)
        clients.remove(client)
        client.close()
        username = usernames[index]
        usernames.remove(username)
        print(f"Cliente {username} desconectado.")
        broadcast(f"{username} ha dejado el chat.".encode('utf-8'), client)
    except Exception as e:
        print(f"Error al remover cliente: {e}")


# Función principal del servidor
def server_program():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
                usernames.append(username)
                clients.append(client)
                print(f"Usuario {username} conectado")
                broadcast(f"{username} se ha unido al chat".encode('utf-8'), client)

                thread = threading.Thread(target=handle_client, args=(client,))
                thread.start()
            except Exception as e:
                print(f"Error al aceptar conexión: {e}")
    except Exception as e:
        print(f"Error en el servidor: {e}")
    finally:
        server.close()


# Función para actualizar lista de usuarios cada 30 segundos
def update_users():
    while True:
        time.sleep(30)
        try:
            user_list = ", ".join(usernames)
            broadcast(f"Usuarios conectados: {user_list}".encode('utf-8'), None)
        except Exception as e:
            print(f"Error al actualizar lista de usuarios: {e}")


if __name__ == "__main__":
    try:
        server_thread = threading.Thread(target=server_program)
        update_thread = threading.Thread(target=update_users)

        server_thread.start()
        update_thread.start()
    except Exception as e:
        print(f"Error al iniciar el servidor: {e}")
