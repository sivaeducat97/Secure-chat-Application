import base64
import json
import socket
import threading

from auth import (
    authenticate_user,
    register_user
)


HOST = "127.0.0.1"
PORT = 5000


clients = {}

public_keys = {}

lock = threading.Lock()


def send_json(sock, data):

    message = json.dumps(data) + "\n"

    sock.sendall(
        message.encode("utf-8")
    )


def send_to_user(username, data):

    with lock:
        sock = clients.get(username)

    if sock:

        try:
            send_json(sock, data)

        except OSError:
            pass


def broadcast_peer_list():

    with lock:

        peers = [
            {
                "username": username,
                "public_key": public_keys[username]
            }

            for username in clients
        ]

        sockets = list(
            clients.values()
        )

    packet = {
        "type": "peers",
        "peers": peers
    }

    for sock in sockets:

        try:
            send_json(sock, packet)

        except OSError:
            pass


def handle_client(
    conn,
    address
):

    username = None

    reader = conn.makefile(
        "r",
        encoding="utf-8"
    )

    try:

        first = reader.readline()

        if not first:
            return

        hello = json.loads(first)

        if hello.get("type") != "auth":

            send_json(
                conn,
                {
                    "type": "auth_result",
                    "ok": False,
                    "message": "Invalid authentication request."
                }
            )

            return

        action = hello.get("action")

        username = hello.get(
            "username",
            ""
        ).strip()

        password = hello.get(
            "password",
            ""
        )

        public_key = hello.get(
            "public_key",
            ""
        )

        # Registration

        if action == "register":

            ok, message = register_user(
                username,
                password
            )

            if not ok:

                send_json(
                    conn,
                    {
                        "type": "auth_result",
                        "ok": False,
                        "message": message
                    }
                )

                return

        # Login

        elif action == "login":

            if not authenticate_user(
                username,
                password
            ):

                send_json(
                    conn,
                    {
                        "type": "auth_result",
                        "ok": False,
                        "message": "Invalid username or password."
                    }
                )

                return

        else:

            send_json(
                conn,
                {
                    "type": "auth_result",
                    "ok": False,
                    "message": "Unknown authentication action."
                }
            )

            return

        # Validate username/public key

        if not username or not public_key:

            send_json(
                conn,
                {
                    "type": "auth_result",
                    "ok": False,
                    "message": "Username and public key are required."
                }
            )

            return

        try:

            base64.b64decode(
                public_key,
                validate=True
            )

        except Exception:

            send_json(
                conn,
                {
                    "type": "auth_result",
                    "ok": False,
                    "message": "Invalid public key."
                }
            )

            return

        # Add user

        with lock:

            if username in clients:

                send_json(
                    conn,
                    {
                        "type": "auth_result",
                        "ok": False,
                        "message": "User is already logged in."
                    }
                )

                return

            clients[username] = conn

            public_keys[username] = public_key

        send_json(
            conn,
            {
                "type": "auth_result",
                "ok": True,
                "message": "Authentication successful.",
                "username": username
            }
        )

        broadcast_peer_list()

        print(
            f"[+] {username} connected from {address}"
        )

        # Chat messages

        for line in reader:

            if not line:
                break

            packet = json.loads(line)

            packet_type = packet.get(
                "type"
            )

            if packet_type == "message":

                recipient = packet.get(
                    "to"
                )

                ciphertext = packet.get(
                    "ciphertext"
                )

                if not recipient or not ciphertext:
                    continue

                with lock:

                    recipient_exists = (
                        recipient in clients
                    )

                if recipient_exists:

                    # Server only forwards ciphertext.
                    # Server never decrypts messages.

                    send_to_user(
                        recipient,
                        {
                            "type": "message",
                            "from": username,
                            "ciphertext": ciphertext
                        }
                    )

            elif packet_type == "get_peers":

                broadcast_peer_list()

    except (
        ConnectionResetError,
        BrokenPipeError,
        json.JSONDecodeError
    ):

        pass

    finally:

        with lock:

            if (
                username
                and clients.get(username) is conn
            ):

                clients.pop(
                    username,
                    None
                )

                public_keys.pop(
                    username,
                    None
                )

        try:
            reader.close()
        except Exception:
            pass

        try:
            conn.close()
        except Exception:
            pass

        if username:

            print(
                f"[-] {username} disconnected"
            )

            broadcast_peer_list()


def start_server():

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind(
        (HOST, PORT)
    )

    server.listen(20)

    print("=" * 60)
    print("SECURE CHAT SERVER")
    print("=" * 60)
    print(
        f"Listening on {HOST}:{PORT}"
    )
    print(
        "Waiting for clients..."
    )
    print(
        "Press Ctrl+C to stop."
    )

    try:

        while True:

            conn, address = server.accept()

            thread = threading.Thread(
                target=handle_client,
                args=(conn, address),
                daemon=True
            )

            thread.start()

    except KeyboardInterrupt:

        print(
            "\nServer stopped."
        )

    finally:

        server.close()


if __name__ == "__main__":

    start_server()