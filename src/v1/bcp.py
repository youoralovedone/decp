# messages can be sent with post requests formatted as such: {"author":"<author>", "message":"<message>"}
# member list formatted as: <local ip>\n<local ip>\n ...

# TODO: cute curses frontend
# TODO: commands for post requests
#   - add member, adds a member to the member list and sends a copy of member list to requested
# TODO: easy connect, add member request get on port 9001 on all machines connected to lan
# TODO: connect generates members.txt
# TODO: e2e encryption, look into rsa https://ctf101.org/cryptography/what-is-rsa/
# TODO: encapsulate bcpServer into seperate module
# TODO: function for commands like send, connect, exit or get ip

# http://99.76.226.255

from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
from threading import Thread
import json
import socket
# make sure the normies pip install these
import requests

ip = "localhost"
port = 8000
name = "null"
# must create a member list before running
members = open("members.txt", "r")
log = open(".NSA_AGENTS_LOOK_HERE.log", "w+")


class bcpServer(BaseHTTPRequestHandler):
    def do_POST(self):
        global name
        # updates message_log with contents of message

        content_length = int(self.headers["Content-Length"])
        raw = self.rfile.read(content_length)
        parsed = json.loads(raw.decode("utf-8"))

        # required for response to be recognized as valid
        self.send_response(200)
        self.end_headers()

        response = BytesIO()
        log.write("[RECEIVED] AUTHOR " + parsed["author"] + " SENT \"" + parsed["message"] + "\"\n")

        print(parsed["author"] + ": " + parsed["message"])
        response.write(b"[SENT] message received by recipient " + name.encode("UTF-8"))

        # wfile output stream for response to client
        self.wfile.write(response.getvalue())

    def log_message(self, format, *args):
        # silence do_POST

        return


server_instance = HTTPServer((ip, port), bcpServer)


def send_message():
    while True:
        message = input()
        if message == "/EXIT":
            server_instance.shutdown()
            break
        if message == "/IP":
            print(ip)
            continue

        for member in members:
            # print(member)
            reply = requests.post(member, json={"author": name, "message": message})
            log.write(reply.text + "\n")

        members.seek(0)


def start_server():
    print("[OK] server started")
    server_instance.serve_forever()


def main():
    # threading is absolute magic
    # https://www.shanelynn.ie/using-python-threading-for-multiple-results-queue/

    threads = []
    server_process = Thread(target=start_server)
    server_process.daemon = True
    server_process.start()
    threads.append(server_process)

    message_process = Thread(target=send_message)
    message_process.start()
    threads.append(message_process)

    for process in threads:
        process.join()

    log.close()


if __name__ == "__main__":
    main()