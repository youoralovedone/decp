from src.v6.decp_node import decp_node
import threading
import requests


def main():
    # print(f"starting listening server thread on {requests.get('https://ip.42.pl/raw').text} port 3623...")
    # print("starting request handler thread...")
    node = decp_node()
    message_thread_stopped = False

    def start_message_thread():
        while True:
            if message_thread_stopped:
                break
            try:
                message_dict = node.message_queue.pop()
                status = "[signature matches]" if message_dict["signed"] else "[WARNING SIGNATURE DOES NOT MATCH]"
                print(status, message_dict["sender_nick"], ":", message_dict["message"])
            except IndexError:
                continue

    # print("starting frontend message handler thread...")
    message_thread = threading.Thread(target=start_message_thread)
    message_thread.start()

    while True:
        while not node.server_ready:
            continue
        message = input()
        if message == "/exit":
            node.stop()
            message_thread_stopped = True
            break
        elif message == "/add":
            # /add <nick> <public key> <ips comma separated>
            args = message.split(" ") # move above scope
            node.add(args[1], args[2], args[3].split(","))
        elif message == "/join":
            node.send_join(True)

        node.send_message(message)


if __name__ == "__main__":
    main()
