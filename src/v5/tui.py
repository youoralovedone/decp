from src.v5.decp_node import decp_node
import threading

def main():
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
            except IndexError as e:
                continue

    message_thread = threading.Thread(target=start_message_thread)
    message_thread.start()

    while True:
        message = input()
        if message == "/exit":
            node.stop()
            break

        node.send_message(message)


if __name__ == "__main__":
    main()
