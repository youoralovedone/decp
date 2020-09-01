from src.v4.decp_node import decp_node
import time


def main():
    node = decp_node()
    while True:
        message = input()
        if message == "/EXIT":
            node.stop_server()
            break

        node.send_message(message)


if __name__ == "__main__":
    main()
