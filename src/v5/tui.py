from src.v5.decp_node import decp_node


def main():
    node = decp_node()
    while True:
        message = input()
        if message == "/EXIT":
            node.stop()
            break

        node.send_message(message)


if __name__ == "__main__":
    main()
