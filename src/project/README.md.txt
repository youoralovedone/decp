# DECP
### Decentralized Encrypted Communications Protocol

DECP is an encrypted decentralized communications protocol.
It aims to provide a secure means of communication with no central point of failure.
At its core, it is a protocol which anyone can use and write a node for but included in the repository is a python node that can handle key generation, keychain management, join requests and message requests.
DECP can also be used symbiotically with existing messaging protocols which is explained further in [symbiosis](##Symbiosis).

 [Github Repository](https://github.com/youoralovedone/decp)
>Installation instructions, source code and protocol documentation can all be found in the repository.
Refer to its README for details.

## Protocol
Each node listens for incoming requests and handles them. Each node is also responsible for distributing requests to every node in the network. This model means there is absolutely NO point of failure anywhere in the network and as long as two nodes are operational, they will be able to communicate. However, this means each node must bear the load of distributing requests to every other node. Detailed documentation for the protocol can be found on the github page.

##  Node implementation
The included python node/library uses a threaded socket server to listen for requests.
The keychain is stored as an SQL database for fast and easy access.
Source code and a v1.0 release for the python library is available on the github page.

## Security
DECP uses a combination of bit AES, SHA and RSA to secure and sign its messages.
First, a message is encrypted with a randomly generated AES key and initialization vector. The key is then encrypted with the recipient's RSA public key. Then signed with SHA and the sender's RSA private key. The encrypted message, encrypted key, initialization vector and signature are then sent.
>v1.0 and 1.1 currently use 256 bit keys for AES, 2048 bit keys for RSA and SHA-224
>Join requests in v1.0 and 1.1 are not secured.

## Symbiosis
The DECP protocol can be used to encrypt messages without distributing them and provided the sender and recipient  have securely exchanged keys, the encrypted message can be sent on any unencrypted service (or even dumped onto pastebin) securely and decrypted by the recipient.
