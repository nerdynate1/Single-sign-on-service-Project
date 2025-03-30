# Single-sign-on-service-Project
# Project Roles and Contributions

## Nathan's Contributions

Nathan played a pivotal role in the development of the project, focusing on the setup, authentication, and secure communication aspects. Specific contributions include:

- **Repository Setup and Version Control**: Nathan was responsible for establishing the GitHub repository, ensuring it was well-structured for the project. This involved:
    - Creating branches for feature development and maintaining clear commit histories to track changes effectively.
    - Managing the version control processes by enforcing best practices for collaborative workflows, such as feature branching, pull requests, and code reviews to ensure high-quality code integration.

- **Key Distribution Center (KDC) Server Implementation**: A critical aspect of the project was the creation of a KDC server to manage the secure distribution of session keys and service tickets. This involved:
    - Implementing the KDC server with a **Kerberos-style authentication protocol** (based on **RFC 4120**) to securely authenticate users before granting access to the echo service.
    - Setting up a **challenge-response mechanism** to verify the identity of clients, allowing the KDC to issue tickets that were necessary for accessing the echo service in a secure manner.
    - The server generated a **session key** that was securely distributed to clients for encrypted communication with the echo service.

- **Client Authentication and Session Key Distribution**: Nathan worked on ensuring secure communication between the client and the KDC server by facilitating the exchange of session keys. This involved:
    - Designing a process in which the client could securely authenticate with the KDC using a shared secret or password.
    - Ensuring that once authentication was successful, the KDC would issue a **session key** for the client to use for subsequent communication with the echo service.
    - Implementing a **ticket-based mechanism** to allow clients to access the echo service without needing to repeatedly authenticate, providing both security and efficiency.

- **Server-Client Secure Communication**: Nathan was also responsible for setting up the communication flow between the client and the echo service to ensure that all data exchanged was encrypted and verified. This involved:
    - Handling the authentication of the session key to ensure that both the client and the echo service could trust each other’s messages.
    - Ensuring that the client’s messages were encrypted with the session key before being sent to the server and that the server’s responses were also encrypted before being sent back to the client.

## Quetzaly's Contributions

Quetzaly focused on the implementation of the echo service and the encryption/decryption protocols, with a particular emphasis on securing the communication channel. Key contributions include:

- **Echo Service Design and Implementation**: The echo service, which acted as the main point of interaction between the client and the server, was designed and implemented to handle encrypted messages. This service:
    - Was responsible for receiving encrypted messages from the client, processing them, and sending back the appropriate response, which could include functional transformations such as converting messages to uppercase for testing purposes.
    - Integrated robust logging mechanisms to track requests and responses for debugging and verification purposes, ensuring that any issues could be traced to the source.

- **Galois/Counter Mode (GCM) Encryption and Decryption**: A core component of the project was ensuring that the communication was secure. Quetzaly integrated **AES-GCM** encryption and decryption to provide confidentiality, integrity, and authenticity for the messages exchanged between the client and the echo service. This work included:
    - Implementing **AES-GCM encryption**, which not only encrypted the message content but also generated an authentication tag to verify the integrity of the data.
    - Using **random initialization vectors (IVs)** to ensure that each message encryption was unique, preventing replay attacks and ensuring that identical messages did not produce identical ciphertexts.
    - Implementing **AES-GCM decryption** on the server side, ensuring that encrypted messages sent by the client were properly decrypted and that the integrity of the data was validated using the authentication tag.

- **Client Handler and Encryption/Decryption Workflow**: The client handler was developed to manage the interaction between the client and the echo service, with a specific focus on the encryption and decryption process:
    - The handler ensured that client requests were securely encrypted before being sent to the echo service.
    - Upon receiving the encrypted response from the echo service, the handler decrypted the message and displayed it in a user-friendly format, ensuring that the client was interacting with the service in a secure manner.
    - This process involved close integration between the client’s encryption system and the echo service’s decryption system, ensuring seamless communication.

- **Project Management and Coordination**: In addition to technical contributions, Quetzaly played a key role in managing the project’s progress, coordinating efforts between the different components of the system, and ensuring that the project stayed on track. This included:
    - Organizing regular milestones to ensure that both the encryption/decryption functionality and the KDC authentication system were properly implemented and tested.
    - Facilitating communication between team members, ensuring that all components were integrated correctly and that any issues were resolved promptly.
    - Conducting tests and debugging to ensure that the encryption and decryption systems were fully operational and aligned with the project goals of secure communication.

## Conclusion

The project was a collaborative effort with clearly defined roles, leading to the successful implementation of a secure communication system. The contributions of each team member were crucial in ensuring that both the server-side authentication system and the secure encryption/decryption mechanisms worked seamlessly together.

- **Nathan’s contributions** focused on the setup and implementation of the KDC server, managing the session key distribution, and ensuring that the client-server communication was secure.
- **Quetzaly’s contributions** involved the development of the echo service, integrating AES-GCM encryption and decryption to secure messages, and handling the client-server interaction securely.

Together, these efforts culminated in a **Single Sign-On (SSO) service** that utilized encryption to ensure confidentiality, integrity, and authentication in client-server communications, meeting the project’s security goals.