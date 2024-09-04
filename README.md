> [!CAUTION]
> This project is still in pre-alpha stage and everything is just a proposal. The code is NOT functional in its current state.

# Nerdlock - E2EE chat application

## Introduction

Nerdlock is a robust E2EE chat application built using the [MLS](https://messaginglayersecurity.rocks/) protocol. It is designed to provide a secure and private communication channel for users to exchange messages, files, and other data.

It can handle small and large group sizes, which makes it perfect for group chats, video calls, and other real-time communication scenarios.

Nerdlock strives to be compliant with MLS 1.0 specification and will make sure to adhere to the latest standards and best practices as they become available. It is recommended for people looking for a secure and private communication platform without compromising on features (Nerdlock's features are heavily inspired by Discord).

Nerdlock supports the following features:
* Basic text messaging, including markdown support.
* Multimedia messaging, including file sharing with preview support for images and videos.
* Direct messaging between two users.
* Group messaging with extensive permissions and moderation features, and organizational support, including channels and roles.
* Real-time voice and video chat including screen sharing over WebRTC.

## Project Structure

The project is structured as follows:
* `/src/client`: This directory contains the source code for the Nerdlock client application.
  * `/src/client/mls`: This directory contains the source code for the MLS protocol implementation.
  * `/src/client/nerdclient`: This directory contains the source code for the Nerdlock client, which uses the MLS protocol implementation to handle the encryption and decryption of messages.
  * `/src/client/app`: This directory contains the source code for the Nerdlock frontend app.
* `src/server/as`: This directory contains the source code for the Nerdlock Authentication Service (AS), which is responsible for handling user authentication and authorization.
* `src/server/ds`: This directory contains the source code for the Nerdlock Delivery Service (DS), which is responsible for handling message delivery and storage.

## Getting Started

To build the project, you need to have [Bun](https://bun.sh) installed on your system.

To install dependencies:

```bash
bun install
```

To execute a full build:

```bash
$ bash build.sh
```