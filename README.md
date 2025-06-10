# OpenMLS Client-Server Messaging System

A secure group messaging application built with Rust using the OpenMLS protocol. Provides end-to-end encryption with forward secrecy and post-compromise security for group communications.

## Security Architecture

- **End-to-end encryption**: All messages encrypted by clients before transmission
- **Zero-knowledge server**: Server cannot decrypt or read message content
- **MLS protocol**: Standards-compliant Message Layer Security implementation
- **Client-managed keys**: All cryptographic operations performed client-side

## Features

- **End-to-End Encrypted Group Messaging**: Secure group communication using MLS protocol
- **Key Package Management**: Automatic generation and distribution of cryptographic key packages
- **Group Lifecycle Management**: Create, join, and leave groups with proper MLS protocol handling
- **Welcome Message Protocol**: Proper onboarding of new group members using MLS Welcome messages
- **Ratchet Tree Synchronization**: Maintains cryptographic state consistency across group members
- **Epoch Key Management**: Saves previous epoch keys to decrypt messages from before group changes
- **Persistent Storage**: Client state and cryptographic material persistence

## Components

### Server
HTTP REST API that manages groups and stores encrypted messages. Handles group membership and message routing without access to plaintext content.

### Client
Command-line interface with MLS encryption capabilities. Manages cryptographic keys and performs all encryption/decryption operations locally.

## Prerequisites

- Rust 1.70 or later
- Cargo package manager

## Quick Start

### 1. Start the Server

```bash
cargo run --bin openmls-server
```

Server runs on `http://127.0.0.1:8080` by default.

### 2. Run Clients

Start clients in separate terminals:

```bash
# Terminal 1
cargo run --bin openmls-client -- --client-id alice

# Terminal 2
cargo run --bin openmls-client -- --client-id bob
```

### 3. Basic Operations

```
create "team-chat"          # Create a group
list                        # List available groups
join "team-chat"            # Join a group
send "team-chat" Hello!     # Send a message
messages "team-chat"        # View messages
add "team-chat" charlie     # Add member to group
leave "team-chat"           # Leave a group
quit                        # Exit
```

## Configuration

### Server Configuration

```bash
# Default settings
cargo run --bin openmls-server

# Custom host and port
cargo run --bin openmls-server -- --host 0.0.0.0 --port 9090

# Custom data directory
cargo run --bin openmls-server -- --data-dir ./server-data
```

### Client Configuration

```bash
# Interactive mode
cargo run --bin openmls-client -- --client-id alice

# Custom server and data directory
cargo run --bin openmls-client -- --client-id bob --server-url http://localhost:9090 --data-dir ./client-data
```

## Commands

### Interactive Mode Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `create <name>` | Create a new group |
| `list` | List all groups |
| `join <group-name>` | Join a group |
| `add <group-name> <user-id>` | Add member to group |
| `leave <group-name>` | Leave a group |
| `send <group-name> <message>` | Send a message |
| `messages <group-name>` | View group messages |
| `upload-key` | Upload new key package |
| `reset` | Reset client state |
| `quit` | Exit the application |

## Data Storage

The application maintains persistent storage across restarts.

### Server Storage (`./data/server/`)
```
data/server/
├── groups.json              # Group metadata
├── messages/                # Encrypted messages per group
│   └── {group-uuid}.json
├── key_packages/            # Client key packages
│   └── {client-id}.json
├── welcome/                 # Welcome messages
│   └── {group-uuid}.json
└── ratchet-tree/           # MLS ratchet trees
    └── {group-uuid}.json
```

### Client Storage (`./data/{client-id}/`)
```
data/{client-id}/
├── state.json              # MLS client state
├── key_package.json        # Client's key package
└── cache/                  # Temporary data
    └── *.json
```

## Encryption Verification

To verify end-to-end encryption, inspect server message storage:

```bash
cat ./data/server/messages/{group-uuid}.json
```

Messages are stored as encrypted byte arrays:
```json
[
  {
    "id": "msg-uuid",
    "group_id": "group-uuid",
    "sender": "alice",
    "encrypted_content": [69,78,67,82,89,80,84,69,68,...],
    "timestamp": "2024-01-01T12:00:00Z"
  }
]
```

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/groups` | List groups |
| POST | `/groups` | Create group |
| GET | `/groups/{id}` | Get group details |
| POST | `/groups/{id}/join` | Join group |
| POST | `/groups/{id}/leave` | Leave group |
| GET | `/groups/{id}/messages` | Get messages |
| POST | `/groups/{id}/messages` | Send message |
| POST | `/key_packages` | Upload key package |
| GET | `/key_packages/{client_id}` | Get key package |
| POST | `/welcome/{group_id}` | Store welcome message |
| GET | `/welcome/{group_id}` | Get welcome message |
| POST | `/ratchet-tree/{group_id}` | Store ratchet tree |
| GET | `/ratchet-tree/{group_id}` | Get ratchet tree |

## Building

### Development Build
```bash
cargo build
```

### Release Build
```bash
cargo build --release
```

### Component-Specific Builds
```bash
# Server only
cargo build --bin openmls-server --release

# Client only
cargo build --bin openmls-client --release
```

## Development

### Debug Logging
```bash
RUST_LOG=debug cargo run --bin openmls-server
RUST_LOG=debug cargo run --bin openmls-client
```

### Testing
```bash
cargo test
```

## Troubleshooting

### Common Issues

- **Connection refused**: Verify server is running on the expected host/port
- **Permission denied**: Check file permissions in data directories
- **Decryption errors**: Ensure all clients are using compatible MLS state
- **Group join failures**: Verify group exists and proper key packages are uploaded

### Fresh Start
To start with clean state:
```bash
rm -rf ./data/
```

## License

MIT License 

## Comprehensive Epoch Key Management

### Problem
In MLS, when group membership changes (users are added or removed), the protocol advances to a new "epoch" with new encryption keys. Messages encrypted in previous epochs cannot be decrypted with current keys, leading to permanently undecryptable messages.

### Solution
This implementation provides **comprehensive historical message decryption guarantees**:

#### Core Principles
- **No action should affect previous messages**: Users can always decrypt messages they previously had access to
- **Permanent access**: Users retain decryption capability even after being removed from groups or if groups are reset
- **Comprehensive coverage**: Keys are saved automatically in all scenarios where the user has access

#### Automatic Key Preservation
1. **Before Group Changes**: Keys are saved before any commit that advances epochs
2. **During Message Decryption**: Keys are saved whenever a message is successfully decrypted
3. **On Group Creation**: Initial epoch keys are saved when creating groups
4. **On Group Joining**: Keys are saved when successfully joining groups via Welcome messages
5. **Before Group Reset**: Current keys are preserved even during state resets

#### Permanent Storage & Retention
- **Never Auto-Delete**: Epoch keys are never automatically removed
- **Survives Group Departure**: Keys are preserved even when leaving groups
- **Survives Group Reset**: Keys remain available even after resetting group state
- **Cross-Group Support**: Comprehensive decryption attempts across all stored keys

### Usage
The epoch key management is completely automatic and provides strong guarantees:

```bash
# All scenarios preserve historical decryption capability
client1> send mygroup "Message 1"
client2> add mygroup client3        # Epoch advances - client1 can still read "Message 1"
client1> leave mygroup              # client1 can STILL decrypt all previous messages
client1> messages mygroup           # Still shows all historical messages

# Even after group resets
client2> reset mygroup              # Group state reset
client1> messages mygroup           # Historical messages still decryptable
```

### New Commands
```bash
epochs                   # Show all stored epoch keys for historical decryption  
decryption-stats         # Show comprehensive decryption capability statistics
```

### Implementation Details

- **EpochKey Structure**: Contains epoch number, application secret, and timestamp
- **Permanent Storage**: Epoch keys stored indefinitely per-group in JSON format
- **Multi-Strategy Decryption**: Attempts multiple decryption methods with historical keys
- **Comprehensive Fallback**: Tries all available keys across all groups if needed
- **Security**: Keys stored locally only, never transmitted over network

## Architecture

```
┌─────────────────┐    HTTP/JSON    ┌─────────────────┐
│   MLS Client    │◄──────────────►│   MLS Server    │
│                 │                 │                 │
│ ┌─────────────┐ │                 │ ┌─────────────┐ │
│ │  Crypto     │ │                 │ │  Message    │ │
│ │  Provider   │ │                 │ │  Relay      │ │
│ └─────────────┘ │                 │ └─────────────┘ │
│ ┌─────────────┐ │                 │ ┌─────────────┐ │
│ │ Persistence │ │                 │ │ Persistence │ │
│ │ Manager     │ │                 │ │ Manager     │ │
│ └─────────────┘ │                 │ └─────────────┘ │
│ ┌─────────────┐ │                 │                 │
│ │ Epoch Key   │ │                 │                 │
│ │ Storage     │ │                 │                 │
│ └─────────────┘ │                 │                 │
└─────────────────┘                 └─────────────────┘
``` 