# OpenMLS Client-Server Application

A secure messaging system built with Rust using the OpenMLS protocol for Message Layer Security (MLS). This application provides end-to-end encryption for group messaging with forward secrecy and post-compromise security.

## Features

- **OpenMLS Protocol**: Implements the Message Layer Security (MLS) standard
- **Group Messaging**: Create and manage secure group conversations
- **CLI Interface**: Interactive command-line interface for the client
- **REST API**: HTTP-based server for group and message management
- **Key Management**: Automatic key package generation and distribution
- **Real-time Communication**: Send and receive messages in groups

## Architecture

The application consists of two main components:

1. **Server** (`server/`): HTTP REST API server that manages groups, messages, and key packages
2. **Client** (`client/`): CLI application that communicates with the server

## Prerequisites

- Rust 1.70+ (latest stable recommended)
- Cargo (comes with Rust)

## Quick Start Demo

### 1. Start the Server

First, start the server in one terminal:

```bash
cargo run -p openmls-server
```

The server will start on `http://127.0.0.1:8080` by default.

### 2. Run the Client

In another terminal, start a client:

```bash
cargo run -p openmls-client -- --client-id alice
```

### 3. Interactive Commands

In the interactive mode, you can use these commands:

```
help                     - Show available commands
create "My Group"        - Create a new group
list                     - List all groups
join <group_id>          - Join a group
send <group_id> Hello!   - Send a message
messages <group_id>      - View messages
leave <group_id>         - Leave a group
upload-key               - Upload new key package
quit                     - Exit
```

### 4. Multi-Client Testing

To test with multiple clients, run each with different client IDs:

```bash
# Terminal 1
cargo run -p openmls-client -- --client-id alice

# Terminal 2
cargo run -p openmls-client -- --client-id bob

# Terminal 3
cargo run -p openmls-client -- --client-id charlie
```

### 5. Example Workflow

1. Alice creates a group
2. Bob and Charlie join the group
3. All participants can send and receive messages

### 6. Command-Line Mode

You can also use command-line mode for scripting:

```bash
cargo run -p openmls-client -- --client-id alice create-group "Test Group"
cargo run -p openmls-client -- --client-id alice list-groups
```

## Building

To build the entire workspace:

```bash
cargo build --release
```

To build individual components:

```bash
# Build server
cargo build --release -p openmls-server

# Build client
cargo build --release -p openmls-client
```

## Detailed Usage

### Server

```bash
# Run from the workspace root
cargo run -p openmls-server

# Or from the server directory
cd server
cargo run
```

### Client Options

#### Interactive Mode (Default)

```bash
# Run from the workspace root
cargo run -p openmls-client

# Or with custom client ID
cargo run -p openmls-client -- --client-id "alice"

# Or with custom server URL
cargo run -p openmls-client -- --server-url "http://localhost:8080"
```

#### Command Line Mode

You can also run individual commands directly:

```bash
# Create a group
cargo run -p openmls-client -- create-group "My Group"

# List all groups
cargo run -p openmls-client -- list-groups

# Join a group (replace with actual group ID)
cargo run -p openmls-client -- join-group "123e4567-e89b-12d3-a456-426614174000"

# Send a message
cargo run -p openmls-client -- send-message "123e4567-e89b-12d3-a456-426614174000" "Hello, world!"

# Get messages from a group
cargo run -p openmls-client -- get-messages "123e4567-e89b-12d3-a456-426614174000"

# Upload key package
cargo run -p openmls-client -- upload-key-package
```

## API Endpoints

The server exposes the following REST API endpoints:

- `GET /health` - Health check
- `GET /groups` - List all groups
- `POST /groups` - Create a new group
- `GET /groups/{id}` - Get group details
- `POST /groups/{id}/join` - Join a group
- `POST /groups/{id}/leave` - Leave a group
- `GET /groups/{id}/messages` - Get group messages
- `POST /groups/{id}/messages` - Send a message to group
- `POST /key_packages` - Upload a key package
- `GET /key_packages/{client_id}` - Get key package for client

## Security Features

The system uses OpenMLS for end-to-end encryption with:

- **Forward Secrecy**: Past messages remain secure even if keys are compromised
- **Post-Compromise Security**: Future messages are secure after key compromise
- **Message Authentication**: Verification of message authenticity and integrity
- **Automatic Key Rotation**: Seamless key updates for enhanced security
- **Group Key Management**: Secure member addition and removal

## Development

To run in development mode with logging:

```bash
RUST_LOG=debug cargo run -p openmls-server
RUST_LOG=debug cargo run -p openmls-client
```

## Troubleshooting

- Ensure the server is running before starting any clients
- Each client should have a unique client ID
- Check that the server URL is correct if using custom configuration
- Use `RUST_LOG=debug` for detailed logging when debugging issues

## License

This project is open source and available under the MIT License. 