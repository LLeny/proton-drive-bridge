# Proton Drive Bridge

A FTP server bridge for Proton Drive, built on top of [libunftp](https://github.com/bolcom/libunftp), allowing you to access your Proton Drive files using any FTP client. 

**Note**: This software was built empirically, and different account settings or unknown parameters may trigger unplanned behaviors. Use with caution and report any issues you encounter.

**Note**: Currently supports single Proton account access only - multi-user drive support is not yet implemented.

> ⚠️ **IMPORTANT DISCLAIMER**: This is NOT an official Proton application. This is a third-party project not affiliated with or endorsed by Proton AG. Use this 
software at your own risk. The developers are not responsible for any data loss, security issues, or other problems that may arise from using this software. Always ensure you understand the security implications before entering your Proton credentials.

## Features

- Secure access to Proton Drive via HTTPS
- Support for 2FA authentication
- **Supported FTP Commands**:
  - `LS` - List directory contents
  - `MKD` - Make directory
  - `RMD` - Remove directory
  - `RM` - Delete file
  - `MV` - Rename file/directory
  - `GET` - Download file
  - `PUT` - Upload file

## Prerequisites

- Rust (latest stable version recommended)
- Docker (for containerized deployment)
- Proton account

## Building from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/LLeny/proton-drive-bridge.git
   cd proton-drive-bridge
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

The binary will be available at `target/release/proton-drive-bridge`

## Usage

### Command Line

```bash
./target/release/proton-drive-bridge [OPTIONS]
```

#### Options:
- `-u, --username <USERNAME>`: Proton account email (or set `PROTON_USERNAME` environment variable)
- `-p, --password <PASSWORD>`: Proton account password (or set `PROTON_PASSWORD` environment variable)
- `--auth-file <AUTH_FILE>`: Path to JSON file containing user credentials (default: "users.json")
- `--bind <BIND>`: IP address to bind to (default: 0.0.0.0)
- `--port <PORT>`: Port to listen on (default: 2121)
- `--greeting <GREETING>`: Server greeting message
- `--tls`: Enable FTPS (requires certificate and key)
- `--cert <CERT>`: Path to certificate file (PEM format, required with --tls)
- `--key <KEY>`: Path to private key file (PEM format, required with --tls)

### Example

```bash
./target/release/proton-drive-bridge -u ftpusername --port 2121
```

## User Authentication

The server uses JSON-based authentication. By default, it looks for a `users.json` file in the current directory.

### users.json Format

Default credentials (username: `user`, password: `mypassword`):

```json
[
  {
    "username": "user",
    "pbkdf2_salt": "Nq8roLd6+Tw=",
    "pbkdf2_key": "jlfERENxed6K3QuTB9tVIaR/Brrx780sYUuNP8uvVcY=",
    "pbkdf2_iter": 500000
  }
]
```

> **Security Note**: The default credentials are for testing only. Please change the password before deploying to production.

### Password Hashing

Passwords must be PBKDF2 encoded. You can generate a password using:

```bash
salt=$(dd if=/dev/random bs=1 count=8)
echo -n "mypassword" | nettle-pbkdf2 -i 500000 -l 32 --hex-salt $(echo -n $salt | xxd -p -c 80) --raw |openssl base64 -A
echo -n $salt | openssl base64 -A
```

Details in the unftp_auth_jsonfile documentation: https://docs.rs/unftp-auth-jsonfile/0.3.6/unftp_auth_jsonfile/

### Command Line

Specify a custom users file:
```bash
./target/release/proton-drive-bridge --auth-file /path/to/users.json
```

### Environment Variables

- `PROTON_USERNAME`: Your Proton account email
- `PROTON_PASSWORD`: Your Proton account password

## Security Notes

- The bridge requires your Proton credentials to function - ensure you trust the environment where you run it

## License

This project is licensed under the [GPLv3 License](LICENSE).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
