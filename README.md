# Proton Drive Bridge

A FTP server bridge for Proton Drive, built on top of [libunftp](https://github.com/bolcom/libunftp), allowing you to access your Proton Drive files using any FTP client. 

**Note**: This software was built empirically, and different account settings or unknown parameters may trigger unplanned behaviors. Use with caution and report any issues you encounter.

**Note**: Currently supports single Proton account access only - multi-user drive support is not yet implemented.

> ⚠️ **IMPORTANT DISCLAIMER**: This is NOT an official Proton application. This is a third-party project not affiliated with or endorsed by Proton AG. Use this 
software at your own risk. The developers are not responsible for any data loss, security issues, or other problems that may arise from using this software. Always ensure you understand the security implications before entering your Proton credentials.

---

## FTP Client Recommendations

For best results:
- **Use only one thread** in your FTP client (disable parallel transfers).
- **Set the command timeout** to a sufficiently long period to avoid disconnects during large operations.

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
- Proton Drive Photos share mapped

## Usage

### Command Line

```bash
proton-drive-bridge --cli [OPTIONS]
```

#### Options:
- `-u, --username <USERNAME>`: Proton account email (or set `PROTON_USERNAME` environment variable)
- `-p, --password <PASSWORD>`: Proton account password (or set `PROTON_PASSWORD` environment variable)
- `--auth-file <AUTH_FILE>`: Path to JSON file containing user credentials (default: "users.json")
- `--port <PORT>`: Port to listen on (default: 2121)
- `--greeting <GREETING>`: Server greeting message
- `--tls`: Enable FTPS (requires certificate and key)
- `--cert <CERT>`: Path to certificate file (PEM format, required with --tls)
- `--key <KEY>`: Path to private key file (PEM format, required with --tls)
- `-c, --cli`: Run in CLI mode (no UI). Short form `-c` is accepted.
- `--sessionpassword <SESSION_PASSWORD>`: Bridge session password (or set `PROTON_SESSION_PASSWORD` environment variable)
- `--workercount <WORKER_COUNT>`: Number of upload/download workers (default: 4)
- `--passiveports <PORT_RANGE>`: Passive mode port range (default: 49000-49100)

Notes:
- In CLI mode, if `--username/--password` (or `PROTON_USERNAME/PROTON_PASSWORD`) are not provided, you will be prompted interactively on stdin.
- If `--sessionpassword` (or `PROTON_SESSION_PASSWORD`) is provided, it will be used to unlock the bridge session vault without prompting.
- When using `--tls`, both `--cert` and `--key` must be provided.

### Example

```bash
proton-drive-bridge --cli -u ftpusername --port 2121
```

With environment variables:

```bash
PROTON_USERNAME=you@example.com PROTON_PASSWORD='yourpass' proton-drive-bridge --cli --port 2121
```

### Bridge Session Password (CLI)

When running with `--cli`, the application maintains a local encrypted "bridge session" vault so you don’t have to re-enter your Proton username/password every time:

- On first run, you will be prompted to create a bridge session password. This password is used to derive a salted key that encrypts your local session vault (which stores access/refresh tokens and session data). The input is hidden (no echo).
- On subsequent runs, you’ll be prompted only for this bridge session password (hidden). The app will unlock the vault and refresh your Proton tokens automatically. If refresh fails, it falls back to a full login and updates the vault.
- To reset the saved session, delete the key from your OS keyring and/or remove the app’s config file (location depends on your OS), then run again to create a new session.

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
proton-drive-bridge --cli --auth-file /path/to/users.json
```

### Environment Variables

- `PROTON_USERNAME`: Your Proton account email
- `PROTON_PASSWORD`: Your Proton account password
- `PROTON_SESSION_PASSWORD`: Bridge session password (used to unlock the local session vault)

## Proton Drive Photos Share

- The Proton Drive Photos share is available under the `/drive_photos` directory.
- Any folder you create inside `/drive_photos` will appear as an **album** in Proton Drive.
- **Albums cannot be nested:** You cannot create albums inside other albums (only one level of albums is supported).
- When you upload a photo to an album, it will **also be uploaded to `/drive_photos`**.
- When you delete a photo from an album, it will **also be deleted from `/drive_photos`**.

## Building from Source

### Prerequisites

- Rust (latest stable version recommended)
- Go


Clone the repository:
   ```bash
   git clone https://github.com/LLeny/proton-drive-bridge.git
   cd proton-drive-bridge
   ```

Build the project:
   ```bash
   cargo build --release
   ```

The binary will be available at `target/release/proton-drive-bridge`

## Security Notes

- The bridge requires your Proton credentials to function - ensure you trust the environment where you run it

## License

This project is licensed under the [GPLv3 License](LICENSE).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
