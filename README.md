# Distributed File System

A distributed file system implementation with a Name Server and multiple Storage Servers supporting concurrent file operations, access control, and streaming capabilities.

## Components

1. **Name Server (NS)**: Central coordinator that manages file metadata, user access, and storage server assignments
2. **Storage Server (SS)**: Handles actual file storage and operations
3. **Client**: User interface for interacting with the system

## Building the System

```bash
# Clean previous builds
make clean

# Build all components
make all
```

## Running the System

### 1. Start the Name Server

```bash
./nameserver <port>

# Example:
./nameserver 8000
```

### 2. Start Storage Server(s)

```bash
./storageserver <nm_ip> <nm_port> <client_port> <storage_path>

# Example:
mkdir -p storage1
./storageserver 127.0.0.1 8000 9001 storage1/

# For multiple storage servers, use different ports and paths:
mkdir -p storage2
./storageserver 127.0.0.1 8000 9002 storage2/-
```

### 3. Start Client(s)

```bash
./client <nm_ip> <nm_port>

# Example:
./client 127.0.0.1 8000
```

## Client Commands

1. **VIEW [-a] [-l]**: View files
   - `-a`: Show all files
   - `-l`: Show detailed list
   - `-al`: Show detailed list of all files

2. **READ <file>**: Read file contents

3. **CREATE <file>**: Create new file

4. **WRITE <file> <sentence#>**: Write to file
   - Enter updates in format: `<word_index> <content>`
   - Type `ETIRW` to finish writing

5. **UNDO <file>**: Undo last change to file

6. **INFO <file>**: Get file information

7. **DELETE <file>**: Delete file

8. **STREAM <file>**: Stream file contents word by word

9. **LIST**: List all connected users

10. **Access Control**:
    - `ADDACCESS -R/-W <file> <user>`: Add read/write access
    - `REMACCESS <file> <user>`: Remove access

11. **EXEC <file>**: Execute file contents as commands

## System Features

1. **Concurrent Access**: Multiple users can access files simultaneously
2. **Access Control**: Owner-based file permissions
3. **File Operations**: Create, read, write, delete, stream
4. **Sentence-Level Locking**: Prevents conflicts during concurrent writes
5. **Automatic Load Balancing**: Distributes files across storage servers
6. **Fault Tolerance**: Handles server disconnections and reconnections
7. **File Streaming**: Word-by-word file streaming support
8. **Command Execution**: Execute file contents as commands
9. **Cache Management**: Efficient file metadata caching
10. **Timeout Handling**: Automatic cleanup of stale locks and connections

## Persistence

- Name Server persists file metadata (owner and access control lists) to `metadata.dat`.
- On startup, the Name Server loads persisted metadata and reconciles it with the live file lists it receives from Storage Servers. Newly discovered files (present on SS but not in metadata) are added with default metadata; existing files retain their owner/ACL across restarts.
- Storage Servers persist file contents on disk in their respective storage folders.

Notes:
- If the Name Server is restarted, restart Storage Servers as well so they re-register and send their file lists, allowing the NM to reconcile with the persisted metadata.
- Files pre-existing on Storage Servers before metadata persistence was introduced will appear without an owner until created via the NM or updated in metadata.

## Implementation Details

### Threading and Concurrency
- Thread-safe file operations
- Mutex-protected shared resources
- Condition variables for synchronization
- Periodic cleanup of stale resources
- Lock timeouts to prevent deadlocks

### Network Communication
- TCP/IP-based communication
- Keep-alive connections
- Connection timeouts
- Automatic reconnection
- Error recovery

### File Management
- Sentence-level granularity
- Word-based updates
- Backup and undo support
- Access control lists
- File metadata tracking

## Error Handling

The system handles various error conditions:
1. Network errors
2. File access permission errors
3. Invalid commands
4. Resource limitations
5. Server disconnections
6. Concurrent access conflicts
7. File system errors

## Assumptions and Limitations

1. Maximum file size: Limited by MAX_BUFFER * 10
2. Maximum number of files: Limited by MAX_FILES
3. Maximum number of users per file: Limited by MAX_ACCESS_USERS
4. Maximum filename length: Limited by MAX_FILENAME
5. Network connectivity: Assumes reliable TCP/IP network
6. File operations: Text files only
7. Storage: Files stored in local filesystem
8. User authentication: Simple username-based

## Debugging

For debugging, the system generates logs with:
- Timestamps
- Component identification (NS/SS/Client)
- Error codes and messages
- Connection information
- Operation tracking

## Known Issues and Workarounds

1. **Long write operations**: Break into smaller chunks
2. **Network timeouts**: Adjust timeout values in code
3. **Stale locks**: Wait for automatic cleanup or restart server
4. **Connection issues**: Check network and retry
5. **Memory usage**: Monitor and adjust MAX_* constants

## Future Improvements

1. Enhanced security with user authentication
2. Encrypted communication
3. File replication for redundancy
4. Binary file support
5. Distributed transaction support
6. Better recovery mechanisms
7. Web-based interface
8. Performance monitoring
9. Automated backup
10. Dynamic load balancing