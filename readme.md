# Distributed File System (Docs++)

A simplified distributed document system similar to Google Docs, with support for concurrency and access control.

## Features

### Core Functionalities
- **File Operations**: Create, Read, Write, Delete files
- **View Files**: List files with various filters (-a for all, -l for details)
- **Concurrency**: Multiple clients can access files simultaneously
- **Access Control**: Owner-based permissions with read/write access
- **Streaming**: Stream file content word-by-word
- **Execute**: Execute file content as shell commands
- **Undo**: Revert last file modification
- **User Management**: List all registered users
- **Efficient Search**: Trie-based file lookup with O(k) complexity
- **Caching**: LRU cache for frequently accessed files
- **Logging**: Comprehensive logging for all operations

### System Architecture
- **Name Server (NM)**: Central coordinator managing file metadata and routing
- **Storage Servers (SS)**: Handle file storage and operations
- **Clients**: User interface for file operations

## Compilation

```bash
make clean
make all
```

This will create three executables:
- `nameserver` - Name server
- `storageserver` - Storage server
- `client` - Client application

## Usage

### 1. Start Name Server

```bash
./nameserver <port>
```

Example:
```bash
./nameserver 8000
```

### 2. Start Storage Server(s)

```bash
./storageserver <nm_ip> <nm_port> <client_port> <storage_path>
```

Example:
```bash
./storageserver 127.0.0.1 8000 9001 ./storage1
./storageserver 127.0.0.1 8000 9002 ./storage2
```

You can start multiple storage servers for load distribution.

### 3. Start Client(s)

```bash
./client <nm_ip> <nm_port>
```

Example:
```bash
./client 127.0.0.1 8000
```

When prompted, enter your username.

## Client Commands

### View Files
```bash
VIEW            # Lists files you have access to
VIEW -a         # Lists all files on the system
VIEW -l         # Lists your files with details (word count, char count, etc.)
VIEW -al        # Lists all files with details
```

### Create File
```bash
CREATE <filename>
```

### Read File
```bash
READ <filename>
```

### Write to File
```bash
WRITE <filename> <sentence_number>
# Then enter updates in format: <word_index> <content>
# Type ETIRW when done
```

Example:
```bash
WRITE test.txt 0
0 Hello
1 World
ETIRW
```

### Undo Last Change
```bash
UNDO <filename>
```

### File Information
```bash
INFO <filename>
```

### Delete File
```bash
DELETE <filename>
```

### Stream File
```bash
STREAM <filename>
```

### List Users
```bash
LIST
```

### Access Control
```bash
ADDACCESS -R <filename> <username>   # Add read access
ADDACCESS -W <filename> <username>   # Add write access
REMACCESS <filename> <username>      # Remove access
```

### Execute File
```bash
EXEC <filename>
```

## File Format

Files contain sentences separated by delimiters (`.`, `!`, `?`). Sentences contain words separated by spaces.

Example file content:
```
Hello world. How are you? I am fine!
```

This is parsed as 3 sentences:
1. "Hello world."
2. "How are you?"
3. "I am fine!"

## Concurrency

- Multiple clients can read a file simultaneously
- Multiple clients can write to different sentences simultaneously
- When a client writes to a sentence, that sentence is locked
- Other clients must wait until the write operation completes

## Access Control

- File owner has full read/write access
- Owner can grant read-only or read/write access to other users
- Owner can revoke access from users
- Only authorized users can access files based on permissions

## Error Handling

The system provides clear error messages for:
- File not found
- Permission denied
- File already exists
- Sentence/word index out of range
- Sentence locked (concurrent write)
- Storage server unavailable
- Connection failures

## Logging

All components log their operations:
- **nameserver.log**: Name server operations
- **storageserver.log**: Storage server operations
- Terminal output shows real-time operation status

Logs include:
- Timestamps
- Client IP and port
- Operation type
- Success/failure status

## Data Persistence

- Files are stored persistently on storage servers
- Metadata (access control, timestamps) is maintained by the name server
- Files persist across storage server restarts
- System recovers gracefully from storage server disconnections

## Example Workflow

```bash
# Terminal 1: Start Name Server
./nameserver 8000

# Terminal 2: Start Storage Server
./storageserver 127.0.0.1 8000 9001 ./storage1

# Terminal 3: Start Client 1 (as user1)
./client 127.0.0.1 8000
Enter username: user1
> CREATE test.txt
File Created Successfully!

> WRITE test.txt 0
0 Hello
1 world
ETIRW
Write Successful!

> READ test.txt
Hello world

> ADDACCESS -R test.txt user2
Access granted successfully!

# Terminal 4: Start Client 2 (as user2)
./client 127.0.0.1 8000
Enter username: user2
> READ test.txt
Hello world

> VIEW
--> test.txt
```

## Implementation Details

### Name Server
- Uses Trie data structure for O(k) file lookup (k = filename length)
- Implements LRU cache for recent file lookups
- Thread-safe using pthread mutexes
- Handles multiple concurrent client connections
- Maintains file-to-storage-server mapping

### Storage Server
- Stores files persistently on disk
- Maintains in-memory cache for active files
- Implements sentence-level locking for concurrent writes
- Supports undo operation with backup mechanism
- Handles streaming with 0.1s word delay

### Client
- Interactive command-line interface
- Direct connection to storage servers for data operations
- Routes metadata operations through name server
- Handles connection failures gracefully

## Testing

Test the system with multiple clients:

```bash
# Test concurrent reads
Client1: READ file.txt
Client2: READ file.txt  # Both should succeed

# Test concurrent writes (different sentences)
Client1: WRITE file.txt 0  # Sentence 0
Client2: WRITE file.txt 1  # Sentence 1 - Should succeed

# Test concurrent writes (same sentence)
Client1: WRITE file.txt 0  # Locks sentence 0
Client2: WRITE file.txt 0  # Should fail with "Sentence is locked"

# Test access control
Client1 (owner): ADDACCESS -R file.txt user2
Client2 (user2): READ file.txt  # Should succeed
Client2 (user2): WRITE file.txt 0  # Should fail (no write access)
```

## Notes

- Maximum file size: ~80KB (adjustable via MAX_BUFFER)
- Maximum files: 10,000 (adjustable via MAX_FILES)
- Maximum concurrent clients: 100 (adjustable via MAX_CLIENTS)
- Maximum storage servers: 50 (adjustable via MAX_SS)
- Sentence delimiters: `.`, `!`, `?`
- Word separator: space

## Troubleshooting

**Connection refused**: Ensure name server is running first
**Permission denied**: Check file access rights with INFO command
**File not found**: Use VIEW to list available files
**Sentence locked**: Another client is currently editing that sentence

## Architecture Diagram

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Client1 │     │ Client2 │     │ Client3 │
└────┬────┘     └────┬────┘     └────┬────┘
     │               │               │
     └───────────────┼───────────────┘
                     │
              ┌──────┴──────┐
              │ Name Server │
              └──────┬──────┘
                     │
        ┌────────────┼────────────┐
        │            │            │
   ┌────┴───┐   ┌───┴────┐   ┌───┴────┐
   │ SS1    │   │ SS2    │   │ SS3    │
   │ 9001   │   │ 9002   │   │ 9003   │
   └────────┘   └────────┘   └────────┘
```

## License

This project is for educational purposes as part of OSN course work.