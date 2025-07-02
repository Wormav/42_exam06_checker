# 42 Exam Rank 06 - Mini Serv Checker

## Disclaimer

⚠️ **Important Notice**: This testing script does not guarantee success in the real exam. It provides basic automated tests to help you verify your implementation, but the actual exam may include additional edge cases and requirements not covered by these tests. Always refer to the official subject for complete requirements.

## Overview

This is an automated testing tool for the `mini_serv` project from 42's Exam Rank 06. It performs comprehensive tests to verify that your implementation meets the basic requirements of the subject.

## Prerequisites

- **Python 3**: Make sure you have Python 3 installed on your system
- **clang compiler**: Required for compiling the C source code
- **Port 4242**: Ensure port 4242 is available (see cleanup instructions below)

## Installation & Usage

### 1. Setup Your Project Structure

Clone this repository directly into your working directory containing your `mini_serv.c` file:

```bash
# In your working directory containing mini_serv.c
git clone https://github.com/Wormav/42_exam06_checker.git
```

Your directory structure should look like this:
```
your_project/
├── mini_serv.c              # Your implementation
├── 42_exam06_checker/
│   ├── test_mini_serv.py    # Test script
│   └── README.md            # This file
└── mini_serv                # Generated after compilation
```

### 2. Clean Port 4242 (if needed)

Before running the tests, make sure port 4242 is available:

```bash
# Kill any processes using port 4242
sudo lsof -ti:4242 | xargs kill -9
```

Or on some systems:
```bash
sudo pkill -f mini_serv
```

### 3. Run the Tests

```bash
cd 42_exam06_checker
python3 test_mini_serv.py
```

The script will:
1. Automatically compile your `mini_serv.c` from the parent directory
2. Run a series of automated tests
3. Generate a detailed report both in terminal and in `test_rapport.txt`

## What the Tests Cover

### ✅ Automated Tests:
- **Compilation**: Checks if code compiles with required flags
- **Forbidden Functions**: Verifies only allowed functions are used
- **Error Handling**: Tests argument validation and port error cases
- **Server Startup**: Ensures server starts correctly on valid port
- **Client Connections**: Tests multiple client connections
- **Client Disconnection**: Verifies disconnection messages
- **Multi-line Messages**: Tests handling of multiple lines in single send
- **Performance**: Basic rapid message handling
- **Code Requirements**: Checks for forbidden `#define` and localhost binding

### ⚠️ Manual Testing Required:

**Message Broadcasting Limitation**: The automated test for message broadcasting has a known limitation - it doesn't properly verify that the sender doesn't receive their own message.

**Recommended Manual Test**:
```bash
# Terminal 1: Start your server
./mini_serv 4242

# Terminal 2: Connect first client
nc 127.0.0.1 4242

# Terminal 3: Connect second client
nc 127.0.0.1 4242

# Terminal 4: Connect third client
nc 127.0.0.1 4242
```

Then manually verify:
1. Each client sees arrival messages for other clients
2. When one client sends a message, only OTHER clients receive it (not the sender)
3. Messages are properly formatted as `client X: message`
4. Disconnection messages appear when clients leave

## Test Results

The script generates two types of output:
1. **Real-time terminal output** with colored results
2. **Detailed report file** (`test_rapport.txt`) with complete analysis

## Common Issues & Tips

- **Compilation errors**: Ensure your code follows the subject requirements exactly
- **Port issues**: Make sure no other process is using port 4242
- **Fatal error messages**: Your program should output "Fatal error" for system-level errors
- **Message format**: Pay attention to exact formatting requirements (`client X: ` prefix)
- **Error messages**: Use exact wording: "Wrong number of arguments"
