#!/usr/bin/env python3
"""Parse shell command string and extract base commands while respecting quotes."""
import sys
import shlex

def extract_commands(cmd_string):
    """Extract all base commands from a shell command string."""
    commands = []

    # Split by command separators: |, &&, ||, ;
    # Use a simple state machine to handle quotes
    in_single = False
    in_double = False
    current = ""
    i = 0

    while i < len(cmd_string):
        c = cmd_string[i]

        # Track quote state
        if c == "'" and not in_double:
            in_single = not in_single
            current += c
        elif c == '"' and not in_single:
            in_double = not in_double
            current += c
        # Check for separators outside quotes
        elif not in_single and not in_double:
            if i < len(cmd_string) - 1 and cmd_string[i:i+2] in ['&&', '||']:
                if current.strip():
                    commands.append(current.strip())
                current = ""
                i += 1  # skip second char
            elif c in ['|', ';']:
                if current.strip():
                    commands.append(current.strip())
                current = ""
            else:
                current += c
        else:
            current += c

        i += 1

    if current.strip():
        commands.append(current.strip())

    # Extract base command from each segment
    base_commands = []
    for cmd in commands:
        try:
            # Use shlex to properly parse the command
            tokens = shlex.split(cmd)
            if tokens:
                base_commands.append(tokens[0])
        except ValueError:
            # If shlex fails, fall back to simple split
            parts = cmd.strip().split()
            if parts:
                base_commands.append(parts[0])

    return base_commands

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = " ".join(sys.argv[1:])
    else:
        cmd = sys.stdin.read().strip()

    commands = extract_commands(cmd)
    for c in commands:
        print(c)
