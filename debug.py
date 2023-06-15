from pwn import *

def generate_breakpoints(binary):
    """
    Generate breakpoints at the beginning of all functions defined in the binary.
    """
    breakpoints = []
    elf = ELF(binary)
    functions = elf.functions
    for function in functions:
        breakpoints.append(function.address)
    return breakpoints

def get_function_args(function):
    """
    Get the arguments passed to a function.
    This implementation assumes the arguments are stored in the registers.
    You might need to modify this based on the calling convention used by the target.
    """
    args = []
    regs = gdb.execute("info registers", to_string=True).strip().split("\n")
    for reg in regs:
        if "rax" in reg or "rdi" in reg or "rsi" in reg or "rdx" in reg:
            arg = reg.split(":\t")[-1]
            if arg.startswith("0x"):
                args.append(int(arg, 16))
    return args

def run_with_breakpoints(binary, args):
    """
    Run the binary with breakpoints at the beginning of each function.
    Capture function calls and their arguments when a breakpoint is hit.
    """
    entries = []
    breakpoints = generate_breakpoints(binary)

    # Start the target executable in GDB
    io = gdb.debug(binary)

    while True:
        # Wait for the prompt
        io.recvuntil("(gdb) ")

        # Check if we hit a breakpoint
        if io.recvline().startswith("Breakpoint"):
            # Get the function name from the breakpoint line
            function_name = io.recvline().split()[0].decode()
            function_address = int(function_name, 16)

            # Get the function arguments
            function_args = get_function_args(function_name)

            # Add the entry to the list
            entries.append((function_name, function_args))

            # Continue execution
            io.sendline("c")
        else:
            # If no breakpoint, assume the program has terminated
            break

    return entries

# Usage example
binary_path = "./test/test"
arguments = ["-h"]

entries = run_with_breakpoints(binary_path, arguments)

# Print the generated entries
for entry in entries:
    function_name, function_args = entry
    print(f"Function: {function_name}")
    print(f"Arguments: {function_args}")
    print()
