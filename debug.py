from elftools.elf.elffile import ELFFile
import frida
import sys

def generate_function_list(binary):
    """
    Generate a list of all the functions defined by the target executable.
    """
    functions = []
    with open(binary, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if section.header.sh_type == 'SHT_SYMTAB':
                for symbol in section.iter_symbols():
                    if symbol.entry.st_info.type == 'STT_FUNC':
                        functions.append(symbol.name)
    return functions

def trace_function_calls(binary, args):
    """
    Run the binary and trace function calls with their arguments.
    """
    entries = []
    function_list = generate_function_list(binary)

    def on_message(message, data):
        if message["type"] == "send":
            function_name = message["payload"]["function"]
            function_args = message["payload"]["args"]
            entries.append((function_name, function_args))

    # Run the binary
    process = frida.spawn(binary, argv=[binary] + args)

    session = frida.attach(process)
    script = session.create_script("""
        var resolver = new ApiResolver('module');

        function traceFunctionCalls() {
            resolver.enumerateMatches('*!*', {
                onMatch: function (match) {
                    var targetFunction = new NativeFunction(match.address, 'void', ['pointer']);
                    Interceptor.replace(match.address, new NativeCallback(function () {
                        send({function: match.name, args: Array.prototype.slice.call(arguments)});
                        return targetFunction.apply(this, arguments);
                    }, 'void', ['pointer']));
                },
                onComplete: function () {
                    send('done');
                }
            });
        }

        traceFunctionCalls();
    """)

    script.on("message", on_message)
    script.load()

    frida.resume(process)

    # Wait for the script to complete
    #script.join()

    #sys.stdin.read()
    # Detach and clean up
    try:
        session.detach()
        frida.kill(process)
    except Exception as e:
        print(e)

    return entries

# Usage example
binary_path = "./test/test"
arguments = ["arg1", "arg2", "arg3"]

entries = trace_function_calls(binary_path, arguments)

# Print the generated entries
for entry in entries:
    function_name, function_args = entry
    print(f"Function: {function_name}")
    print(f"Arguments: {function_args}")
    print()
