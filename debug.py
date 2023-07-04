from elftools.elf.elffile import ELFFile
import frida
import sys
from time import sleep

#questa non mi sembra utile
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


def make_script(f,n):
    args_str = ', '.join(f'args[{i}]' for i in range(n))
    return """
            console.log('Called function '+DebugSymbol.getFunctionByName('"""+f+"""'))
            Interceptor.attach(DebugSymbol.getFunctionByName('"""+f+"""'), {
                onEnter: function (args) {
                    send({function: '"""+f+"""', args: [""" + args_str + """]})
                    console.log('onEnter function '+DebugSymbol.getFunctionByName('"""+f+"""'))
                },
                onLeave: function (retval) {
                	send({function: '"""+f+"""', ret: retval})
                    console.log('onLeave function '+DebugSymbol.getFunctionByName('"""+f+"""'))

                }
            });
        """

def trace_function_calls(binary, args,functions,n):
    """
    Run the binary and trace function calls with their arguments.
    """
    entries = []
    function_list = generate_function_list(binary)

    def on_message(message, data):
        print(message)
        if message["type"] == "send" and message["payload"] != "done":
            #function_payload = message["payload"] #["function"]
            function_name = message["payload"]["function"]
            #TODO: cambiare
            try:
                function_args = message["payload"]["args"]
                io="input"
            except:
                function_args=message["payload"]["ret"]
                io="output"
            entries.append((function_name,function_args))

    # Run the binary
    process = frida.spawn(binary, argv=[binary] + args)
    #process= frida.spawn(binary, argv=args)

    sleep(1)

    session = frida.attach(process)
    script_txt=""
    for f,i in zip(functions,n):
        script_txt+= make_script(f,i)
        script_txt+="\n"
    
    script = session.create_script(script_txt)
    script.on("message",on_message)
    script.load()

    frida.resume(process)

    # Wait for the script to complete
    #script.join()
    sleep(5)
    
    #sys.stdin.read()
    
    # Detach and clean up
    try:
        session.detach()
        #frida.kill(process)
    except Exception as e:
        print(e)

    return entries

# Usage example
#binary_path = "./test/test" 
#arguments = ["arg1", "arg2", "arg3"]
#list_functions=['h','g','f']
#n=2

#entries = trace_function_calls(binary_path, arguments,list_functions,n)


# Print the generated entries
#for entry in entries:
    #function_name, function_args = entry
    #print(f"Function: {function_name}")
    #print(f"Arguments: {function_args}")
    #print()
