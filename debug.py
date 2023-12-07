
import frida
from time import sleep
from angr.sim_type import SimTypePointer, SimTypeLongLong, SimTypeInt
import logging


#Script Internal functions
def make_script_in(pair):
    (f,input)=pair
    args_str=''
    for i,type in enumerate(input):
        if isinstance(type, SimTypePointer) or isinstance(type, SimTypeLongLong):
            args_str+=f'args[{i}].readCString()'
        elif isinstance(type,SimTypeInt):
            args_str+=f'args[{i}].toInt32()'
        else:
            args_str+=f'args[{i}]'
        args_str+=', '
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

#Scripte exported functions
def make_script_ex(pair):
    (f,input)=pair
    args_str=''
    for i,type in enumerate(input):
        if isinstance(type, SimTypePointer) or isinstance(type, SimTypeLongLong):
            args_str+=f'args[{i}].readCString()'
        elif isinstance(type,SimTypeInt):
            args_str+=f'args[{i}].toInt32()'
        else:
            args_str+=f'args[{i}]'
        args_str+=', '
    return """
            Interceptor.attach(Module.findExportByName(null, '"""+f+"""'), {
                onEnter: function (args) {
                    send({function: '"""+f+"""', args: [""" + args_str + """]})
                },
                onLeave: function (retval) {
                	send({function: '"""+f+"""', ret: retval})
                }
            });
        """

#Main Function
def trace_function_calls(binary, args,exported_func,internal_func):
    """
    Run the binary and trace function calls with their arguments.
    """
    entries = []

    def on_message(message, data):
        logging.debug(message)
        if message["type"] == "send" and message["payload"] != "done":
            function_name = message["payload"]["function"]
            #TODO: cambiare
            try:
                function_args = message["payload"]["args"]
                io="input"
            except:
                function_args=message["payload"]["ret"]
                io="output"
            entries.append([function_name,function_args,io])

    # Run the binary
    process = frida.spawn(binary, argv=[binary] + args)

    session = frida.attach(process)
    script_txt=""
    for f in internal_func:
        script_txt+= make_script_in(f)
        script_txt+="\n"
    for f in exported_func:
        script_txt+= make_script_ex(f)
        script_txt+="\n"

    script = session.create_script(script_txt)
    script.on("message",on_message)
    script.load()

    frida.resume(process)

    # Wait for the script to complete
    sleep(1)
    
    # Detach and clean up
    try:
        session.detach()
    except Exception as e:
        logging.info(e)

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
