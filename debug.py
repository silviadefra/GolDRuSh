
import frida
from time import sleep
from angr.sim_type import SimTypePointer, SimTypeLongLong, SimTypeInt
import logging
import sys
from create_delete_main import run_process_and_get_pid
from os import kill
from signal import SIGTERM


#Script Internal functions
def make_script_binary(pair,binary):
    (f,input)=pair
    args_str=''
    for i,t in enumerate(input):
        if isinstance(t, SimTypePointer) or isinstance(t, SimTypeLongLong):
            args_str+=f'args[{i}].readCString()'
        elif isinstance(t,SimTypeInt):
            args_str+=f'args[{i}].toInt32()'
        else:
            args_str+=f'args[{i}]'
        args_str+=', '
    return """
            Interceptor.attach(DebugSymbol.getFunctionByName('"""+f+"""'), {
                onEnter: function (args) {
                    send({function: '"""+f+"""', args: [""" + args_str + """]})
                },
                onLeave: function (retval) {
                	send({function: '"""+f+"""', ret: retval})

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

def make_script_lib(pair,binary):
    (f,input)=pair
    # last_slash_index = binary.rfind('/')
    # # Check if '/' was found
    # if last_slash_index == -1:
    #     # If no '/' found, the path is the file name itself
    #     file_name = binary
    # else:
    #     # Extract the part after the last '/'
    #     file_name = binary[last_slash_index + 1:]

    args_str=''
    for i,type in enumerate(input):
        if isinstance(type, SimTypePointer):  # Handle pointers
            args_str += f'args[{i}] !== null ? args[{i}].readPointer().toString() : "null"'
        elif isinstance(type, SimTypeLongLong):
            args_str+=f'args[{i}].readCString()'
        elif isinstance(type,SimTypeInt):
            args_str+=f'args[{i}].toInt32()'
        else:
            args_str+=f'args[{i}]'
        args_str+=', '
    return """
            var c= Module.load('"""+binary+"""');
            console.log('module info:\n'+JSON.stringify(c));
            Interceptor.attach(Module.findExportByName('"""+binary+"""', '"""+f+"""'), {
                onEnter: function (args) {
                    send({function: '"""+f+"""', args: [""" + args_str + """]})
                },
                onLeave: function (retval) {
                	send({function: '"""+f+"""', ret: retval})
                }
            });
        """


#Main Function
def trace_function_calls(binary, args,exported_func,internal_func,flag):
    """
    Run the binary and trace function calls with their arguments.
    """
    entries = []
    def on_message(message, data):
        #logging.warning(message)
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
    if flag:
        process = frida.spawn(binary, argv=[binary] + args)
        make_script_in=make_script_binary
    else:
        process=frida.spawn('my_program')
        make_script_in=make_script_lib
    session = frida.attach(process)
    script_txt=""
    script_txt+="\n"
    internal_func.reverse()
    for f in exported_func:
        script_txt+= make_script_ex(f)
        script_txt+="\n"
    for f in internal_func:
        script_txt+= make_script_in(f,binary)
        script_txt+="\n"

    script = session.create_script(script_txt)
    script.on("message",on_message)
    script.load()

    frida.resume(process)

    # Wait for the script to complete
    sleep(10)
    
    # Detach and clean up
    try:
        session.detach()
    except Exception as e:
        logging.info(e)

    return entries
