import subprocess
import os
from time import sleep

source_file = "my_main.c"
target_process="my_program"

# Create the my_main.c file with an empty main function
def create_main_file(binary):
    
    c_code = '''
    #include <stdio.h>
    #include <dlfcn.h>

    int main() {
        void *handle = dlopen("'''+binary+'''", RTLD_LAZY);
        if (!handle) {
            return 1;
        }
        dlclose(handle);
        return 0;
    }
    '''

    # Save the C code to a file
    with open(source_file, "w") as file:
        file.write(c_code)

    # Compile the C file with gcc, linking against the shared library
    compile_command = ["gcc", source_file, "-o", target_process]


    try:
        subprocess.run(compile_command, check=True)
    except subprocess.CalledProcessError as e:
        print("Error during compilation:", e)
        exit(1)

def run_process_and_get_pid():
    # Run the compiled program and get its PID
    process = subprocess.Popen(["./" + target_process])
    sleep(1)  # Allow some time for the process to start
    return process.pid, process

def clean_up():
    if os.path.exists(source_file):
        os.remove(source_file)
    if os.path.exists(target_process):
        os.remove(target_process)
