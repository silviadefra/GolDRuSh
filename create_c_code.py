import sys

def generate_c_file(function_name, input_arguments, c_file_path='generated_code.c'):
    # Create the C code
    c_code = f'''
#include <stdio.h>

// Function prototype
void {function_name}({", ".join(input_arguments)});

// Main function
int main() {{
    // Call the function
    {function_name}({", ".join([f"arg{i}" for i in range(len(input_arguments))])});
    return 0;
}}
'''

    # Write the C code to a file
    with open(c_file_path, 'w') as c_file:
        c_file.write(c_code)

    print(f'C code has been written to {c_file_path}')

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python create_c-code.py <function_name> <args>")
        #sys.exit(1)

    # Path to the binary program
    function_name = sys.argv[1]

    # Specify the function name
    args= sys.argv[2]
generate_c_file(function_name, args)
