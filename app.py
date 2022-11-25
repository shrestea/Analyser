from DLLProcess import DLLProcess
from parser import parser
import os
import shutil, magic, uuid
from ELFScanner import ELFScanner

dll_string = ['[stack]' , '[vdso]','[vvar]', '[anon]']

if __name__ == '__main__':
    argument = parser()
    dll_process = DLLProcess()
    filename = argument.file_path
    output_file = argument.output_file_path
    threshold = argument.threshold
    dll_map = None
    f = None
    if output_file:
        f = open(output_file, "w")
    if not filename or not os.path.exists(filename):
        print('Executable file or filepath does not exist')
        exit(0)
    filetype = magic.from_file(filename, mime=True)
    
    # if argument.iterative:
    #     dll_map = dll_process.iterative_dll_reading(filename)
    #     print('Please wait while processing iterations')
    #     for dll in dll_map: 
    #         dll_result = ''
    #         if dll.path in dll_string:
    #             dll_result = dll.path + '\tmemory (in hex): '+ dll.addr
    #         else:
    #             dll_result = dll.path
    #         print(dll_result)
    #         if f is not None:
    #             f.write(str(dll_result) + "\n")

    # else: 
    #     debug_process = dll_process.create_debug_process(filename)
    #     similar_count = 0
    #     while dll_process.is_process_alive(debug_process):
    #         temp_dll_map = dll_process.single_dll_reading(debug_process)

    #         if similar_count >=threshold: 
    #             continue_analyze = input('No new libraries are being analyzed. Do you want to keep recording? [Y/N]').upper()
    #             while (continue_analyze not in ['Y', 'N']):
    #                 continue_analyze = input('No new libraries are being analyzed. Do you want to keep recording? [Y/N]').upper()
    #             if (continue_analyze == 'Y'):
    #                 similar_count = 0
    #             else:
    #                 break

    #         if dll_map is None or (temp_dll_map is not None and len(temp_dll_map) > len(dll_map)):
    #             dll_map = temp_dll_map
    #             similar_count = 0
    #         else: 
    #             similar_count += 1

    #         for dll in dll_map: 
    #             dll_result = ''
    #             if dll.path in dll_string:
    #                 dll_result = dll.path + '\tmemory (in hex): '+ dll.addr
    #             else:
    #                 dll_result = dll.path
    #             print(dll_result)
    #             if f is not None:
    #                 f.write(str(dll_result) + "\n")
    # if output_file:
    #     f.close()
    
    filetype = magic.from_file(filename, mime=True)
    print(filetype)
    if filetype == 'application/x-executable' or filetype == 'application/x-pie-executable':
        elf = ELFScanner(filename=filename)

        print("File Details: ")
        for n in elf.file_info('report'):
            print('\t', n)
    
        depends = elf.dependencies()
        if depends:
            print("Dependencies: ")
            for line in depends:
                line = line.decode('utf-8', 'ignore').replace("\n", "")
                print(line)
        
        prog_header = elf.program_header()
        if prog_header:
            print("Program Header Information: ")
            for line in prog_header:
                line = line.decode('utf-8', 'ignore').replace("\n", "")
                print(line)

        sect_header = elf.section_header()
        if sect_header:
            print("Section Header Information: ")
            for line in sect_header:
                line = line.decode('utf-8', 'ignore').replace("\n", "")
        
        syms = elf.symbols()
        if syms:
            print("Symbol Information: ")
            for line in syms:
                line = line.decode('utf-8', 'ignore').replace("\n", "")
                print(line)

        checksec = elf.checksec()
        if checksec:
            print("CheckSec Information: ")
            for key, value in checksec.items():
                print(key + ": " + str(value))
           


          




