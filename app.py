from DLLProcess import DLLProcess
from parser import parser
import os
import shutil, magic, uuid
from ELFScanner import ELFScanner
from get_strings import get_strings
import yara
import re
from get_domains import get_domains
from check_yara_rules import check_yara_rules

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
    print(filetype)
    
    if argument.iterative:
        dll_map = dll_process.iterative_dll_reading(filename)
        print('Please wait while processing iterations')
        for dll in dll_map: 
            dll_result = ''
            if dll.path in dll_string:
                dll_result = dll.path + '\tmemory (in hex): '+ dll.addr
            else:
                dll_result = dll.path
            print(dll_result)
            if f is not None:
                f.write(str(dll_result) + "\n")

    elif argument.single: 
        debug_process = dll_process.create_debug_process(filename)
        similar_count = 0
        while dll_process.is_process_alive(debug_process):
            temp_dll_map = dll_process.single_dll_reading(debug_process)

            if similar_count >=threshold: 
                continue_analyze = input('No new libraries are being analyzed. Do you want to keep recording? [Y/N]').upper()
                while (continue_analyze not in ['Y', 'N']):
                    continue_analyze = input('No new libraries are being analyzed. Do you want to keep recording? [Y/N]').upper()
                if (continue_analyze == 'Y'):
                    similar_count = 0
                else:
                    break

            if dll_map is None or (temp_dll_map is not None and len(temp_dll_map) > len(dll_map)):
                dll_map = temp_dll_map
                similar_count = 0
            else: 
                similar_count += 1

            for dll in dll_map: 
                dll_result = ''
                if dll.path in dll_string:
                    dll_result = dll.path + '\tmemory (in hex): '+ dll.addr
                else:
                    dll_result = dll.path
                print(dll_result)
                if f is not None:
                    f.write(str(dll_result) + "\n")
    
    elif argument.analyse:
        if filetype == 'application/x-executable' or filetype == 'application/octet-stream' or filetype == 'application/x-pie-executable' or filetype == 'application/x-sharedlib' :
            elf = ELFScanner(filename=filename)
            dependencies = elf.dependencies()
            program_header = elf.program_header()
            section_header = elf.section_header()
            elf_symbols = elf.symbols()
            checksec = elf.checksec()

            print("\nFile Details: ")
            if f is not None:
                f.write("\nFile Details: " + "\n")
            for info in elf.file_info():
                print('\t', info)
                if f is not None:
                    f.write(str(info) + "\n")
        
            
            if dependencies:
                print("\nList of Dependencies: ")
                if f is not None:
                    f.write("\nList of Dependencies: " + "\n")

                for val in dependencies:
                    val = val.decode('utf-8', 'ignore').replace("\n", "")
                    print(val)
                    if f is not None:
                        f.write(str(val) + "\n")
            
            if program_header:
                print("\nProgram Header Information: ")
                if f is not None:
                    f.write("\nProgram Header Information: " + "\n")
                for val in program_header:
                    val = val.decode('utf-8', 'ignore').replace("\n", "")
                    print(val)
                    if f is not None:
                        f.write(str(val) + "\n")
                    

            if section_header:
                print("\nSection Header Information: ")
                if f is not None:
                    f.write("\nSection Header Information: " + "\n")
                for val in section_header:
                    val = val.decode('utf-8', 'ignore').replace("\n", "")
                    if f is not None:
                        f.write(str(val) + "\n")
            
            if elf_symbols:
                print("\nSymbol Information: ")
                if f is not None:
                    f.write("\nSymbol Information: " + "\n")
                for val in elf_symbols:
                    val = val.decode('utf-8', 'ignore').replace("\n", "")
                    print(val)
                    if f is not None:
                        f.write(str(val) + "\n")

            if checksec:
                print("\nCheckSec Information: ")
                if f is not None:
                    f.write("\nCheckSec Information: " + "\n")
                for key, value in checksec.items():
                    print(key + ": " + str(value))
                    if f is not None:
                        f.write(str(val) + "\n")
            
            #checking executable with all yara-rules
            total_yara_rules = check_yara_rules(filename = filename)
            for key, value in total_yara_rules.items():
                print("\n", key, " used in the file: ", value)
                if f is not None:
                    f.write("\n" + str(key) +  " used in the file: " + str(value) + "\n")
            
            #checking strings in the executable
            strings = get_strings(filename=filename).get_strings()
            if (strings[0]):
                print('\nIP addresses in file:', strings[0])
                if f is not None:
                    f.write(str(strings[0]) + "\n")
            if (strings[1]):
                print('\nEmail in file:', strings[1])
                if f is not None:
                    f.write(str(strings[1]) + "\n")
            if (strings[2]):
                print('\nWebsites in file', strings[2])
                if f is not None:
                    f.write(str(strings[2]) + "\n")

            total_malware_domains = list(strings[0]) + list(strings[2])
            malware_domains = get_domains()
            malware_in_file = []
            
            for mal_dom in total_malware_domains:
                r = re.compile(".*{}.*".format(mal_dom))
                if any(r.match(line) for line in malware_domains):
                    malware_in_file.append(mal_dom)
            
            if len(malware_in_file) > 0:
                print("\nMalware domains/websites present in file:")
                for mal in malware_in_file:
                    print(mal)
                    if f is not None:
                        f.write(mal)


                