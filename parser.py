from argparse import ArgumentParser 
import math

def parser():
    parser = ArgumentParser()
    parser.add_argument('-f', action='store', dest='file_path', help='Specify absolute path to executable file')
    parser.add_argument('-out', action='store', dest='output_file_path', help='Specify absolute path to output file')
    parser.add_argument('--version', action='version', version='DLL Analyser 1.0')

    parser.add_argument('-s', action='store_true', default=False, dest='single', help='Switch to single mode of DLL reader')
    parser.add_argument('-i', action='store_true', default=False, dest='iterative', help='Swich to iterative mode of DLL reader')
    parser.add_argument('-a', action='store_true', default=False, dest='analyse', help='Switch to analyse the file')

    parser.add_argument('-t', type=int, dest='threshold',  help = 'If the program did not load any new library after this number of checks, it will ask you whether you want to continue. Only useful in single mode. Default value is infinite')

    parser.set_defaults(iterative = False)
    parser.set_defaults(threshold = math.inf)

    argument = parser.parse_args()
    return argument