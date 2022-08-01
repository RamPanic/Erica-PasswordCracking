# Created by RamPanic

import argparse
import hashlib

from sys import argv, exit
from time import time
from os.path import isfile
from platform import platform
from multiprocessing import Pool


class EricaException(Exception):
    ''' Generate generic exception ''' 

# Constants

DEFAULT_LONG = 2
DEFAULT_PROCESS = 2


def main():

    banner()

    errors = list()

    parser = argparse.ArgumentParser()
    parser.description = "Erica is a tool that will allow you to \
     crack many families of algorithms with their respective versions."
    parser.usage = "erica.py [OPTIONS]"
    parser.epilog = "Examples: erica.py -H d8e8fca2dc0f896fd7cb4cb0031ba249 \
     -a md5 -w passwords.txt"

    main_arguments = parser.add_argument_group('main arguments')
    main_arguments.add_argument('-H', '--hash', type=str, help='Hash to crack')
    main_arguments.add_argument('-a', '--algorithm', type=str, help='Algorithm')
    main_arguments.add_argument('-w', '--wordlist', type=str, help='Dictionary')    

    optional_arguments = parser.add_argument_group('optional arguments')
    optional_arguments.add_argument('-p', '--processes', help='Number of processes in parallel. \
        WARNING: Please do it at your own care. Predetermined: {}'.format(DEFAULT_PROCESS), 
        type=int, default=DEFAULT_PROCESS)
    optional_arguments.add_argument('-l', '--list', help='List available algorithms', 
        default=False, action='store_true')
    optional_arguments.add_argument('-v', '--version', help='Shows the version of this software', 
        default=False, action='store_true')

    args = parser.parse_args()

    if len(argv) == 1:
        parser.print_help()
        exit(0)

    if args.version:
        print_version()
        exit(0)

    if args.list:
        list_available_algorithms()
        exit(0)

    if not args.hash:
        errors.append("-H/--hash")

    if not args.algorithm:
        errors.append("-a/--algorithm")

    if not args.wordlist:
        errors.append("-w/--wordlist")

    if errors:
        print("Required arguments:", ", ".join(errors))
        exit(1)

    try:

        attack((
            args.hash, 
            args.algorithm, 
            args.wordlist,
            args.processes
        ))

    except EricaException as error:

        print(error)
        code = 1

    else:

        code = 0

    finally:

        exit(code)        


def banner():

    output =  "\n\n  ▓█████  ██▀███   ██▓ ▄████▄   ▄▄▄       \n"
    output += "  ▓█   ▀ ▓██ ▒ ██▒▓██▒▒██▀ ▀█  ▒████▄     \n"
    output += "  ▒███   ▓██ ░▄█ ▒▒██▒▒▓█    ▄ ▒██  ▀█▄   \n"
    output += "  ▒▓█  ▄ ▒██▀▀█▄  ░██░▒▓▓▄ ▄██▒░██▄▄▄▄██  \n"
    output += "  ░▒████▒░██▓ ▒██▒░██░▒ ▓███▀ ░ ▓█   ▓██▒ \n"
    output += "  ░░ ▒░ ░░ ▒▓ ░▒▓░░▓  ░ ░▒ ▒  ░ ▒▒   ▓▒█░ \n"
    output += "   ░ ░  ░  ░▒ ░ ▒░ ▒ ░  ░  ▒     ▒   ▒▒ ░ \n"
    output += "     ░     ░░   ░  ▒ ░░          ░   ▒    \n"
    output += "     ░  ░   ░      ░  ░ ░            ░  ░ \n"
    output += "                                          \n"
    output += "            Created by RamPanic            \n"

    print(output)


def print_version():

    print("Erica version 1.0")
    print(f"Platform: {platform()}")


def list_available_algorithms():

    print("List available algorithms")
    print("=========================\n")

    for algorithm in hashlib.algorithms_guaranteed:
        print(f"[-] {algorithm}")


def file_exists(file_path):

    return isfile(file_path)


def algorithm_exists(algorithm_type):

    return algorithm_type in hashlib.algorithms_guaranteed


def attack(args):

    hashed_password, algorithm, wordlist, processes = args


    if not file_exists(wordlist):
        raise EricaException("Dictionary not found")

    if not algorithm_exists(algorithm):
        raise EricaException("Algorithm not found. Check the flag: -l/--list")


    passwords = get_passwords_from_file(wordlist)

    breakpoints = get_breakpoints(len(passwords), processes)

    args = [ ( hashed_password, algorithm, passwords[bp["start"]:bp["end"]] ) for bp in breakpoints ]

    initial_time = time()

    with Pool(processes=processes) as pool:
        for password in pool.imap_unordered(find_password, args):
            if password is not None:
                break

    final_time = time() - initial_time

    print("\n", "=" * 60)

    if password:
        print(f"\n [+] Password: {password}")
    else:
        print(f"\n [x] Password not found")

    print(f" [+] Elapsed time for attack: {final_time}")

    print("\n", "=" * 60)


def get_passwords_from_file(file_path):

    with open(file_path) as file:
        lines = file.readlines()
    
    return [ line.strip() for line in lines ]


def get_breakpoints(items_length, processes):

    ''' Divide the number of items per process '''

    total_items_per_process = items_length // processes

    return [ { 
    "start": total_items_per_process * iteration, 
    "end": total_items_per_process * (iteration + 1) 
    } for iteration in range(processes) ]


def find_password(args):

    hashed_password, algorithm_name, passwords = args

    algorithm = getattr(hashlib, algorithm_name)


    found = False
    index = 0

    password_found = None

    while index < len(passwords) and not found:

        # We get the hashed password from the password list 
        # to compare it with the entered hash

        current_password = passwords[index]
        hashed_current_password = algorithm(current_password.encode("utf-8")).hexdigest()

        print(f"{current_password} -> {hashed_current_password} ?= {hashed_password}")

        if hashed_password == hashed_current_password:
            password_found = current_password
            found = True

        index += 1

    return password_found


if __name__ == '__main__':

    main()
