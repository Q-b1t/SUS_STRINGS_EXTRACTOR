#!/usr/bin/python3

import re
from base64 import b64decode
from termcolor import colored
import time 
from argparse import ArgumentParser,Namespace

def extract_usefull_strings(file_name):    
    """
    Receibes a filename as parameter.
    Reads the file, opens a handler, and iterates over the line comparing each line to different patterns 
    found un malware samples. The patterns are classified in lists, and the function returns a dictionary
    mapping pattern to the list of matching strings found.
    """
    print(colored(f"[*] Searching for common malware patterns in {file_name}.","blue"))
    # pattern particular for wannacry
    language_pattern = r"^msg/m_([a-z]+).wnry"
    # urls
    url_pattern = r"^http://([a-zA-Z0-9._-]).([a-zA-Z0-9_-])"
    # directories (windows) 
    dir_pattern = r"^C:([a-zA-Z0-9/\\_-]+).(\W+)"
    # files (random files (only name and/or relative path)) 
    file_pattern = r"^([a-zA-Z0-9_-]+)([.]{1})([a-zA-Z]+)"
    # xml like format 
    xml_pattern = r"^<([a-zA-Z0-9=_ -/!:{}*.;\"']+)>$"
    # user agent pattern
    user_agent_pattern = r"([A-Za-z0-9_ @]*)([A-Za-z]{4,8})/([0-9.]{3,6})"
    # ip address pattern
    ip_address_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    # possible base 64 pattern
    base64_pattern = r"[a-zA-Z0-9+/,=]{40,}"
    # golang indicators
    golang_pattern = r"^golang.org([A-Za-z0-9/.()*]+)"

    # lists to store findings
    language_list = list()
    url_list = list()
    dir_list = list()
    file_list = list()
    xml_list = list()
    user_agent_list = list()
    ip_address_list = list()
    base64_list = list()
    golang_list = list()

    # open file handler
    f = open("strings.txt","r")

    # iterate over all the lines in the file and compare with every pattern
    for line in f:
        if re.match(language_pattern,line):
            language_list.append(line)
        elif re.match(url_pattern,line):
            url_list.append(line)
        elif re.match(dir_pattern,line):
            dir_list.append(line)
        elif re.match(file_pattern,line):
            file_list.append(line)
        elif re.match(xml_pattern,line):
            xml_list.append(line)
        elif re.match(user_agent_pattern,line):
            user_agent_list.append(line)
        elif re.match(ip_address_pattern,line):
            ip_address_list.append(line)
        elif re.match(base64_pattern,line):
            base64_list.append(line)
        elif re.match(golang_pattern,line):
            golang_list.append(line)
        else:
            continue

    return {
        "wannacry_language":language_list,
        "directories":dir_list,
        "urls": url_list,
        "files":file_list,
        "xml":xml_list,
        "user_agents":user_agent_list,
        "ip_addresses":ip_address_list,
        "base64":base64_list,
        "golang_indicators":golang_list
    }

def show_findings(patterns):
    """
    Print the findings dictionary in case the verbose flag is active.
    """
    for pattern,ocurrences in patterns.items():
        if len(ocurrences) > 0:
            print(colored(f"[+] Found {len(ocurrences)} possible ocurrences of {pattern}","green"))
            time.sleep(1)

def write_output_file(patterns,output_file,decode,verbose):
    """
    Receibes and output file as argument and 
    """
    if decode and len(patterns["base64"]) > 0:
        print(colored("[*] Will attempt to decode base64 possible ocurrences.","blue"))
        time.sleep(2)
    with open(output_file,"w") as f:
        for pattern,ocurrences in patterns.items():
            if len(ocurrences) > 0:
                f.write("*"*50 + " " + pattern.upper().replace("_"," ") + " " + "*"*50 + "\n")
                for ocurrence in ocurrences:
                    if ocurrence[-1] != "\n":
                        ocurrence += "\n"
                    if pattern == "base64" and decode:
                        try:
                            ocurrence = b64decode(ocurrence).decode()
                            if verbose:
                                print(colored("[-] Base64 decoding successfull.","green"))
                        except:
                            if verbose:
                                print(colored("[-] Base64 decoding failed.","red"))
                    f.write(ocurrence)
            else:
                continue
    f.close() 
    print(colored(f"[+] The findings have beed written to {output_file}.","green"))


if __name__ == '__main__':

    # instance the parser
    parser = ArgumentParser()
    parser.add_argument("-i","--input_file",help="Name of the strings input text file (default: \"strings.txt\")",type=str,default="strings.txt",nargs="?")
    parser.add_argument("-o","--output_file",help="Name of the classified usefull strings' output text file (default: \"classified_strings.txt\")",type=str,default="classified_strings.txt",nargs="?")
    parser.add_argument("-v","--verbose",help="If the flag is used, it provides a more verbose output.",action="store_true")
    parser.add_argument("-d","--decode",help="If the flag is used, it the program will try to decode any potential base64 string it might find.",action="store_true")
    args: Namespace = parser.parse_args()

    input_file = args.input_file
    output_file = args.output_file
    decode = args.decode
    verbose = args.verbose

    # extract the classified patterns 
    patterns_classified = extract_usefull_strings(input_file)
    # show the findings
    if verbose:
        show_findings(patterns_classified)
    # write the patterns to an output file
    write_output_file(patterns_classified,output_file,decode = decode,verbose = verbose)


