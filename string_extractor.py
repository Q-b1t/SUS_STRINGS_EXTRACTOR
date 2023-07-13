import re

def extract_usefull_strings(file_name):    
    """
    Receibes a filename as parameter.
    Reads the file, opens a handler, and iterates over the line comparing each line to different patterns 
    found un malware samples. The patterns are classified in lists, and the function returns a dictionary
    mapping pattern to the list of matching strings found.
    """
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

    # lists to store findings
    language_list = list()
    url_list = list()
    dir_list = list()
    file_list = list()
    xml_list = list()
    user_agent_list = list()
    ip_address_list = list()
    base64_list = list()

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
        "base64":base64_list
    }

def write_output_file(patterns,output_file):
    pass


if __name__ == '__main__':
    input_file = "strings.txt"
    output_file = "classified_strings.txt"

    # extract the classified patterns 
    patterns_classified = extract_usefull_strings(input_file)

    # write the patterns to an output file
    write_output_file(patterns_classified,output_file)


