# SUS STRING EXTRACTOR
**It is recomended to run this script inside a virtual environment in order to install the required dependencies.**
Prototype for a command line interface for further analysing text files containing strings extracted from malware samples. The idea is to symplify malware analysis. The strings that are searched for are patterns belonging to the following categories:
- Wanacry Language Indicators
- Windows Directories
- URLs
- Binaries & Executables
- Possible base 64 strings (there is an option to decode the strings if found)
- IP Addresses
- Calls to golang's API 
- Known malitious addresses
Any pattern if finds will be written to ```classified_strings.txt``` by default. This option can be changed with the corresponding flag (```-o```). Similary, by default, the input file must be named ```strings.txt```, and this can be changed using the flag ```-i```.

## Usage
```
./sus_string_extractor.py --input_file <something.txt> --output_file <something.txt> --verbose --decode
```

### NOTES
I will update it as I discover other common patterns (the most likely next update is a more refined XML search). **This tool does not completely automate the malware string analysis task.** Although it may find some revealing strings, it is still recommended to look manually at the file since the script is not perfect (like most tools) and prone to miss some patterns.

