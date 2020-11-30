# ds-generic-parser
This repo contains a generic pcap parser for agility developed in Python by the datascience team.

## Introduction
The generic parser algorithm takes packet capture files (PCAPs) and generates from them a flow of useful information for SMEs to take decisions (success/fail, root cause analysis, etc...)
This function can now work on any PCAP that uses the SIP protocol. All logic included is generic and should work on any telco operator.
The main challenge is to treat call flows differently based on the type of call (basic vs emergency (e911))
Since we have yet to find a way to detect the type of call from the data itself, we are reading the type of call from a txt file.

## How to run
1) Ensure wireshark is installed on your system
2) Move the attached PCAP files (names starting with timothy.vogel to a folder on your system
3) Change "pcap_folder" in notebook to the designated folder on your system which contains the PCAP files
4) Change "pcap_folder" in PCAP_Generic_Parser_Helper.py to the designated folder on your system which contains the PCAP files
5) Move the text file (type.txt) to the same location as the notebook and enter the desired type (basic or emergency)
N.B The attached PCAP files are all e911 calls and are thus emergency
6) PCAP_Generic_Parser_Helper.py contains the helper functions that are called from the notebook to run them in parallel processing
7) run all cells in the notebook sequentially to convert PCAPs, get json files list, and finally call the function that reads and parses json files in parallel
8) result is saved to a csv file in the same folder as the notebook