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
4) The assigned "pcap_folder" in the notebook will be automatically read by PCAP_Generic_Parser_Helper.py to be the designated folder on your system which contains the PCAP files
5) Move the text file (type.txt) to the same location as the notebook and enter the desired type (basic or emergency)
N.B The attached PCAP files are all e911 calls and are thus emergency
6) PCAP_Generic_Parser_Helper.py contains the helper functions that are called from the notebook to run them in parallel processing
7) run all cells in the notebook sequentially to convert PCAPs, get json files list, and finally call the function that reads and parses json files in parallel
8) result is saved to a csv file in the same folder as the notebook

# GTPv2 Logic
Collect all requests (message type = 32)
For each request, get corresponding response (message type= 33) with matching gtpv2.seq
For messages with consecutive requests followed by consecutive responses:
Mark all used responses by noting frame number
Retrieve unused responses for every other request to avoid using same response more than once
For each request – response pair, retrieve:
IP src for request and response
IP dst for request and response
GTPv2.cause
Static Columns: total number of requests, total number of responses, total number of unanswered requests, and number of occurrences in each gtpv2 cause

# Diameter v2 Logic
Filter out Watch-dog-answer and lost segments 
Collect each response with diameter result codes Different than 2001 
For each response, find the request with matching diameter.Session-Id
Packets with 2 consecutive requests followed by 2 consecutive responses, all having the same session ID:
Mark all used requests by noting frame number
Retrieve unused requests for every other response to avoid using same requests more than once
Static Columns: total number of requests, total number of responses, and number of occurrences in each result code
Retrieve the following as request-response pairs:
Origin Host
Destination Host
Request Type
Results Code
