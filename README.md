# ds-generic-parser
This repo contains a generic pcap parser for agility developed in Python by the datascience team.

## Introduction
The generic parser algorithm takes packet capture files (PCAPs) and generates from them a flow of useful information for SMEs to take decisions (success/fail, root cause analysis, etc...)  
This function can now work on any PCAP that uses the SIP protocol. All logic included is generic and should work on any telco operator.  
The main challenge is to treat call flows differently based on the type of call (basic vs emergency (e911))  
Since we have yet to find a way to detect the type of call from the data itself, we are reading the type of call from a txt file.  

## Pre-Requisites
1. [tshark binary](https://www.wireshark.org/download.html)
2. Python 3.x

## How to run
1. Start by initializing a virtual environment
    ```bash
    # run it from the projects root directory
    python3 -m venv /venv
    source ./venv/bin/activate
    pip install -r requirements.txt
    ```
1. Now let's start a jupyter server to run the notebook
    ```bash
    jupyter notebook
    ```
    This will open jupyter browser, make sure to click source -> AgilityGenericParser.ipynb and your notebook will open in a new window
1. Go to Cell -> Run All

## How does it work
1. The notebook relies on [PcapGenericParserHelper.py](./PcapGenericParserHelper.py) to do the parsing
1. The input data is under [data](./data) folder
1. The output of each run is under `./data/output/<uuid>` and includes the json transformed pcap files and a csv dump of the extractions per input file called `generic_parser_output.csv`
1. The call type is provided in [type.txt](./data/type.txt) file (don't ask me why :thinking: )