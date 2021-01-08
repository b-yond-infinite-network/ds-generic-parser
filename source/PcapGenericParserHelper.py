import subprocess
from pathlib import Path
import os
import io
import subprocess
import shlex
import pickle

pcap_folder = pickle.load(open("pcap_folder.p", "rb"))
# pcap_folder='5G_pcaps'
path = Path(pcap_folder)


def convert_pcap(files):
    absolute_path = path.absolute()
    return subprocess.call(f'cd "{absolute_path}"; tshark -r "{files}.pcap" -T json >"{files}.json"', shell=True)


def custom_hook(ordered_pairs):
    """Convert duplicate keys to arrays."""
    d = {}
    for k, v in ordered_pairs:
        if k in d:
            if type(d[k]) is list:
                d[k].append(v)
            else:
                d[k] = [d[k], v]
        else:
            d[k] = v
    return d


def read_json_parallel(json_files):
    import json
    filename = path / json_files
    with filename.open(encoding="utf8", errors="ignore") as f:
        return json.load(f, object_pairs_hook=custom_hook)


def extract_values(obj, key):
    """Pull all values of specified key from nested JSON."""
    arr = []

    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    extract(v, arr, key)
                elif k == key:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr, key)
        return arr

    results = extract(obj, arr, key)
    return results


def Generic_Parser(dataframe, filename):
    import pandas as pd
    extract = []
    extract.append(filename.split('.json')[0])
    # Read type of file (basic or emergency) specified by the user from the text file "type.txt"
    # f = open("type.txt", "r")
    emergency_codes = list(pd.read_csv('emergency_codes.csv', dtype=str, header=None)[0])
    mapping = pd.read_csv('IP_Mapping_All.csv', dtype=str)

    def ipname_file(IpSrc):
        for i in range(0, len(mapping)):
            if (IpSrc == mapping['IP'].iloc[i]):
                return mapping['Label Helper'].iloc[i]
        return ''

    def extract_values(obj, key):
        """Pull all values of specified key from nested JSON."""
        arr = []

        def extract(obj, arr, key):
            """Recursively search for values of key in JSON tree."""
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        extract(v, arr, key)
                    elif k == key:
                        arr.append(v)
            elif isinstance(obj, list):
                for item in obj:
                    extract(item, arr, key)
            return arr

        results = extract(obj, arr, key)
        return results

    # Define IP Mapping key value pairs from SME team
    def ipnamejose(string):
        try:
            if (string.startswith("2607:f160:10:30d:ce")):
                return "P-CSCF"
            elif (string.startswith("2607:f160:10:230d:ce:104")):
                return "S-CSCF"
            elif (string == "2607:f160:0:2000::7"):
                return "SR-Signaling"
            elif (string == "2607:f160:10:6067:ce:106::6"):
                return "C-SBC"
            elif (string == "2607:f160:0:2000::9"):
                return "C-SBC-RAN"
            elif (string == "2607:f160:0:2000::c"):
                return "P-SBC"
            elif (string == "198.226.37.37"):
                return "P-SBC"
            elif (string == "216.221.133.23"):
                return "Comtech-SBC"
            elif (string == "10.209.224.180"):
                return "SR"
            elif (string == "10.209.239.197"):
                return "P-SBC"
            elif (string == "10.209.239.196"):
                return "C-SBC"
            elif (string == "172.31.172.74"):
                return "E-SBC"
            elif (string == "172.31.129.70"):
                return "MSC"
            elif (string == "172.31.129.78"):
                return "MSC"
            elif (string == "172.31.133.135"):
                return "Eric_NOIS_CDMA"
            elif (string == "172.18.31.5"):
                return "C-SBC"
            elif (string == "172.18.31.6"):
                return "C-SBC"
            elif (string == "172.18.31.10"):
                return "C-SBC"
            elif (string == "172.18.31.11"):
                return "C-SBC"
            elif (string.startswith("172.18.31.")):
                return "P-SBC"
            elif (string == "217.243.184.11"):
                return "MTAS"
            elif ((string == "10.0.81.87") or (string == "217.243.180.5") or (string == "217.243.180.14") or (string == "217.243.182.5") or (string == "217.243.182.14") or (
                    string == "217.243.184.5") or (string == "217.243.184.14") or (string == "10.0.194.213")):
                return "S-CSCF"
            elif (string == "80.156.55.115"):
                return "UE"
            elif (string == "51.255.222.9"):
                return "P-CSCF02A"
            elif ((string == "51.255.222.9") or (string == "10.0.81.15") or (string == "10.0.81.17") or (string == "10.0.194.9") or (string == "10.0.194.12")):
                return "P-CSCF"
            elif (string == "10.0.81.17"):
                return "P-CSCF02C"
            elif (string == "51.255.221.10"):
                return "ABGF"
            elif ((string == "62.156.169.4") or (string == "62.156.169.5") or (string == "62.156.169.6") or (string == "62.156.169.7") or (string == "62.156.169.8") or (string == "62.154.169.4") or (
                    string == "62.154.169.5") or (string == "62.154.169.6") or (string == "62.154.169.7") or (string == "62.154.169.8")):
                return "MRFC"
            elif ((string == "62.154.169.36") or (string == "62.154.169.37") or (string == "62.154.169.38") or (string == "62.154.169.39") or (string == "62.154.169.40") or (
                    string == "62.156.172.36") or (string == "62.156.172.37") or (string == "62.156.172.38") or (string == "62.156.172.39") or (string == "62.156.172.40")):
                return "MRFP"
            # UE is a calculated field from each PCAP
            elif (string == UE):
                return 'UE'
            else:
                return 'Unmapped IP'
        except(NameError) as e:
            return 'Unmapped IP'

    # read type of PCAP from file if it is Emergency call or Basic call
    for i in range(len(dataframe)):
        try:
            siprequest = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Request-Line')[0])
        except (KeyError, IndexError) as e:
            siprequest = ''
        if ('sos' in siprequest or '911' in siprequest):
            emergency_call = True
            break;
        emergency_call = False
    # find 1st invite

    # emergency_call=(f.read()=='emergency')
    # Define a list of call IDs to be used to filter the call
    callids = []
    found_1st_invite = False
    firstsipfrom = ''
    firstsipto = ''
    # Get 1st Invite and store sip from and sip to
    for i in range(len(dataframe)):
        if (found_1st_invite):
            break;
        # find 1st invite
        try:
            siprequest = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Request-Line')[0])
        except (KeyError, IndexError) as e:
            siprequest = ''
        try:
            sipmethod = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Method')[0])
        except (KeyError, IndexError) as e:
            sipmethod = ''
        # if the type of call is emergency, we will need an additional boolean condition in the first invite
        if (emergency_call):
            condition = ('sos' in siprequest or '911' in siprequest)
        else:
            condition = True
        # get the first invite based on condition which differes based on type of call if basic or emergency
        if ((sipmethod == 'INVITE') and (condition) and (found_1st_invite == False)):
            try:
                firstsipfrom = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.from.user')[0])
            except (KeyError, IndexError) as e:
                firstsipfrom = 'NOT AVAILABLE'
            try:
                firstsipto = extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.to.user')[0]
            except (KeyError, IndexError) as e:
                firstsipto = 'NOT AVAILABLE'
            # extract IP fields
            try:
                ipv6src2 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[1]
                ipv6dst2 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[1]
            except (KeyError, IndexError) as e:
                ipv6src2 = ""
                ipv6dst2 = ""
            try:
                ipv6src1 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[0]
                ipv6dst1 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[0]
            except (KeyError, IndexError) as e:
                ipv6src1 = ""
                ipv6dst1 = ""
            try:
                ipv4src2 = extract_values(dataframe[i]['_source']['layers'], 'ip.src')[1]
            except (KeyError, IndexError) as e:
                ipv4src2 = ""
            try:
                ipv4dst2 = extract_values(dataframe[i]['_source']['layers'], 'ip.dst')[1]
            except (KeyError, IndexError) as e:
                ipv4dst2 = ""
            try:
                ipv4src1 = extract_values(dataframe[i]['_source']['layers'], 'ip.src')[0]
            except (KeyError, IndexError) as e:
                ipv4src1 = ""
            try:
                ipv4dst1 = extract_values(dataframe[i]['_source']['layers'], 'ip.dst')[0]
            except (KeyError, IndexError) as e:
                ipv4dst1 = ""
            # Get IP Source Based on hierarchy (ipv6 2nd layer - ipv6 1st layer - ipv4 2nd layer - ipv4 1st layer)
            if (ipv6src2 != ''):
                ipsrc = ipv6src2
            elif (ipv4src2 != ''):
                ipsrc = ipv4src2
            elif (ipv6src1 != ''):
                ipsrc = ipv6src1
            else:
                ipsrc = ipv4src1
            # Dst
            if (ipv6dst2 != ''):
                ipdst = ipv6dst2
            elif (ipv4dst2 != ''):
                ipdst = ipv4dst2
            elif (ipv6dst1 != ''):
                ipdst = ipv6dst1
            else:
                ipdst = ipv4dst1
            # Save value for the 1st invite IP Source as the UE (calculated field used in mapping function)
            UE = ipsrc
            found_1st_invite = True

    # Get Call ID list
    for i in range(0, len(dataframe)):
        try:
            sipfrom = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.from.user')[0])
        except (KeyError, IndexError) as e:
            sipfrom = ''
        try:
            sipto = extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.to.user')[0]
        except (KeyError, IndexError) as e:
            sipto = ''
        try:
            sipcallid = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Call-ID')[0])
        except (KeyError, IndexError) as e:
            sipcallid = ''
        # Get call IDs based on type of call
        # emergency_call=True
        if (emergency_call):
            if (sipfrom != '' and str(sipfrom) in str(firstsipfrom)):
                callids.append(sipcallid)
        else:
            if ((sipfrom != '' and sipfrom in firstsipfrom) or (sipto != '' and sipto in firstsipfrom) or (sipfrom != '' and firstsipfrom in sipfrom) or (sipto != '' and firstsipfrom in sipto) or (
                    sipfrom != '' and sipfrom in firstsipto) or (sipto != '' and sipto in firstsipto) or (sipfrom != '' and firstsipto in sipfrom) or (sipto != '' and firstsipto in sipto)):
                callids.append(sipcallid)
    # Retain unique list of Call IDs
    callids = list(set(callids))
    # print(callids)
    # Loop over the entire PCAP to get the parser output
    for i in range(0, len(dataframe)):
        try:
            frametype = extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.protocols')[0]
        except (KeyError, IndexError) as e:
            frametype = ''
        try:
            sipmethod = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Method')[0])
        except (KeyError, IndexError) as e:
            sipmethod = ''
        # Try to find the second occurrance of ipv6 layer and get source and destination addresses
        try:
            ipv6src2 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[1]
            ipv6dst2 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[1]
        except (KeyError, IndexError) as e:
            ipv6src2 = ""
            ipv6dst2 = ""
        # Get the first occurrence of ipv6 layer and get source and destination addresses
        try:
            ipv6src1 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[0]
            ipv6dst1 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[0]
        except (KeyError, IndexError) as e:
            ipv6src1 = ""
            ipv6dst1 = ""
        try:
            ipv4src2 = extract_values(dataframe[i]['_source']['layers'], 'ip.src')[1]
        except (KeyError, IndexError) as e:
            ipv4src2 = ""
        try:
            ipv4dst2 = extract_values(dataframe[i]['_source']['layers'], 'ip.dst')[1]
        except (KeyError, IndexError) as e:
            ipv4dst2 = ""
        try:
            ipv4src1 = extract_values(dataframe[i]['_source']['layers'], 'ip.src')[0]
        except (KeyError, IndexError) as e:
            ipv4src1 = ""
        try:
            ipv4dst1 = extract_values(dataframe[i]['_source']['layers'], 'ip.dst')[0]
        except (KeyError, IndexError) as e:
            ipv4dst1 = ""
        try:
            sipcallid = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Call-ID')[0])
        except (KeyError, IndexError) as e:
            sipcallid = ''
        try:
            sipfromuser = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.from.user')[0])
        except (KeyError, IndexError) as e:
            sipfromuser = ''
        try:
            siptouser = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.to.user')[0])
        except (KeyError, IndexError) as e:
            siptouser = ''
        try:
            sipstatus = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Status-Line')[0])
        except (KeyError, IndexError) as e:
            sipstatus = ''
        try:
            sipstatus1 = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Status-Code')[0])
        except (KeyError, IndexError) as e:
            sipstatus1 = ''
        try:
            siprequest = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Request-Line')[0])
        except (KeyError, IndexError) as e:
            siprequest = ''
        try:
            seqmethod = (extract_values(dataframe[i]['_source']['layers']['sip'], 'CSeq.method')[0])
        except (KeyError, IndexError) as e:
            seqmethod = ''
        try:
            sipcallid = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Call-ID')[0])
        except (KeyError, IndexError) as e:
            sipcallid = ''
        try:
            sipreason = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Reason')[0])
        except (KeyError, IndexError) as e:
            sipreason = ''

        # Get IP Source Based on hierarchy (ipv6 2nd layer - ipv6 1st layer - ipv4 2nd layer - ipv4 1st layer)
        if (ipv6src2 != ''):
            ipsrc = ipv6src2
        elif (ipv4src2 != ''):
            ipsrc = ipv4src2
        elif (ipv6src1 != ''):
            ipsrc = ipv6src1
        else:
            ipsrc = ipv4src1
        # Dst
        if (ipv6dst2 != ''):
            ipdst = ipv6dst2
        elif (ipv4dst2 != ''):
            ipdst = ipv4dst2
        elif (ipv6dst1 != ''):
            ipdst = ipv6dst1
        else:
            ipdst = ipv4dst1

        temp_extract = ''
        # Filter the call flow based on Call IDs list and sip method and sip sequence method
        if ((sipmethod.upper() != 'OPTIONS') and (seqmethod.upper() != 'OPTIONS') and (sipstatus1 != '' or sipmethod != '') and (sipcallid in callids)):
            # If packet has errors or a bye message, add additional field called sip reason
            if (sipreason != '' and (sipmethod.upper() == 'BYE' or sipstatus1.startswith('4') or sipstatus1.startswith('5') or sipstatus1.startswith('6'))):
                temp_extract = (ipnamejose(ipsrc) + '-' + sipmethod + sipstatus1 + '&&' + sipreason + '-' + ipnamejose(ipdst))
            else:
                temp_extract = (ipnamejose(ipsrc) + '-' + sipmethod + sipstatus1 + '-' + ipnamejose(ipdst))
            # Remove consecutive duplicates from the parser output
            try:
                if (extract[-1] != temp_extract and extract[-2] != temp_extract and extract[-3] != temp_extract and extract[-4] != temp_extract and temp_extract != ''):
                    extract.append(temp_extract)
            except (KeyError, IndexError) as e:
                extract.append(temp_extract)
    return extract


def tshark_aggregate_gtpcause(file):
    values = []
    file_path = path / file
    process = subprocess.Popen(shlex.split(f'tshark -2 -R "gtpv2" -r "{file_path}" -T fields -e gtpv2.cause -E occurrence=l'), stdout=subprocess.PIPE)
    while True:
        output = process.stdout.readline().decode('UTF-8')
        if output == '' and process.poll() is not None:
            break
        if output:
            values.extend(map(lambda x: x.replace('\n', ''), output.split(':')))
    return values


def tshark_aggregate_diameterresultcode(file):
    values = []
    file_path = path / file
    process = subprocess.Popen(shlex.split(f'tshark -2 -R "diameter" -r "{file_path}" -T fields -e diameter.Result-Code -E occurrence=l'), stdout=subprocess.PIPE)
    while True:
        output = process.stdout.readline().decode('UTF-8')
        if output == '' and process.poll() is not None:
            break
        if output:
            values.extend(map(lambda x: x.replace('\n', ''), output.split(':')))
    return values


def parse_diameter(dataframe, filename):
    import pandas as pd
    output = []
    requests_output = []
    responses_output = []
    used_responses = []
    requests_list = []
    requests_count = 0
    responses_count = 0
    unanswered_requests = 0
    import pickle
    diametercodes = pickle.load(open("diameter_result_codes.p", "rb"))
    for i in range(len(dataframe)):
        # Frame Layer
        framenumber = (extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.number')[0])
        frametype = extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.protocols')[0]
        # Check if ipv6 layer exists
        hasdiameter = 'diameter' in frametype
        # Check msg type if it is a request
        try:
            diameter_cmd_code = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.cmd.code')[0])
        except (KeyError, IndexError) as e:
            diameter_cmd_code = ''
        try:
            msgtype = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.flags')[0])
        except (KeyError, IndexError) as e:
            msgtype = ''
        try:
            uncaptured = extract_values(dataframe[i]['_source']['layers']['tcp'], 'tcp.analysis.ack_lost_segment')[0]
            uncaptured_packet = True
        except (KeyError, IndexError) as e:
            uncaptured = ''
            uncaptured_packet = False
        try:
            diameter_result_code = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Result-Code')[0])
        except (KeyError, IndexError) as e:
            diameter_result_code = ''
        # Filter
        if (hasdiameter and (diameter_cmd_code != '280') and (uncaptured_packet == False)):
            if (msgtype == '0x000000c0'):
                # found a gtp request
                requests_count = requests_count + 1
                try:
                    seq_n = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Session-Id')[0])
                    requests_list.append([seq_n, int(framenumber) - 1])
                except (KeyError, IndexError) as e:
                    seq_n = ''
            if (msgtype == '0x00000040'):
                # found a gtp response
                responses_count = responses_count + 1
            if (diameter_result_code != ''):
                diametercodes.append(diameter_result_code)
            # got list of all requests and their seq numbers
    for request in requests_list:
        request_seq_number = request[0]
        index = request[1]
        # Get Request info
        try:
            request_type = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.CC-Request-Type')[0])
        except (KeyError, IndexError) as e:
            request_type = ''
        try:
            request_origin_host = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Origin-Host')[0])
        except (KeyError, IndexError) as e:
            request_origin_host = ''
        try:
            request_destination_host = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Destination-Host')[0])
        except (KeyError, IndexError) as e:
            request_destination_host = ''

        # Get Response (if any)
        response_origin_host = ''
        response_destination_host = ''
        diameter_result_code = ''
        for i in range(index + 1, len(dataframe)):
            # Find response from packet which contains request onward
            framenumber = (extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.number')[0])
            frametype = extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.protocols')[0]
            hasdiameter = 'diameter' in frametype
            try:
                msgtype = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.flags')[0])
            except (KeyError, IndexError) as e:
                msgtype = ''
            try:
                seq_n = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Session-Id')[0])
            except (KeyError, IndexError) as e:
                seq_n = ''

            if (hasdiameter and msgtype == '0x00000040' and seq_n == request_seq_number and framenumber not in used_responses):
                used_responses.append(framenumber)
                try:
                    response_origin_host = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Origin-Host')[0])
                except (KeyError, IndexError) as e:
                    response_origin_host = ''
                try:
                    response_destination_host = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Destination-Host')[0])
                except (KeyError, IndexError) as e:
                    response_destination_host = ''
                try:
                    diameter_result_code = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Result-Code')[0])
                except (KeyError, IndexError) as e:
                    diameter_result_code = ''
                if (diameter_result_code == '' and response_origin_host == '' and response_destination_host == ''):
                    unanswered_requests += 1
                try:
                    if ((
                            request_origin_host + ' - Request - ' + response_destination_host + ' >>> ' + ' Response - ' + response_origin_host + ' - Result Code = ' + diameter_result_code + ' - ' + response_destination_host) !=
                            output[-1]):
                        output.append(
                            request_origin_host + ' - Request - ' + response_destination_host + ' >>> ' + ' Response - ' + response_origin_host + ' - Result Code = ' + diameter_result_code + ' - ' + response_destination_host)
                except IndexError as e:
                    output.append(
                        request_origin_host + ' - Request - ' + response_destination_host + ' >>> ' + ' Response - ' + response_origin_host + ' - Result Code = ' + diameter_result_code + ' - ' + response_destination_host)

                from more_itertools import unique_everseen
                output = list(unique_everseen(output))
        # Static Columns
    causes_counts = []
    import collections
    for i in collections.Counter(diametercodes).values():
        causes_counts.append(i - 1)

    return [filename.split('.json')[0]] + [str(requests_count)] + [str(responses_count)] + [str(unanswered_requests)] + causes_counts + output


def parse_diameter_errors(dataframe, filename):
    # Version 2 of the Diameter Parser which only shows anomalies (diameter result codes different from 2001)
    import pandas as pd
    output = []
    requests_output = []
    responses_output = []
    used_responses = []
    requests_list = []
    requests_count = 0
    responses_count = 0
    unanswered_requests = 0
    import pickle
    diametercodes = pickle.load(open("diameter_result_codes.p", "rb"))
    for i in range(len(dataframe)):
        # Frame Layer
        framenumber = (extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.number')[0])
        frametype = extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.protocols')[0]
        # Check if ipv6 layer exists
        hasdiameter = 'diameter' in frametype
        # Check msg type if it is a request
        try:
            diameter_cmd_code = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.cmd.code')[0])
        except (KeyError, IndexError) as e:
            diameter_cmd_code = ''
        try:
            msgtype = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.flags')[0])
        except (KeyError, IndexError) as e:
            msgtype = ''
        try:
            uncaptured = extract_values(dataframe[i]['_source']['layers']['tcp'], 'tcp.analysis.ack_lost_segment')[0]
            uncaptured_packet = True
        except (KeyError, IndexError) as e:
            uncaptured = ''
            uncaptured_packet = False
        try:
            diameter_result_code = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Result-Code')[0])
        except (KeyError, IndexError) as e:
            diameter_result_code = ''
        # Filter
        if (hasdiameter and (diameter_cmd_code != '280') and (uncaptured_packet == False) and str(diameter_result_code) != '2001' and str(diameter_result_code) != ''):
            if (msgtype == '0x000000c0'):
                # found a gtp request
                requests_count = requests_count + 1
            if (msgtype == '0x00000040'):
                # found a gtp response
                responses_count = responses_count + 1
                try:
                    seq_n = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Session-Id')[0])
                    requests_list.append([seq_n, int(framenumber) - 1])
                except (KeyError, IndexError) as e:
                    seq_n = ''
            if (diameter_result_code != ''):
                diametercodes.append(diameter_result_code)
            # got list of all requests and their seq numbers
    for request in requests_list:
        request_seq_number = request[0]
        index = request[1]
        # Get Request info
        try:
            request_type = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.CC-Request-Type')[0])
        except (KeyError, IndexError) as e:
            request_type = ''
        try:
            request_origin_host = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Origin-Host')[0])
        except (KeyError, IndexError) as e:
            request_origin_host = ''
        try:
            request_destination_host = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Destination-Host')[0])
        except (KeyError, IndexError) as e:
            request_destination_host = ''

        # Get Response (if any)
        response_origin_host = ''
        response_destination_host = ''
        diameter_result_code = ''
        for i in range(index - 1, 0, -1):
            # Find request from packet which contains response backward
            framenumber = (extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.number')[0])
            frametype = extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.protocols')[0]
            hasdiameter = 'diameter' in frametype
            try:
                msgtype = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.flags')[0])
            except (KeyError, IndexError) as e:
                msgtype = ''
            try:
                seq_n = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Session-Id')[0])
            except (KeyError, IndexError) as e:
                seq_n = ''

            if (hasdiameter and msgtype == '0x000000c0' and seq_n == request_seq_number and framenumber not in used_responses):
                used_responses.append(framenumber)
                try:
                    response_origin_host = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Origin-Host')[0])
                except (KeyError, IndexError) as e:
                    response_origin_host = ''
                try:
                    response_destination_host = (extract_values(dataframe[i]['_source']['layers']['diameter'], 'diameter.Destination-Host')[0])
                except (KeyError, IndexError) as e:
                    response_destination_host = ''
                try:
                    diameter_result_code = (extract_values(dataframe[index]['_source']['layers']['diameter'], 'diameter.Result-Code')[0])
                except (KeyError, IndexError) as e:
                    diameter_result_code = ''
                if (diameter_result_code == '' and response_origin_host == '' and response_destination_host == ''):
                    unanswered_requests += 1

                output.append(
                    request_origin_host + ' - Request - ' + response_destination_host + ' >>> ' + ' Response - ' + response_origin_host + ' - Result Code = ' + diameter_result_code + ' - ' + response_destination_host)

                from more_itertools import unique_everseen
                output = list(unique_everseen(output))
        # Static Columns
    causes_counts = []
    import collections
    for i in collections.Counter(diametercodes).values():
        causes_counts.append(i - 1)

    return [filename.split('.json')[0]] + [str(requests_count)] + [str(responses_count)] + [str(unanswered_requests)] + causes_counts + output


def parse_gtp(dataframe, filename):
    # Collect a list of all requests and save their frame numbers. Then for each request, find the response with matching
    # Seq number from that frame numbre onward to avoid inefficient indexing
    import pandas as pd
    import pickle
    import collections
    requests_output = []
    responses_output = []
    requests_list = []
    used_responses = []
    requests_count = 0
    responses_count = 0
    unanswered_requests = 0
    gtp_causes = pickle.load(open("gtpcauses.p", "rb"))

    for i in range(len(dataframe)):
        # Frame Layer
        framenumber = (extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.number')[0])
        frametype = extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.protocols')[0]
        # Check if ipv6 layer exists
        hasgtp = 'gtpv2' in frametype
        # Check msg type if it is a request
        try:
            msgtype = (extract_values(dataframe[i]['_source']['layers']['gtpv2'], 'gtpv2.message_type')[0])
        except (KeyError, IndexError) as e:
            msgtype = ''
        try:
            cause = (extract_values(dataframe[i]['_source']['layers']['gtpv2'], 'gtpv2.cause')[0])
        except (KeyError, IndexError) as e:
            cause = ''
        if (cause != ''):
            gtp_causes.append(cause)
        if (hasgtp and msgtype == '32'):
            # found a gtp request
            requests_count = requests_count + 1
            try:
                seq_n = (extract_values(dataframe[i]['_source']['layers']['gtpv2'], 'gtpv2.seq')[0])
                requests_list.append([seq_n, int(framenumber) - 1])
            except (KeyError, IndexError) as e:
                seq_n = ''
        if (hasgtp and msgtype == '33'):
            # found a gtp response
            responses_count = responses_count + 1
    # got list of all requests and their seq numbers
    for request in requests_list:
        request_seq_number = request[0]
        index = request[1]
        # Get Request info
        # Try to find ipv6/4 layer
        try:
            ipv6src = (extract_values(dataframe[index]['_source']['layers']['ipv6'], 'ipv6.src')[0])
        except (KeyError, IndexError) as e:
            ipv6src = ''
        try:
            ipv6dst = (extract_values(dataframe[index]['_source']['layers']['ipv6'], 'ipv6.dst')[0])
        except (KeyError, IndexError) as e:
            ipv6dst = ''
        try:
            ipv4src = extract_values(dataframe[index]['_source']['layers']['ip'], 'ip.src')[0]
            ipv4dst = extract_values(dataframe[index]['_source']['layers']['ip'], 'ip.dst')[0]
        except (KeyError, IndexError) as e:
            ipv4src = ''
            ipv4dst = ''
        if (ipv6src != ''):
            request_ipsrc = ipv6src
            request_ipdst = ipv6dst
        else:
            request_ipsrc = ipv4src
            request_ipdst = ipv4dst
        # Get Response (if any)
        response_ipsrc = ''
        response_ipdst = ''
        cause = ''
        for i in range(index + 1, len(dataframe)):
            # Find response from packet which contains request onward
            frametype = extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.protocols')[0]
            framenumber = (extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.number')[0])
            hasgtp = 'gtpv2' in frametype
            try:
                msgtype = (extract_values(dataframe[i]['_source']['layers']['gtpv2'], 'gtpv2.message_type')[0])
            except (KeyError, IndexError) as e:
                msgtype = ''
            try:
                seq_n = (extract_values(dataframe[i]['_source']['layers']['gtpv2'], 'gtpv2.seq')[0])
            except (KeyError, IndexError) as e:
                seq_n = ''

            if (hasgtp and msgtype == '33' and seq_n == request_seq_number and framenumber not in used_responses):
                used_responses.append(framenumber)
                try:
                    cause = (extract_values(dataframe[i]['_source']['layers']['gtpv2'], 'gtpv2.cause')[0])
                except (KeyError, IndexError) as e:
                    cause = ''
                # Try to find ipv6/4 layer
                try:
                    ipv6src = (extract_values(dataframe[i]['_source']['layers']['ipv6'], 'ipv6.src')[0])
                except (KeyError, IndexError) as e:
                    ipv6src = ''
                try:
                    ipv6dst = (extract_values(dataframe[i]['_source']['layers']['ipv6'], 'ipv6.dst')[0])
                except (KeyError, IndexError) as e:
                    ipv6dst = ''
                try:
                    ipv4src = extract_values(dataframe[i]['_source']['layers']['ip'], 'ip.src')[0]
                    ipv4dst = extract_values(dataframe[i]['_source']['layers']['ip'], 'ip.dst')[0]
                except (KeyError, IndexError) as e:
                    ipv4src = ''
                    ipv4dst = ''
                if (ipv6src != ''):
                    response_ipsrc = ipv6src
                    response_ipdst = ipv6dst
                else:
                    response_ipsrc = ipv4src
                    response_ipdst = ipv4dst
        # check for unanswered requests
        if (cause == '' and response_ipsrc == '' and response_ipdst == ''):
            unanswered_requests = unanswered_requests + 1
        requests_output.append(request_ipsrc + ' - Request - ' + request_ipdst + ' >>> ' + ' Response - ' + response_ipsrc + ' - Cause = ' + cause + ' - ' + response_ipdst)
    causes_counts = []
    for i in collections.Counter(gtp_causes).values():
        causes_counts.append(i - 1)

    return [filename.split('.json')[0]] + [str(requests_count)] + [str(responses_count)] + [str(unanswered_requests)] + causes_counts + requests_output


def read_parse_generic(json_files):
    import json
    filename = path / json_files
    with filename.open(encoding="utf8", errors="ignore") as f:
        return Generic_Parser(json.load(f, object_pairs_hook=custom_hook), json_files)


def read_parse_gtp(json_files):
    import json
    filename = path / json_files
    with filename.open(encoding="utf8", errors="ignore") as f:
        return parse_gtp(json.load(f, object_pairs_hook=custom_hook), json_files)


def read_parse_diameter(json_files):
    import json
    filename = path / json_files
    with filename.open(encoding="utf8", errors="ignore") as f:
        return parse_diameter_errors(json.load(f, object_pairs_hook=custom_hook), json_files)