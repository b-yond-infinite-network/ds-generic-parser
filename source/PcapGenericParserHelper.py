import subprocess
from pathlib import Path
import os


def convert_pcap(input_folder_path: Path, output_folder_path: Path, file_name: str):

    return subprocess.run(
        f'cd "{input_folder_path.absolute()}"; tshark -r "{file_name}.pcap" -T json > "{os.path.join(output_folder_path.absolute(), file_name + ".json")}"', capture_output=True
        , shell=True)


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


def read_json_parallel(pcap_folder_path: Path, json_files):
    import json
    filename = pcap_folder_path / json_files
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


def parse(dataframe, filename, call_type):
    print(f'dataframe type: {type(dataframe)}')
    extract = [filename.split('.json')[0]]

    # Define IP Mapping key value pairs from SME team
    def ip_to_host(ip: str):
        try:
            if ip.startswith("2607:f160:10:30d:ce"):
                return "P-CSCF"
            elif ip.startswith("2607:f160:10:230d:ce:104"):
                return "S-CSCF"
            elif ip == "2607:f160:0:2000::7":
                return "SR-Signaling"
            elif ip == "2607:f160:10:6067:ce:106::6":
                return 'C-SBC'
            elif ip == "2607:f160:0:2000::9":
                return "C-SBC-RAN"
            elif ip == "2607:f160:0:2000::c":
                return "P-SBC"
            elif ip == "198.226.37.37":
                return "P-SBC"
            elif ip == "216.221.133.23":
                return "Comtech-SBC"
            elif ip == "10.209.224.180":
                return "SR"
            elif ip == "10.209.239.197":
                return "P-SBC"
            elif ip == "10.209.239.196":
                return "C-SBC"
            elif ip == "172.31.172.74":
                return "E-SBC"
            elif ip == "172.31.129.70":
                return "MSC"
            elif ip == "172.31.129.78":
                return "MSC"
            elif ip == "172.31.133.135":
                return "Eric_NOIS_CDMA"
            elif ip == "172.18.31.5":
                return "C-SBC"
            elif ip == "172.18.31.6":
                return "C-SBC"
            elif ip == "172.18.31.10":
                return "C-SBC"
            elif ip == "172.18.31.11":
                return "C-SBC"
            elif ip.startswith("172.18.31."):
                return "P-SBC"
            elif ip == "217.243.184.11":
                return "MTAS"
            elif ((ip == "10.0.81.87") or (ip == "217.243.180.5") or (ip == "217.243.180.14") or (
                    ip == "217.243.182.5") or (ip == "217.243.182.14") or (ip == "217.243.184.5") or (
                          ip == "217.243.184.14") or (ip == "10.0.194.213")):
                return "S-CSCF"
            elif ip == "80.156.55.115":
                return "UE"
            elif ip == "51.255.222.9":
                return "P-CSCF02A"
            elif ((ip == "51.255.222.9") or (ip == "10.0.81.15") or (ip == "10.0.81.17") or (
                    ip == "10.0.194.9") or (ip == "10.0.194.12")):
                return "P-CSCF"
            elif ip == "10.0.81.17":
                return "P-CSCF02C"
            elif ip == "51.255.221.10":
                return "ABGF"
            elif ((ip == "62.156.169.4") or (ip == "62.156.169.5") or (ip == "62.156.169.6") or (
                    ip == "62.156.169.7") or (ip == "62.156.169.8") or (ip == "62.154.169.4") or (
                          ip == "62.154.169.5") or (ip == "62.154.169.6") or (ip == "62.154.169.7") or (
                          ip == "62.154.169.8")):
                return "MRFC"
            elif ((ip == "62.154.169.36") or (ip == "62.154.169.37") or (ip == "62.154.169.38") or (
                    ip == "62.154.169.39") or (ip == "62.154.169.40") or (ip == "62.156.172.36") or (
                          ip == "62.156.172.37") or (ip == "62.156.172.38") or (
                          ip == "62.156.172.39") or (ip == "62.156.172.40")):
                return "MRFP"
            # UE is a calculated field from each PCAP
            elif ip == user_equipment:
                return 'UE'
            else:
                return ''
        except NameError as e:
            return ''

    # read type of PCAP from file if it is Emergency call or Basic call
    emergency_call = (call_type == 'emergency')
    # Define a list of call IDs to be used to filter the call
    call_ids = []
    found_1st_invite = False
    first_sip_from = ''
    first_sip_to = ''
    # Get 1st Invite and store sip from and sip to
    for i in range(len(dataframe)):
        if found_1st_invite:
            break;
        # find 1st invite
        try:
            sip_request = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Request-Line')[0])
        except (KeyError, IndexError) as e:
            sip_request = ''
        try:
            sip_method = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Method')[0])
        except (KeyError, IndexError) as e:
            sip_method = ''
        # if the type of call is emergency, we will need an additional boolean condition in the first invite
        if emergency_call:
            condition = ('sos' in sip_request or '911' in sip_request)
        else:
            condition = True
        # get the first invite based on condition which differs based on type of call if basic or emergency
        if (sip_method == 'INVITE') and condition and (found_1st_invite is False):
            try:
                first_sip_from = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.from.user')[0])
            except (KeyError, IndexError) as e:
                first_sip_from = 'NOT AVAILABLE'
            try:
                first_sip_to = extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.to.user')[0]
            except (KeyError, IndexError) as e:
                first_sip_to = 'NOT AVAILABLE'
            # extract IP fields
            try:
                ipv6_src2 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[1]
                ipv6_dst2 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[1]
            except (KeyError, IndexError) as e:
                ipv6_src2 = ""
                ipv6_dst2 = ""
            try:
                ipv6_src1 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[0]
                ipv6_dst1 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[0]
            except (KeyError, IndexError) as e:
                ipv6_src1 = ""
                ipv6_dst1 = ""
            try:
                ipv4_src2 = extract_values(dataframe[i]['_source']['layers'], 'ip.src')[1]
            except (KeyError, IndexError) as e:
                ipv4_src2 = ""
            try:
                ipv4_dst2 = extract_values(dataframe[i]['_source']['layers'], 'ip.dst')[1]
            except (KeyError, IndexError) as e:
                ipv4_dst2 = ""
            try:
                ipv4_src1 = extract_values(dataframe[i]['_source']['layers'], 'ip.src')[0]
            except (KeyError, IndexError) as e:
                ipv4_src1 = ""
            try:
                ipv4_dst1 = extract_values(dataframe[i]['_source']['layers'], 'ip.dst')[0]
            except (KeyError, IndexError) as e:
                ipv4_dst1 = ""
            # Get IP Source Based on hierarchy (ipv6 2nd layer - ipv6 1st layer - ipv4 2nd layer - ipv4 1st layer)
            if ipv6_src2 != '':
                ip_src = ipv6_src2
            elif ipv4_src2 != '':
                ip_src = ipv4_src2
            elif ipv6_src1 != '':
                ip_src = ipv6_src1
            else:
                ip_src = ipv4_src1
            # Dst
            if ipv6_dst2 != '':
                ip_dst = ipv6_dst2
            elif ipv4_dst2 != '':
                ip_dst = ipv4_dst2
            elif ipv6_dst1 != '':
                ip_dst = ipv6_dst1
            else:
                ip_dst = ipv4_dst1
            # Save value for the 1st invite IP Source as the UE (calculated field used in mapping function)
            user_equipment = ip_src
            found_1st_invite = True

    # Get Call ID list
    for i in range(0, len(dataframe)):
        try:
            sip_from = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.from.user')[0])
        except (KeyError, IndexError) as e:
            sip_from = ''
        try:
            sip_to = extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.to.user')[0]
        except (KeyError, IndexError) as e:
            sip_to = ''
        try:
            sip_call_id = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Call-ID')[0])
        except (KeyError, IndexError) as e:
            sip_call_id = ''
        # Get call IDs based on type of call
        if emergency_call:
            if str(sip_from) in str(first_sip_from) or str(first_sip_from) in str(sip_from):
                call_ids.append(sip_call_id)
        else:
            if (sip_from in first_sip_from
                    or sip_to in first_sip_from
                    or first_sip_from in sip_from
                    or first_sip_from in sip_to
                    or sip_from in first_sip_to
                    or sip_to in first_sip_to
                    or first_sip_to in sip_from
                    or first_sip_to in sip_to):
                call_ids.append(sip_call_id)
    # Retain unique list of Call IDs
    call_ids = list(set(call_ids))
    # Loop over the entire PCAP to get the parser output
    for i in range(0, len(dataframe)):
        try:
            frame_type = extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.protocols')[0]
        except (KeyError, IndexError) as e:
            frame_type = ''
        try:
            sip_method = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Method')[0])
        except (KeyError, IndexError) as e:
            sip_method = ''
        # Try to find the second occurrence of ipv6 layer and get source and destination addresses
        try:
            ipv6_src2 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[1]
            ipv6_dst2 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[1]
        except (KeyError, IndexError) as e:
            ipv6_src2 = ""
            ipv6_dst2 = ""
        # Get the first occurrence of ipv6 layer and get source and destination addresses
        try:
            ipv6_src1 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[0]
            ipv6_dst1 = extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[0]
        except (KeyError, IndexError) as e:
            ipv6_src1 = ""
            ipv6_dst1 = ""
        try:
            ipv4_src2 = extract_values(dataframe[i]['_source']['layers'], 'ip.src')[1]
        except (KeyError, IndexError) as e:
            ipv4_src2 = ""
        try:
            ipv4_dst2 = extract_values(dataframe[i]['_source']['layers'], 'ip.dst')[1]
        except (KeyError, IndexError) as e:
            ipv4_dst2 = ""
        try:
            ipv4_src1 = extract_values(dataframe[i]['_source']['layers'], 'ip.src')[0]
        except (KeyError, IndexError) as e:
            ipv4_src1 = ""
        try:
            ipv4_dst1 = extract_values(dataframe[i]['_source']['layers'], 'ip.dst')[0]
        except (KeyError, IndexError) as e:
            ipv4_dst1 = ""
        try:
            sip_call_id = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Call-ID')[0])
        except (KeyError, IndexError) as e:
            sip_call_id = ''
        try:
            sip_from_user = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.from.user')[0])
        except (KeyError, IndexError) as e:
            sip_from_user = ''
        try:
            sip_to_user = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.to.user')[0])
        except (KeyError, IndexError) as e:
            sip_to_user = ''
        try:
            sip_status = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Status-Line')[0])
        except (KeyError, IndexError) as e:
            sip_status = ''
        try:
            sip_status_1 = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Status-Code')[0])
        except (KeyError, IndexError) as e:
            sip_status_1 = ''
        try:
            sip_request = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Request-Line')[0])
        except (KeyError, IndexError) as e:
            sip_request = ''
        try:
            seq_method = (extract_values(dataframe[i]['_source']['layers']['sip'], 'CSeq.method')[0])
        except (KeyError, IndexError) as e:
            seq_method = ''
        try:
            sip_call_id = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Call-ID')[0])
        except (KeyError, IndexError) as e:
            sip_call_id = ''
        try:
            sip_reason = (extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Reason')[0])
        except (KeyError, IndexError) as e:
            sip_reason = ''

        # Get IP Source Based on hierarchy (ipv6 2nd layer - ipv6 1st layer - ipv4 2nd layer - ipv4 1st layer)
        if ipv6_src2 != '':
            ip_src = ipv6_src2
        elif ipv4_src2 != '':
            ip_src = ipv4_src2
        elif ipv6_src1 != '':
            ip_src = ipv6_src1
        else:
            ip_src = ipv4_src1
        # Dst
        if ipv6_dst2 != '':
            ip_dst = ipv6_dst2
        elif ipv4_dst2 != '':
            ip_dst = ipv4_dst2
        elif ipv6_dst1 != '':
            ip_dst = ipv6_dst1
        else:
            ip_dst = ipv4_dst1

        temp_extract = ''
        # Filter the call flow based on Call IDs list and sip method and sip sequence method
        if ((sip_method.upper() != 'OPTIONS') and (seq_method.upper() != 'OPTIONS') and (
                sip_status_1 != '' or sip_method != '') and (sip_call_id in call_ids)):
            # If packet has errors or a bye message, add additional field called sip reason
            if (sip_reason != '' and (
                    sip_method.upper() == 'BYE' or sip_status_1.startswith('4') or sip_status_1.startswith(
                    '5') or sip_status_1.startswith('6'))):
                temp_extract = (
                            ip_to_host(ip_src) + '-' + sip_method + sip_status_1 + '&&' + sip_reason + '-' + ip_to_host(
                                ip_dst))
            else:
                temp_extract = (ip_to_host(ip_src) + '-' + sip_method + sip_status_1 + '-' + ip_to_host(ip_dst))
            # Remove consecutive duplicates from the parser output
            if extract[-1] != temp_extract and temp_extract != '':
                extract.append(temp_extract)
    # Remove null values in the parser output
    try:
        extract.remove('')
    except ValueError as e:
        pass
    return extract


def read_parse_generic(pcap_folder_path, json_files, call_type):
    import json
    filename = pcap_folder_path / json_files
    with filename.open(encoding="utf8", errors="ignore") as f:
        return parse(json.load(f, object_pairs_hook=custom_hook), json_files, call_type)
