import subprocess
from pathlib import Path

pcap_folder='50 pcaps'
path = Path(pcap_folder)


def convert_pcap(files):
    absolute_path = path.absolute()
    return subprocess.call(f'cd "{absolute_path}"; tshark -r "{files}.pcap" -T json >"{files}.json"', shell=True)
	#return subprocess.call('cmd /k "cd C:\Program Files\Wireshark & tshark -r "'+files+'.pcap"'+' -T json >"'+files+'.json"'+'"')


def custom_hook(ordered_pairs):
    """Convert duplicate keys to arrays."""
    d = {}
    for k, v in ordered_pairs:
        if k in d:
            if type(d[k]) is list:
                d[k].append(v)
            else:
                d[k] = [d[k],v]
        else:
            d[k] = v
    return d

def read_json_parallel(json_files):
    import json
    filename = path / json_files
    with filename.open(encoding="utf8", errors="ignore") as f:
        return json.load(f,object_pairs_hook=custom_hook)

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
    extract=[]
    extract.append(filename.split('.json')[0])
    # Read type of file (basic or emergency) specified by the user from the text file "type.txt"
    f = open("type.txt", "r")
    
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
            if(string.startswith("2607:f160:10:30d:ce")):
                return "P-CSCF"
            elif(string.startswith("2607:f160:10:230d:ce:104")):
                return "S-CSCF"
            elif(string == "2607:f160:0:2000::7"):
                return "SR-Signaling"
            elif(string == "2607:f160:10:6067:ce:106::6"):
                return "C-SBC"
            elif(string == "2607:f160:0:2000::9"):
                 return "C-SBC-RAN"
            elif(string == "2607:f160:0:2000::c"):
                return "P-SBC"
            elif(string == "198.226.37.37"):
                return "P-SBC"
            elif(string == "216.221.133.23"):
                return "Comtech-SBC"
            elif(string == "10.209.224.180"):
                 return "SR"
            elif(string == "10.209.239.197"):
                return "P-SBC"
            elif(string == "10.209.239.196"):
                return "C-SBC"
            elif(string == "172.31.172.74"):
                return "E-SBC"
            elif(string == "172.31.129.70"):
                return "MSC"
            elif(string == "172.31.129.78"):
                return "MSC"
            elif(string == "172.31.133.135"):
                return "Eric_NOIS_CDMA"
            elif(string == "172.18.31.5"):
                return "C-SBC"
            elif(string == "172.18.31.6"):
                return "C-SBC"
            elif(string == "172.18.31.10"):
                return "C-SBC"
            elif(string == "172.18.31.11"):
                return "C-SBC"
            elif(string.startswith("172.18.31.")):
                return "P-SBC"
            elif (string == "217.243.184.11"):
                return "MTAS"
            elif ((string == "10.0.81.87") or (string == "217.243.180.5") or (string == "217.243.180.14") or (string == "217.243.182.5") or (string == "217.243.182.14") or (string == "217.243.184.5") or (string == "217.243.184.14") or (string == "10.0.194.213")):
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
            elif ((string == "62.156.169.4") or (string == "62.156.169.5") or (string == "62.156.169.6") or (string == "62.156.169.7") or (string == "62.156.169.8") or (string == "62.154.169.4") or (string == "62.154.169.5") or (string == "62.154.169.6") or (string == "62.154.169.7") or (string == "62.154.169.8")):
                return "MRFC"
            elif ((string == "62.154.169.36") or (string == "62.154.169.37") or (string == "62.154.169.38") or (string == "62.154.169.39") or (string == "62.154.169.40") or (string == "62.156.172.36") or (string == "62.156.172.37") or (string == "62.156.172.38") or (string == "62.156.172.39") or (string == "62.156.172.40")):
                return "MRFP"
            # UE is a calculated field from each PCAP
            elif(string==UE):
                return 'UE'
            else:
                return ''
        except(NameError) as e:
            return ''
    # read type of PCAP from file if it is Emergency call or Basic call
    emergency_call=(f.read()=='emergency')
    # Define a list of call IDs to be used to filter the call
    callids=[]
    found_1st_invite=False
    firstsipfrom=''
    firstsipto=''
    # Get 1st Invite and store sip from and sip to
    for i in range(len(dataframe)):
        if(found_1st_invite):
            break;
        #find 1st invite
        try:
            siprequest=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Request-Line')[0])
        except (KeyError, IndexError) as e:
            siprequest=''
        try:
            sipmethod=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Method')[0])
        except (KeyError, IndexError) as e:
            sipmethod=''
# if the type of call is emergency, we will need an additional boolean condition in the first invite
        if(emergency_call):
            condition=('sos' in siprequest or '911' in siprequest)
        else:
            condition=True
        # get the first invite based on condition which differes based on type of call if basic or emergency
        if((sipmethod =='INVITE') and (condition) and (found_1st_invite==False)):
            try:
                firstsipfrom=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.from.user')[0])
            except (KeyError, IndexError) as e:
                firstsipfrom='NOT AVAILABLE'
            try:
                firstsipto=extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.to.user')[0]
            except (KeyError, IndexError) as e:
                firstsipto='NOT AVAILABLE'
            # extract IP fields
            try:
                ipv6src2=extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[1]
                ipv6dst2=extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[1]
            except (KeyError, IndexError) as e:
                ipv6src2=""
                ipv6dst2=""
            try:
                ipv6src1=extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[0]
                ipv6dst1=extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[0]
            except (KeyError, IndexError) as e:
                ipv6src1=""
                ipv6dst1=""  
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
            if(ipv6src2!=''):
                ipsrc=ipv6src2
            elif (ipv4src2 != ''):
                ipsrc = ipv4src2            
            elif(ipv6src1!=''):
                ipsrc=ipv6src1         
            else:
                ipsrc=ipv4src1
            # Dst
            if(ipv6dst2!=''):
                ipdst=ipv6dst2
            elif(ipv4dst2!=''):
                ipdst=ipv4dst2 
            elif(ipv6dst1!=''):
                ipdst=ipv6dst1 
            else:
                ipdst=ipv4dst1
# Save value for the 1st invite IP Source as the UE (calculated field used in mapping function)
            UE=ipsrc
            found_1st_invite=True
        
    # Get Call ID list
    for i in range(0,len(dataframe)):
        try:
            sipfrom=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.from.user')[0])
        except (KeyError, IndexError) as e:
            sipfrom=''
        try:
            sipto=extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.to.user')[0]
        except (KeyError, IndexError) as e:
            sipto=''        
        try:
            sipcallid=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Call-ID')[0])
        except (KeyError, IndexError) as e:
            sipcallid=''
        # Get call IDs based on type of call
        if(emergency_call):
            if( (str(sipfrom) in str(firstsipfrom) or str(firstsipfrom) in str(sipfrom)) ):
                callids.append(sipcallid)
        else:
            if(sipfrom in firstsipfrom or sipto in firstsipfrom or firstsipfrom in sipfrom or firstsipfrom in sipto or sipfrom in firstsipto or sipto in firstsipto or firstsipto in sipfrom or firstsipto in sipto):
                callids.append(sipcallid)
# Retain unique list of Call IDs
    callids=list(set(callids))
# Loop over the entire PCAP to get the parser output
    for i in range(0,len(dataframe)):
        try:
            frametype=extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.protocols')[0]
        except (KeyError, IndexError) as e:
            frametype=''
        try:
            sipmethod=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Method')[0])
        except (KeyError, IndexError) as e:
            sipmethod=''
# Try to find the second occurrance of ipv6 layer and get source and destination addresses
        try:
            ipv6src2=extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[1]
            ipv6dst2=extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[1]
        except (KeyError, IndexError) as e:
            ipv6src2=""
            ipv6dst2=""
# Get the first occurrence of ipv6 layer and get source and destination addresses
        try:
            ipv6src1=extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[0]
            ipv6dst1=extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[0]
        except (KeyError, IndexError) as e:
            ipv6src1=""
            ipv6dst1=""  
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
            sipcallid=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Call-ID')[0])
        except (KeyError, IndexError) as e:
            sipcallid=''
        try:
            sipfromuser=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.from.user')[0])
        except (KeyError, IndexError) as e:
            sipfromuser=''
        try:
            siptouser=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.to.user')[0])
        except (KeyError, IndexError) as e:
            siptouser=''			
        try:
            sipstatus=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Status-Line')[0])
        except (KeyError, IndexError) as e:
            sipstatus=''
        try:
            sipstatus1=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Status-Code')[0])
        except (KeyError, IndexError) as e:
            sipstatus1=''
        try:
            siprequest=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Request-Line')[0])
        except (KeyError, IndexError) as e:
            siprequest=''
        try:
            seqmethod=(extract_values(dataframe[i]['_source']['layers']['sip'], 'CSeq.method')[0])
        except (KeyError, IndexError) as e:
            seqmethod=''
        try:
            sipcallid=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Call-ID')[0])
        except (KeyError, IndexError) as e:
            sipcallid=''	
        try:
            sipreason=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Reason')[0])
        except (KeyError, IndexError) as e:
            sipreason=''                

# Get IP Source Based on hierarchy (ipv6 2nd layer - ipv6 1st layer - ipv4 2nd layer - ipv4 1st layer)
        if(ipv6src2!=''):
            ipsrc=ipv6src2
        elif (ipv4src2 != ''):
            ipsrc = ipv4src2
        elif(ipv6src1!=''):
            ipsrc=ipv6src1
        else:
            ipsrc=ipv4src1
        # Dst
        if(ipv6dst2!=''):
            ipdst=ipv6dst2
        elif(ipv4dst2!=''):
            ipdst=ipv4dst2 
        elif(ipv6dst1!=''):
            ipdst=ipv6dst1 
        else:
            ipdst=ipv4dst1

        temp_extract=''
# Filter the call flow based on Call IDs list and sip method and sip sequence method
        if( (sipmethod.upper()!='OPTIONS') and (seqmethod.upper()!='OPTIONS') and (sipstatus1!='' or sipmethod!='') and (sipcallid in callids)):        
# If packet has errors or a bye message, add additional field called sip reason
            if(sipreason!='' and (sipmethod.upper()=='BYE' or sipstatus1.startswith('4') or sipstatus1.startswith('5') or sipstatus1.startswith('6'))):
                temp_extract=(ipnamejose(ipsrc)+'-'+sipmethod+sipstatus1+'&&'+sipreason+ '-'+ipnamejose(ipdst))
            else:
                temp_extract=(ipnamejose(ipsrc)+'-'+sipmethod+sipstatus1+'-'+ipnamejose(ipdst))
# Remove consecutive duplicates from the parser output
            if(extract[-1]!=temp_extract and temp_extract!=''):
                extract.append(temp_extract)
# Remove null values in the parser output
    try:
        extract.remove('')
    except ValueError as e:
        pass
    return extract


def read_parse_generic(json_files):
    import json
    filename = path / json_files
    with filename.open(encoding="utf8", errors="ignore") as f:
        return Generic_Parser(json.load(f,object_pairs_hook=custom_hook),json_files)