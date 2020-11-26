def Generic_Parser(dataframe, filename):
    extract=[]
    extract.append(filename.split('.json')[0])
    #import filters set by the user for protocols, ip hosts, and telephone numbers
    import pandas as pd
    try:
        mapping=pd.read_csv('User_IP_Mappings.csv', dtype=str)
    except OSError as e:
        mapping=pd.read_csv('IP_Mapping.csv', dtype=str)    
    try:
        protocols=pd.read_csv('filtered_protocols.csv', dtype=str)
    except OSError as e:
        protocols=pd.read_csv('protocols.csv', dtype=str)
    try:
        ips=pd.read_csv('filtered_protocols_ip_hosts.csv', dtype=str)
    except OSError as e:
        ips=pd.read_csv('ip_hosts.csv', dtype=str)    
    try:
        telephone_numbers=pd.read_csv('filtered_protocols_telephone_numbers.csv', dtype=str)
    except OSError as e:
        telephone_numbers=pd.read_csv('telephone_numbers.csv', dtype=str)
    f = open("type.txt", "r")
    tel_nums=list(telephone_numbers['Telephone number'])
    ip_list=list(ips['IP'])
    protocols_list=list(protocols['Protocol'])
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
			# UE is a calculated field retrieved below
            elif(string==UE):
                return 'UE'
            else:
                return ''
        except(NameError) as e:
            return ''

    emergency_call=(f.read()=='emergency')
    def ipname(ip):
        for i in range(0,len(mapping['IP'])):
            if(ip==mapping['IP'].iloc[i]):
                return mapping['Label Helper'].iloc[i]
        return ip

    callids=[]
    found_1st_invite=False
    firstsipfrom=''
    firstsipto=''
    # Get 1st Invite and sip from and sip to
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
        if(emergency_call):
            condition=('sos' in siprequest or '911' in siprequest)
		else:
            condition=True
		# If call is emergency, we need to add condition ('sos' in siprequest or '911' in siprequest)
		# If call is not emergency, we need to remove above condition
		if((sipmethod =='INVITE') and (condition) and (found_1st_invite==False)):
			try:
				firstsipfrom=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.from.user')[0])
			except (KeyError, IndexError) as e:
				firstsipfrom='NOT AVAILABLE'
			try:
				firstsipto=extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.to.user')[0]
			except (KeyError, IndexError) as e:
				firstsipto='NOT AVAILABLE'
			try:
				ipsrc2=extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[1]
				ipdst2=extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[1]
			except (KeyError, IndexError) as e:
				ipsrc2=""
				ipdst2=""
			try:
				ipsrc1=extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[0]
				ipdst1=extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[0]
			except (KeyError, IndexError) as e:
				ipsrc1=""
				ipdst1=""
			try:
				ipv4src1=extract_values(dataframe[i]['_source']['layers'], 'ip.src')[0]
				ipv4dst1=extract_values(dataframe[i]['_source']['layers'], 'ip.dst')[0]
			except (KeyError, IndexError) as e:            
				ipv4src1=""
				ipv4dst1=""	
			if(ipsrc2!=''):
				ipsrc=ipsrc2
			elif(ipsrc1!=''):
				ipsrc=ipsrc1        
			else:
				ipsrc=ipv4src1
			if(ipdst2!=''):
				ipdst=ipdst2
			elif(ipdst1!=''):
				ipdst=ipdst1            
			else:
				ipdst=ipv4dst1
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
        if(emergency_call):
            if( (str(sipfrom) in str(firstsipfrom) or str(firstsipfrom) in str(sipfrom)) ):
                callids.append(sipcallid)
        else:
            if(sipfrom in firstsipfrom or sipto in firstsipfrom or firstsipfrom in sipfrom or firstsipfrom in sipto or sipfrom in firstsipto or sipto in firstsipto or firstsipto in sipfrom or firstsipto in sipto):
                callids.append(sipcallid)
    callids=list(set(callids))

    for i in range(0,len(dataframe)):
		# Filter on protocols
        take_packet=False
        try:
            frametype=extract_values(dataframe[i]['_source']['layers']['frame'], 'frame.protocols')[0]
        except (KeyError, IndexError) as e:
            frametype=''
        for j in protocols_list:
            take_packet=take_packet or (j in frametype)
        # extract needed fields
        try:
            sipmethod=(extract_values(dataframe[i]['_source']['layers']['sip'], 'sip.Method')[0])
        except (KeyError, IndexError) as e:
            sipmethod=''
        # add to ips the ipname of src or dst
        # Try to find ipv6 layer
        try:
            ipsrc2=extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[1]
            ipdst2=extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[1]
        except (KeyError, IndexError) as e:
            ipsrc2=""
            ipdst2=""
        try:
            ipsrc1=extract_values(dataframe[i]['_source']['layers'], 'ipv6.src')[0]
            ipdst1=extract_values(dataframe[i]['_source']['layers'], 'ipv6.dst')[0]
        except (KeyError, IndexError) as e:
            ipsrc1=""
            ipdst1=""
        try:
            ipv4src1=extract_values(dataframe[i]['_source']['layers'], 'ip.src')[0]
            ipv4dst1=extract_values(dataframe[i]['_source']['layers'], 'ip.dst')[0]
        except (KeyError, IndexError) as e:
            ipv4src1=""
            ipv4dst1=""            
        # extract needed fields
        try:
            IpSrc1 = extract_values(dataframe[i]['_source']['layers']['ip_dup1'], 'ip.src')[0]
        except (KeyError, IndexError) as e:
            IpSrc1 = ""
        try:
            IpDst1 = extract_values(dataframe[i]['_source']['layers']['ip_dup1'], 'ip.dst')[0]
        except (KeyError, IndexError) as e:
            IpDst1 = ""
        try:
            IpSrc2 = extract_values(dataframe[i]['_source']['layers']['ip'], 'ip.src')[0]
        except (KeyError, IndexError) as e:
            IpSrc2 = ""
        try:
            IpDst2 = extract_values(dataframe[i]['_source']['layers']['ip'], 'ip.dst')[0]
        except (KeyError, IndexError) as e:
            IpDst2 = ""
        if (IpSrc1 != ""):
            IpSrc = IpSrc1
        else:
            IpSrc = IpSrc2
        if (IpDst1 != ""):
            IpDst = IpDst1
        else:
            IpDst = IpDst2
        # Try to find the sip layer
        try:
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
        except KeyError:
            sipfromuser=''
            seqmethod=''
            sipstatus1=''
            sipstatus=''
            siprequest=''
        if(ipsrc2!=''):
            ipsrc=ipsrc2
        elif(ipsrc1!=''):
            ipsrc=ipsrc1        
        else:
            ipsrc=ipv4src1
        if(ipdst2!=''):
            ipdst=ipdst2
        elif(ipdst1!=''):
            ipdst=ipdst1            
        else:
            ipdst=ipv4dst1
        temp_extract=''
        if( ('sip' in frametype) and (sipmethod.upper()!='OPTIONS') and (seqmethod.upper()!='OPTIONS') and (sipstatus1!='' or sipmethod!='') and (sipcallid in callids)):        
#        if((ipsrc in ip_list or ipdst in ip_list) and (sipcallid in callids) and take_packet and ('sip' in frametype) and (sipmethod.upper()!='OPTIONS') and (seqmethod.upper()!='OPTIONS') #and (sipfromuser in tel_nums or siptouser in tel_nums)):
            if(sipreason!='' and (sipmethod.upper()=='BYE' or sipstatus1.startswith('4') or sipstatus1.startswith('5') or sipstatus1.startswith('6'))):
                temp_extract=(ipnamejose(IpSrc)+'-'+sipmethod+sipstatus1+'&&'+sipreason+ '-'+ipnamejose(IpDst))
            else:
                temp_extract=(ipnamejose(IpSrc)+'-'+sipmethod+sipstatus1+'-'+ipnamejose(IpDst))
            if(extract[-1]!=temp_extract and temp_extract!=''):
                extract.append(temp_extract)
    try:
        extract.remove('')
    except ValueError as e:
        pass
    return extract