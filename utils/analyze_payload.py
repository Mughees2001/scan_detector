from codecs import ignore_errors
import shutil
import glob
import os
import sys, traceback
import logging
import subprocess
import difflib
from jinja2 import Environment, FileSystemLoader

tshark_path = "tshark"
suricata_path = "C:\Program Files (x86)\Suricata\suricata"
search_directory = "processed_data"
template_path = os.path.abspath("utils")
template_name = "snippet_det.template"
cmp_files_pcap = {}
cmp_files_json = {}
cmp_files_lcsubstrings = {}
cmp_files_payloads = {}
cmp_files_rules = {}
cmp_files_alerts = {}
cmp_files_dpktsnippet = {}

logging.getLogger().setLevel(logging.DEBUG)
rule_id = "9000001"

def hexToASCII(hexx):
    logging.debug("Converting hex bytes to ascii")
    # initialize the ASCII code string as empty.
    ascii = ""
    start_pipe = False
    for i in range(0, len(hexx), 2):
 
        # extract two characters from hex string
        part = hexx[i : i + 2]
 
        int_part = int(part,16)
        if int_part >=32 and int_part <= 126:
            # change it into base 16 and
            # typecast as the character
            ch = chr(int(part, 16))
        else:
            ch = "|"+str(part)+"|"
        # add this char to final ASCII string
        ascii += ch
    ascii = ascii.replace("||", " ")
    return ascii

def map_lcs_proto(pdml_proto):
    #logging.debug("Mapping Proto")    
    if "tls" in pdml_proto:
        return "tls"
    elif "http" in pdml_proto:
        return "http"
    elif "tcp" in pdml_proto:
        return "tcp"
    elif "dns" in pdml_proto:
        return "dns"
    elif "snmp" in pdml_proto:
        return "snmp"
    elif "udp" in pdml_proto:
        return "udp"

def get_pcap_filenames(contains=""):
    logging.debug("Getting PCAP filenames")
    pathname = search_directory + "/**/*.pcap*"
    files = glob.glob(pathname, recursive=True)
    for file in files:  
        if contains != "":
            if contains not in file:
                continue
        try:
            cmp_base = os.path.dirname(file)
            if cmp_base not in cmp_files_pcap:
                cmp_files_pcap[cmp_base] = []
            cmp_files_pcap[cmp_base].append(file)   
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.error("Error while searching for pcap files")
            traceback.print_exception(exc_type, exc_value, exc_traceback)

    #logging.debug("CMP_BASES: " + str(cmp_files_pcap))

def get_json_filenames(contains=""):
    logging.debug("Getting JSON filenames")
    pathname = search_directory + "/**/*.json*"
    files = glob.glob(pathname, recursive=True)
    for file in files:  
        if contains != "":
            if contains not in file:
                continue
        try:
            cmp_base = os.path.dirname(file)
            if cmp_base not in cmp_files_json:
                cmp_files_json[cmp_base] = []
            cmp_files_json[cmp_base].append(file)   
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.error("Error while searching for json files")
            traceback.print_exception(exc_type, exc_value, exc_traceback)

def get_payload_filenames(contains=""):
    logging.debug("Getting Payload filenames")
    pathname = search_directory + "/**/*.payload*"
    files = glob.glob(pathname, recursive=True)
    for file in files:
        if contains != "":
            if contains not in file:
                continue
        try:
            cmp_base = os.path.dirname(file)
            if cmp_base not in cmp_files_payloads:
                cmp_files_payloads[cmp_base] = []
            cmp_files_payloads[cmp_base].append(file)   
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.error("Error while searching for payload files")
            traceback.print_exception(exc_type, exc_value, exc_traceback)

def get_lcs_filenames(contains=""):
    logging.debug("Getting LCS filenames")
    pathname = search_directory + "/**/*.lcs"
    files = glob.glob(pathname, recursive=True)
    for file in files:
        if contains != "":
            if contains not in file:
                continue
        try:
            cmp_base = os.path.dirname(file)
            if cmp_base not in cmp_files_lcsubstrings:
                cmp_files_lcsubstrings[cmp_base] = []
            cmp_files_lcsubstrings[cmp_base].append(file)   
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.error("Error while searching for lcs files")
            traceback.print_exception(exc_type, exc_value, exc_traceback)

def get_rules_filenames(contains=""):
    logging.debug("Getting Rules filenames")
    pathname = search_directory + "/**/*.rules*"
    files = glob.glob(pathname, recursive=True)
    for file in files:  
        if contains != "":
            if contains not in file:
                continue
        try:
            cmp_base = os.path.dirname(file)
            if cmp_base not in cmp_files_rules:
                cmp_files_rules[cmp_base] = []
            cmp_files_rules[cmp_base].append(file)   
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.error("Error while searching for rules files")
            traceback.print_exception(exc_type, exc_value, exc_traceback)


def extract_json_from_pcap(replace_if_exists=True):
    logging.debug("Converting PCAPs to JSON")
    for dir in cmp_files_pcap:
        for myfile in cmp_files_pcap[dir]:
            logging.debug("Working on file: " + str(myfile))
            if dir not in cmp_files_json:
                cmp_files_json[dir] = []
            json_filename = os.path.splitext(myfile)[0] + ".json"
            cmp_files_json[dir].append(json_filename)
            if os.path.exists(json_filename) and replace_if_exists == False:
                continue
            try:
                cmd = "tshark -r " + myfile + " -T json "
                logging.debug("Running tshark to obtain json: " + str(cmd) )
                json_data = subprocess.getoutput(cmd)
                #logging.debug(json_data)
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                logging.error("Error during directory tshark execution")
                traceback.print_exception(exc_type, exc_value, exc_traceback)                 

            try:
                with open(json_filename, "w") as json_file:
                    json_file.write(json_data) 
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                logging.error("Error writing json data to file")
                traceback.print_exception(exc_type, exc_value, exc_traceback)      

def extract_payloads_from_json(replace_if_exists=True):
    logging.debug("Extracting payloads from JSON")
    curr_num = 1
    num_json_files = len(cmp_files_json)
    for dir in cmp_files_json:
        logging.debug("Extracting payloads from JSON")
        logging.debug("Processing folder " + str(curr_num) + " of " + str(num_json_files))
        curr_num += 1
        for myfile in cmp_files_json[dir]:
            payloads = []
            if dir not in cmp_files_payloads:
                cmp_files_payloads[dir] = []
            payload_filename = os.path.splitext(myfile)[0] + ".payload"
            cmp_files_payloads[dir].append(payload_filename)
            if os.path.exists(payload_filename) and replace_if_exists == False:
                continue

            try:
                with open(myfile, "r") as json_file:
                    #logging.error("WORKING WITH: " + str(myfile))
                    protocols = ""
                    dstport = ""
                    for line in json_file:
                        #TODO: actually read the JSON to ensure values are more accurate
                        #will get protocol, dstport (if any)
                        #erase data on "_index" since this means it's a new packet:
                        if "_index\":" in line:
                            protocols =""
                            dstport = ""
                        if "frame.protocols\":" in line:
                            split_protocols = line.split("frame.protocols\":")
                            if len(split_protocols) < 2:
                                logging.error("Found unusual protocols line: " + str(line))
                                continue
                            else:
                                protocols = split_protocols[1].split("\"")[1]
                        if ".dstport\":" in line:
                            split_dstport = line.split(".dstport\":")
                            if len(split_dstport) < 2:
                                logging.error("Found unusual dstport line: " + str(line))
                                continue
                            else:
                                dstport = split_dstport[1].split("\"")[1]
                        if ".payload\":" in line and protocols != "":
                                split_payload = line.split(".payload\":")
                                if len(split_payload) < 2:
                                    logging.error("Found unusual payload line: " + str(line))
                                    continue
                                else:
                                    payload = split_payload[1].split("\"")[1]
                                    payloads.append(protocols+","+dstport+","+payload)
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                logging.error("Error during directory tshark execution")
                traceback.print_exception(exc_type, exc_value, exc_traceback)

            try:
                with open(payload_filename, "w") as payload_file:
                    for payload in payloads:
                        payload_file.write(payload + "\n")

            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                logging.error("Error during directory tshark execution")
                traceback.print_exception(exc_type, exc_value, exc_traceback)   

def extract_lcs_from_payloads(replace_if_exists=True):
    logging.debug("Extracting LCS from Payloads")
    for dir in cmp_files_payloads:
        logging.debug("Analyzing: " + str(dir))
        if len(cmp_files_payloads[dir]) < 2:
            logging.error("Need at least two json files to compare in folder: " + str(dir))
            continue
        file1 = cmp_files_payloads[dir][0]
        file2 = cmp_files_payloads[dir][1]
        file1_basename = os.path.splitext(file1)[0]
        file2_basename = os.path.splitext(file2)[0]
        files_cmp1 = os.path.join(dir, os.path.basename(file1_basename) + "_" + os.path.basename(file2_basename) + ".lcs")
        files_cmp2 = os.path.join(dir, os.path.basename(file2_basename) + "_" + os.path.basename(file1_basename) + ".lcs")
        file1_payloads = []
        file2_payloads = []
        if dir not in cmp_files_lcsubstrings:
            cmp_files_lcsubstrings[dir] = []
        cmp_files_lcsubstrings[dir].append(files_cmp1)
        cmp_files_lcsubstrings[dir].append(files_cmp2)

        if os.path.exists(files_cmp1) and os.path.exists(files_cmp1) and replace_if_exists == False:
            logging.error("Skipping because files already exist in dir: " + str(dir))
            continue
        try:
            with open(file1, "r") as json_file:
                #only get the first for now
                file1_payloads = json_file.readlines()

        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.error("Error during directory tshark execution")
            traceback.print_exception(exc_type, exc_value, exc_traceback)      

        try:
            with open(file2, "r") as json_file:
                file2_payloads = json_file.readlines()

        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.error("Error during directory tshark execution")
            traceback.print_exception(exc_type, exc_value, exc_traceback)   

        try:
            if len(file1_payloads) < 1:
                logging.error("Payload is missing: " + str(file1))
                continue
            if len(file2_payloads) < 1:
                logging.error("Payload is missing: " + str(file2))
                continue
            file1_proto, file1_dstport, file1_payload = file1_payloads[0].split(",")
            clean_file1_payloads = file1_payload.replace("\n","")
            if clean_file1_payloads[0] == ":":
                clean_file1_payloads = clean_file1_payloads[1:]
            # if clean_file1_payloads.startswith("2e:31:30"):
            #     clean_file1_payloads = clean_file1_payloads[8:]
            if clean_file1_payloads[-1] == ":":
                clean_file1_payloads = clean_file1_payloads[0:-2]
            # if clean_file1_payloads.endswith("2e:31:30"):
            #     clean_file1_payloads = clean_file1_payloads[0:-9]

            file2_proto, file2_dstport, file2_payload = file2_payloads[0].split(",")
            clean_file2_payloads = file2_payload.replace("\n","")
            if clean_file2_payloads[0] == ":":
                clean_file2_payloads = clean_file2_payloads[1:]
            # if clean_file2_payloads.startswith("2e:31:30"):
            #     clean_file2_payloads = clean_file2_payloads[8:]
            if clean_file2_payloads[-1] == ":":
                clean_file2_payloads = clean_file2_payloads[0:-2]
            # if clean_file2_payloads.endswith("2e:31:30"):
            #     clean_file2_payloads = clean_file2_payloads[0:-9]
            #start with first file and find/write substrings
            with open(files_cmp1, "w") as json_file:
                s = difflib.SequenceMatcher(None, clean_file1_payloads, clean_file2_payloads)
                matching_blocks = s.get_matching_blocks()
                for block in matching_blocks:
                    if block[2] < 6:
                        continue
                    start = block[0]
                    end = block[0]+block[2]
                    if start != end:
                        str_block = clean_file1_payloads[start:end]
                        if str_block[1] == ":":
                            str_block = str_block[2:]
                        if str_block[-2] == ":":
                            str_block = str_block[0:-2]
                        str_block = str_block.replace(":","")
                        logging.debug("START" + str(start) + " END: " + str(end) + " CONVERTING: " + str(str_block))
                        #now decode the data into ascii
                        #thebytes = codecs.decode(str_block, "hex")
                        #ascii = codecs.decode(thebytes,"ASCII",'slashescape')
                        ascii = hexToASCII(str_block)
                        #json_file.write("Block_HEX (a=" + str(block[0]) + ",b=" + str(block[1]) + ",len="+str(block[2]) + ") : " + str_block + "\n")
                        json_file.write("X," + str(block[0]) + "," + str(block[1]) + "," + str(block[2]) + "," + file1_proto + "," + file1_dstport + ",|" + str_block + "|\n")
                        #json_file.write("Block_ASCII: (a=" + str(block[0]) + ",b=" + str(block[1]) + ",len="+str(block[2]) + ") : " + ascii + "\n")
                        json_file.write("A," + str(block[0]) + "," + str(block[1]) + "," + str(block[2]) + "," + file1_proto + "," + file1_dstport + "," + ascii + "\n")

            #move onto the second file and find/write substrings
            with open(files_cmp2, "w") as json_file:
                s = difflib.SequenceMatcher(None, clean_file2_payloads, clean_file1_payloads)
                matching_blocks = s.get_matching_blocks()
                for block in matching_blocks:
                    if block[2] < 6:
                        continue
                    start = block[0]
                    end = block[0]+block[2]
                    if start != end:
                        str_block = clean_file2_payloads[start:end]
                        if str_block[1] == ":":
                            str_block = str_block[2:]
                        if str_block[-2] == ":":
                            str_block = str_block[0:-2]
                        str_orig = str_block
                        str_block = str_block.replace(":","")
                        
                        logging.debug("START" + str(start) + " END: " + str(end) + " CONVERTING: " + str(str_block))
                                                #thebytes = codecs.decode(str_block, "hex")
                        #ascii = codecs.decode(thebytes,"ASCII",'slashescape')
                        ascii = hexToASCII(str_block)
                        #json_file.write("Block_HEX (a=" + str(block[0]) + ",b=" + str(block[1]) + ",len="+str(block[2]) + ") : " + str_block + "\n")
                        json_file.write("X," + str(block[0]) + "," + str(block[1]) + "," + str(block[2]) + "," + file2_proto + "," + file2_dstport + "," + str_block + "\n")
                        #json_file.write("Block_ASCII: (a=" + str(block[0]) + ",b=" + str(block[1]) + ",len="+str(block[2]) + ") : " + ascii + "\n")
                        json_file.write("A," + str(block[0]) + "," + str(block[1]) + "," + str(block[2]) + "," + file2_proto + "," + file2_dstport + "," + ascii + "\n")

        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.error("Error while looking for LCS")
            traceback.print_exception(exc_type, exc_value, exc_traceback)
            exit()

def extract_rules_from_lcs(replace_if_exists=True):
    logging.debug("Extracting rules from LCS")
    global rule_id
    for dir in cmp_files_lcsubstrings:
        for myfile in cmp_files_lcsubstrings[dir]:
            rules = []
            if dir not in cmp_files_rules:
                cmp_files_rules[dir] = []
            rules_filename = os.path.splitext(myfile)[0] + ".rules"
            cmp_files_rules[dir].append(rules_filename)
            if os.path.exists(rules_filename) and replace_if_exists == False:
                continue

            try:
                with open(myfile, "r") as lcsubstrings_file:
                    #logging.error("WORKING WITH: " + str(myfile))
                    lcssubstrings_data = lcsubstrings_file.readlines()
                
                for line in lcssubstrings_data:
                    if line.startswith("A"):
                        split_lcsubstring = line.split(",")
                        if len(split_lcsubstring) < 7:
                            logging.error("Found unusually short ASCII line: " + str(line))
                            continue
                        else:
                            #Create rules:
                            loc_f1 = split_lcsubstring[1]
                            loc_f2 = split_lcsubstring[2]
                            lcs_len = split_lcsubstring[3]
                            lcs_proto = split_lcsubstring[4]
                            mapped_lcs_proto = map_lcs_proto(lcs_proto)
                            lcs_dstport = split_lcsubstring[5]
                            lcs_content = "".join(split_lcsubstring[6:]).replace("\n","")
                            #sample rule for windows: suricata -c suricata.yaml -S C:\Users\Acosta\Desktop\scan_detector\tmp\dnsenum_001_int_scan_traffic_output_0\att\10.0.0.0_att_129.0.0.0_att.rules -r C:\Users\Acosta\Desktop\scan_detector\tmp\dnsenum_001_int_scan_traffic_output_0\att\10.0.0.0_att.pcap -l C:\Users\Acosta\Desktop\scan_detector\tmp\dnsenum_001_int_scan_traffic_output_0\att\ -k none
                            #may have to (re)install npcap on windows for suricata to work off of pcaps
                            rule_str = "alert " + str(mapped_lcs_proto) + " any any " + "-> any " + lcs_dstport + \
                                " (msg:\""+mapped_lcs_proto + "_alert\";" + \
                                " content:\"" + lcs_content + "\"" + ";" + \
                                "sid:"+rule_id + ";"\
                                ")"
                            int_rule_id = int(rule_id)
                            int_rule_id += 1
                            rule_id = str(int_rule_id)
                            #append it to the list of rules for the current file
                            rules.append(rule_str)
                
                    with open(rules_filename, "w") as rules_file:
                        for rule in rules:
                            rules_file.write(rule + "\n")

            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                logging.error("Error during directory rule generation")
                traceback.print_exception(exc_type, exc_value, exc_traceback)      

def extract_alerts_from_rules(replace_if_exists=True):
    logging.debug("Extracting Rules from Alerts")
    for dir in cmp_files_rules:
        #also get the pcap files in the directory:
        pathname = dir + "/**/*.pcap*"
        test_pcap_files = glob.glob(pathname, recursive=True)
        if dir not in cmp_files_alerts:
            cmp_files_alerts[dir] = []
        #making sure there are pcaps here
        if len(test_pcap_files) < 1:
            logging.error("Now PCAPs found in dir, skipping: " + str(dir))
            continue
        for myfile in cmp_files_rules[dir]:
            for test_pcap_file in test_pcap_files:
                logging.debug("Working with rule file: " + str(myfile) + " on pcap: " + str(test_pcap_file))
                myfile_basename = os.path.basename(myfile)
                test_pcap_basename = os.path.basename(test_pcap_file)
                alerts_filename = os.path.join(dir,os.path.splitext(myfile_basename)[0] + "_" + os.path.splitext(test_pcap_basename)[0] + ".alerts")
                default_log_filename = os.path.join(dir,"fast.log")
                cmp_files_alerts[dir].append(alerts_filename)

                if os.path.exists(alerts_filename) and replace_if_exists == False:
                    continue
                try:
                    #sample suricata command:
                    #suricata -c suricata.yaml -S C:\Users\Acosta\Desktop\scan_detector\tmp\dnsenum_001_int_scan_traffic_output_0\att\10.0.0.0_att_129.0.0.0_att.rules -r C:\Users\Acosta\Desktop\scan_detector\tmp\dnsenum_001_int_scan_traffic_output_0\att\10.0.0.0_att.pcap -l C:\Users\Acosta\Desktop\scan_detector\tmp\dnsenum_001_int_scan_traffic_output_0\att\ -k none
                    cmd = suricata_path + " -S " + myfile + " -r " + os.path.abspath(test_pcap_file) + " -l " + dir + " -k none"
                    logging.debug("Running suricata to obtain alerts: " + str(cmd) )
                    alert_data = subprocess.Popen(cmd)
                    alert_data.wait()
                except Exception as e:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    logging.error("Error during directory Suricata execution")
                    traceback.print_exception(exc_type, exc_value, exc_traceback)                 

                try:
                    #now rename the fast.log file to the intended alerts filename
                    shutil.move(default_log_filename, alerts_filename)
                except Exception as e:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    logging.error("Error renaming fast.log data to file")
                    traceback.print_exception(exc_type, exc_value, exc_traceback)    

def extract_dpktsnippet_from_lcs(replace_if_exists=True):
    logging.debug("Extracting dpkt snippet from LCS")
    global rule_id

    env = Environment(
	    loader=FileSystemLoader(template_path)
	    )

    for dir in cmp_files_lcsubstrings:
        for myfile in cmp_files_lcsubstrings[dir]:
            snippets = []
            if dir not in cmp_files_dpktsnippet:
                cmp_files_dpktsnippet[dir] = []
            #toolname = os.path.basename(os.path.normpath(os.path.dirname(myfile)))
            toolname = os.path.abspath(os.path.join(myfile,os.pardir,os.pardir))
            toolname = os.path.basename(toolname)
            toolname = toolname.split("_")[0]
            #logging.debug("TOOLNAME: " + str(toolname))
            dpktsnippet_filename = os.path.splitext(myfile)[0] + "_"+toolname+".py"
            cmp_files_dpktsnippet[dir].append(dpktsnippet_filename)
            if os.path.exists(dpktsnippet_filename) and replace_if_exists == False:
                continue
            if os.path.exists(myfile) == False:
                continue
            try:
                with open(myfile, "r") as lcsubstrings_file:
                    #logging.error("WORKING WITH: " + str(myfile))
                    lcssubstrings_data = lcsubstrings_file.readlines()
                
                for line in lcssubstrings_data:
                    if line.startswith("X"):
                        split_lcsubstring = line.split(",")
                        if len(split_lcsubstring) < 7:
                            logging.error("Found unusually short Hex line: " + str(line))
                            continue
                        else:
                            #Create rules:
                            loc_f1 = split_lcsubstring[1]
                            loc_f2 = split_lcsubstring[2]
                            lcs_len = split_lcsubstring[3]
                            lcs_proto = split_lcsubstring[4]
                            mapped_lcs_proto = map_lcs_proto(lcs_proto)
                            lcs_dstport = split_lcsubstring[5]
                            lcs_content = "".join(split_lcsubstring[6:]).replace("\n","")
                            #remove the first and last | since this isn't an ids rule
                            if lcs_content.startswith("|"):
                                lcs_content = lcs_content[1:]
                            if lcs_content.endswith("|"):
                                lcs_content = lcs_content[0:-1]
                            #remove any instances of .10
                            if lcs_content.startswith("2e3130"):
                                lcs_content = lcs_content[6:]
                            if lcs_content.endswith("2e3130"):
                                lcs_content = lcs_content[0:-7]
                            snippet = {"loc_f1": loc_f1, "loc_f2": loc_f2, "lcs_len": lcs_len, "mapped_lcs_proto": mapped_lcs_proto, "lcs_dstport": lcs_dstport, "lcs_content": lcs_content}
                            #append it to the list of rules for the current file
                            snippets.append(snippet)
                    i = 0
                    for snippet in snippets:
                        logging.debug("extract_dpktsnippet_from_lcs(): rendering det snippet")
                        out_filename = dpktsnippet_filename+"_"+snippet["lcs_dstport"]+"_"+str(i)
                        logging.debug("Writing to file: " + str(out_filename))
                        with open(out_filename, "w") as dpktsnippet_file:
                            dpktsnippet_file.write(env.get_template(template_name).render(jinja_mapped_lcs_proto=snippet["mapped_lcs_proto"], jinja_lcs_content=snippet["lcs_content"]))
                            #logging.debug("data: " + str(snippet["lcs_content"]))
                        i+=1
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                logging.error("Error during directory snippet generation")
                traceback.print_exception(exc_type, exc_value, exc_traceback)      

get_pcap_filenames()
#extract_json_from_pcap(replace_if_exists=False)
get_json_filenames()
#extract_payloads_from_json(replace_if_exists=True)
get_payload_filenames()
#extract_lcs_from_payloads(replace_if_exists=True)
get_lcs_filenames()
#extract_rules_from_lcs(replace_if_exists=False)
#get_rules_filenames()
#extract_alerts_from_rules(replace_if_exists=False)

extract_dpktsnippet_from_lcs(replace_if_exists=True)