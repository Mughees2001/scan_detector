#!/bin/bash

python scan_start.py config/w_conn/10.0.0.0/nmap_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/spiderfoot_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/theHarvester_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/ike-scan_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/recon-ng_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/nikto_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/commix_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/skipfish_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/sqlmap_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/wpscan_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/cutycapt_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/dirb_specific.div
sleep 5
#python scan_start.py config/w_conn/10.0.0.0/dirbuster_specific.div
#sleep 5
python scan_start.py config/w_conn/10.0.0.0/ffuf_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/wfuzz_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/davtest_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/wapiti_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/whatweb_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/dnsenum_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/dnsrecon_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/fierce_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/lbd_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/wafw00f_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/enum4linux_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/nbtscan_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/swaks_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/onesixtyone_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/snmp-check_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/sslscan_specific.div
sleep 5
python scan_start.py config/w_conn/10.0.0.0/sslyze_specific.div