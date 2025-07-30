#!/usr/bin/python
import json
import logging
import os
import shutil
import sys, traceback
from time import sleep
from subprocess import Popen

configs = {}

def rmDirsFromConfigsFromFile(filename):
	logging.debug("readConfigFile() instantiated")
	with open(filename) as json_input:
		experiment = json.load(json_input)
		logging.info("Reading JSON file")
		
		logging.debug("readConfigFile(): Reading global parameters")
		g = experiment['global']
		logging.debug("collection-name: " + g['collection-name'])
		logging.debug("core-gui-path: " + g['core-gui-path'])
		logging.debug("scan-tool-path: " + g['scan-tool-path'])
		logging.debug("scenario-template-path: " + g['scenario-template-path'])
		logging.debug("max-parallel-runs: " + str(g['max-parallel-runs']))
		logging.debug("time-between-parallel-starts: " + str(g['time-between-parallel-starts']))
		configs['global'] = g
		configs['scenarios'] = {}
		
		for p in experiment['config']:
			logging.debug("Config-name: " + str(p))

			logging.debug("traffic-output-path: " + p['traffic-output-path'])
			logging.debug("num-iterations: " + str(p['num-iterations']))
			logging.debug("parallel-collection: " + str(p['parallel-collection']))
			for x in range(p['num-iterations']):
				#generate the core scenario file
				scen_gen_path_it = os.path.join(p['scenario-gen-output-path'],str(x))
				
				rmDirectory(scen_gen_path_it)

				traffic_output_path_it = os.path.join(p['traffic-output-path'],str(x))
				rmDirectory(traffic_output_path_it)

				scan_tool_output_path_it = ""
				if "scan-tool-output-path" in p:
					scan_tool_output_path_it = os.path.join(p['scan-tool-output-path'],str(x))
					rmDirectory(scan_tool_output_path_it)

def rmDirectory(dirname):
	logging.debug("makeDirectory() instantiated")

	try:					
		if os.path.exists(dirname) == True:
			shutil.rmtree(dirname)	
			if os.path.exists(dirname) == True:
				logging.error("Could not remove non-empty directory: " + str(dirname))
				exit()
			logging.debug("Dir removed: " + str(dirname))
		else:
			logging.debug("Dir does not exist, skipping: " + str(dirname))

	except Exception as e:
		exc_type, exc_value, exc_traceback = sys.exc_info()
		logging.error("Error during directory creation")
		traceback.print_exception(exc_type, exc_value, exc_traceback)
		exit()

if __name__ == "__main__":
	logging.getLogger().setLevel(logging.DEBUG)
	logging.debug("Starting Program")
	if len(sys.argv) != 2:
		logging.error("Usage: clear_data.py <config file>")
		exit()
	#filename = '/home/research/div_experimentation/experiment-001.div'
	filename = sys.argv[1]
	rmDirsFromConfigsFromFile(filename)
	
