#!/usr/bin/python
import json
import logging
import os
import shutil
import shlex
import sys, traceback
from time import sleep
import threading
from jinja2 import Environment, FileSystemLoader
from subprocess import Popen
import subprocess

configs = {}
run_count = 0
lock = threading.Lock()

def readConfigsFromFile(filename):
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

		#Name of the collection
		name=g['collection-name']
		
		for p in experiment['config']:
			logging.debug("Config-name: " + str(p))

			if "scan-tool-output-path" in p:
				logging.debug("scan-tool-output-path: " + p['scan-tool-output-path'])
				scan_tool_output_path = p['scan-tool-output-path']
			else:
				scan_tool_output_path = None

			if "scan-tool-output-filename" in p:
				logging.debug("scan-tool-output-filename: " + p['scan-tool-output-filename'])
				scan_tool_output_filename = p['scan-tool-output-filename']
			else:
				scan_tool_output_filename = None

			if "scan-tool-output-argument" in p:
				logging.debug("scan-tool-output-argument: " + p['scan-tool-output-argument'])
				scan_tool_output_argument = p['scan-tool-output-argument']
			else:
				logging.debug("no scan-tool-output-argument specified")
				scan_tool_output_argument = None

			logging.debug("traffic-output-path: " + p['traffic-output-path'])
			logging.debug("num-iterations: " + str(p['num-iterations']))
			logging.debug("parallel-collection: " + str(p['parallel-collection']))
			for x in range(p['num-iterations']):
				#generate the core scenario file
				scen_name_it = str(x)+"_"+p['config-name']
				scen_gen_path_it = os.path.join(p['scenario-gen-output-path'],str(x))
				scen_gen_file_it = os.path.join(scen_gen_path_it,scen_name_it+".imn")
				makeDirectory(scen_gen_path_it, removeIfExists=False)

				traffic_output_path_it = os.path.join(p['traffic-output-path'],str(x))
				makeDirectory(traffic_output_path_it, removeIfExists=False)

				scan_tool_output_argument = ""
				if "scan-tool-output-argument" in p:
					scan_tool_output_argument = p['scan-tool-output-argument']

				scan_tool_output_path_it = ""
				if "scan-tool-output-path" in p:
					scan_tool_output_path_it = os.path.join(p['scan-tool-output-path'],str(x))
					makeDirectory(scan_tool_output_path_it, removeIfExists=False)

				scan_tool_output_file_it = scan_tool_output_path_it
				if "scan-tool-output-filename" in p:
					scan_tool_output_file_it = os.path.join(scan_tool_output_path_it,p['scan-tool-output-filename'])

				scan_port = None
				if "scan-port" in p:
					scan_port = p['scan-port']
					logging.debug("scan-port: " + scan_port )

				#unroll the list of arguments into a string
				scan_tool_args_str = ""
				if "scan-tool-arguments" in p:
					logging.debug("scan-tool-arguments: " + str(p['scan-tool-arguments']))
					for scan_tool_arg in p['scan-tool-arguments']:
						scan_tool_args_str += " " + scan_tool_arg

				scan_tool_cmd = g['scan-tool-path'] + " " + scan_tool_output_argument + " " +  scan_tool_output_file_it + " " + scan_tool_args_str
				start_scen_cmd = g['core-gui-path'] + " -b " + scen_gen_file_it
				
				if p['config-name'] not in configs['scenarios']:
					configs['scenarios'][p['config-name']] = {}
				if str(x) not in configs['scenarios'][p['config-name']]:
					configs['scenarios'][p['config-name']][str(x)] = {}
				configs['scenarios'][p['config-name']][str(x)] = {"scen_name_it": scen_name_it, \
					"scen_gen_path_it": scen_gen_path_it, \
					"scen_gen_file_it": scen_gen_file_it, \
					"scan_tool_output_path_it": scan_tool_output_path_it, \
					"scan_tool_output_file_it": scan_tool_output_file_it, \
					"traffic_output_path_it": traffic_output_path_it, \
					"scan_port": scan_port, \
					"scan_tool_cmd": scan_tool_cmd, \
					"start_scen_cmd": start_scen_cmd}

def genScenariosFromConfig(config_names=[]):
	logging.debug("makeDirectory() instantiated")
	#if no config_name specified go through all 
	if len(config_names) == 0:
		for scen_name in configs['scenarios']:
			its_data = configs['scenarios'][scen_name]
			for it_num in its_data:
				it = its_data[it_num]
				genScen(configs['global']['scenario-template-path'], it["scan_tool_cmd"], it["scen_gen_file_it"], it["traffic_output_path_it"]+"/", it["scan_port"])

	else:
		for scen_name in config_names:
			if scen_name in configs['scenarios']:
				its_data = configs['scenarios'][scen_name]
				for it_num in its_data:
					it = its_data[it_num]
					genScen(configs['global']['scenario-template-path'], it["scan_tool_cmd"], it["scen_gen_file_it"], it["traffic_output_path_it"]+"/", it["scan_port"])
			else:
				logging.error("Specified configname was not found: " + str(scen_name))


def makeDirectory(dirname, removeIfExists = True):
	logging.debug("makeDirectory() instantiated")

	try:					
		if os.path.exists(dirname) == True:
			if removeIfExists:
				shutil.rmtree(dirname)	
				if os.path.exists(dirname) == True:
					logging.error("Could not remove non-empty directory: " + str(dirname))
					exit()
				logging.debug("Dir removed -- Creating directory: " + str(dirname))
		else:
			logging.debug("Creating directory: " + str(dirname))
			os.makedirs(dirname)

	except Exception as e:
		exc_type, exc_value, exc_traceback = sys.exc_info()
		logging.error("Error during directory creation")
		traceback.print_exception(exc_type, exc_value, exc_traceback)
		exit()

def genScen(templatepath, scantool_cmd, scenariooutfile, trafficoutdir, scan_port = None):
	logging.debug("genScen() instantiated")
	logging.debug("genScen(): reading template file")
	logging.debug("Using templatepath: " + str(templatepath))
	templateDir = os.path.dirname(templatepath)
	templateName = os.path.basename(templatepath)

	env = Environment(
		loader=FileSystemLoader(templateDir)
		)
	logging.debug("genScen(): rendering scenario file")
	
	with open(scenariooutfile, "w") as out:
		out.write(env.get_template(templateName).render(jinjaScanCmd=scantool_cmd, jinjaTrafficDir=trafficoutdir, jinjaScanPort=scan_port))

def runScenariosFromConfig(config_names=[]):
	logging.debug("runScenariosFromConfig() instantiated")
	#retrieve command for config_name
	#in the case where this is the first scenario executed:
	if len(config_names) == 0:
		for scen_name in configs['scenarios']:
			its_data = configs['scenarios'][scen_name]
			for it_num in its_data:
				it = its_data[it_num]
				runScenario(it["start_scen_cmd"], it["traffic_output_path_it"]+"/")
	#in the case where other scenarios are running, output looks different = parse differently
	else:
		for scen_name in config_names:
			if scen_name in configs['scenarios']:
				its_data = configs['scenarios'][scen_name]
				for it_num in its_data:
					it = its_data[it_num]
					runScenario(it["start_scen_cmd"], it["traffic_output_path_it"]+"/")
			else:
				logging.error("Specified configname was not found: " + str(scen_name))

def runScenario(cmd, trafficpath):
	global run_count
	logging.debug("runScenario() instantiated")
	time_between_parallel_runs = configs['global']["time-between-parallel-starts"]
	max_parallel_runs = configs['global']["max-parallel-runs"]
	#check if we have fewer parallel running than our restrictions:
	logging.error("RUN Count: " + str(run_count))
	while lock.acquire() == False:
		logging.debug("Lock in place, waiting to acquire")
		sleep(1)
	try:
		while run_count >= max_parallel_runs:
			logging.debug("Maximum number of runs reached " + str(max_parallel_runs))
			logging.debug("Waiting one second before checking again...")
			sleep(1)

		if time_between_parallel_runs > 0:
			logging.debug("Waiting the prescribed time between parallel starts: " + str(time_between_parallel_runs))
			sleep(time_between_parallel_runs)
		t = threading.Thread(target=workerThread, args=(cmd, trafficpath+"completed.scan"))
		run_count +=1
		t.start()
	finally:
		lock.release()

def workerThread(cmd, done_id_filename):
	try:
		global run_count
		logging.debug("workerThread() instantiated; run_count: " + str(run_count))
		#start thread with command
		output = subprocess.check_output(shlex.split(cmd), shell=False, encoding="utf-8")
		logging.debug("Started process: " + str(cmd))
		#look and save through command output for session id
		if "Session id is" in output:
			curr_session = output.split("Session id is ")[1].split(".")[0]
		else:
			regdata = output.split("REG")[1]
			session_list = regdata.split("sids=")[1].split(",")[0].split("|")
			curr_session = session_list[-1]
		logging.debug("Session started: " + str(curr_session))
		logging.debug("Wait loop until complete")
		#loop until the done_id_filename exists
		logging.debug("Checking for file: " + done_id_filename)
		wait_cycles = 1
		while os.path.exists(done_id_filename) == False:
			logging.debug("Not found, waiting for existance of: " + done_id_filename + " wait-cycle: " + str(wait_cycles))
			wait_cycles += 1
			sleep(1)
		end_scen_cmd = configs['global']['core-gui-path'] + " -c " + curr_session
		output = subprocess.check_output(shlex.split(end_scen_cmd), shell=False, encoding="utf-8")
		logging.debug("Killing session with command: " + str(cmd))
		logging.debug("OUTPUT: " + str(output))
	except Exception as e:
		exc_type, exc_value, exc_traceback = sys.exc_info()
		logging.error("Error during core scenario execution")
		traceback.print_exception(exc_type, exc_value, exc_traceback)	
	finally:
		run_count-=1

if __name__ == "__main__":
	logging.getLogger().setLevel(logging.DEBUG)
	logging.debug("Starting Program")
	if len(sys.argv) != 2:
		logging.error("Usage: scan_start.py <config file>")
		exit()
	#filename = '/home/research/div_experimentation/experiment-001.div'
	filename = sys.argv[1]
	readConfigsFromFile(filename)
	genScenariosFromConfig()
	runScenariosFromConfig()
