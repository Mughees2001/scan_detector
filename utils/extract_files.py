import glob
import shutil
import os
import sys, traceback
import logging
import platform

logging.getLogger().setLevel(logging.DEBUG)

search_directory = ".."
search_directory = search_directory.replace("utils", "")
target_directory = "processed_data"
pathname1 = os.path.join(search_directory, "10.0.0.0/**/*.pcap*")
print(pathname1)
pathname2 = os.path.join(search_directory, "129.0.0.0/**/*.pcap*")
filesA = glob.glob(pathname1, recursive=True)
filesB = glob.glob(pathname2, recursive=True)
files = filesA + filesB

def process_files():
    for file in files:
        newfile = check_system_type(file)
        if newfile.startswith("./") or newfile.startswith(".\\"):
            newfile = newfile[2:]
        if newfile.startswith("."):
            newfile = newfile[2:]
        if newfile.startswith("_"):
            newfile = newfile[1:]
        splitfilename = newfile.split("_")
        print(splitfilename)
        if len(splitfilename) < 8:
            logging.error("File is not valid for extraction: ORIG: " + str(file) + "\nMOD: " + str(newfile))
        base_dir = splitfilename[1]+"_"+splitfilename[2]+"_"+splitfilename[3]+"_"+splitfilename[4]+"_"+splitfilename[5]+"_"+splitfilename[6]+"_"+splitfilename[7]
        print("base"+base_dir)
        cmp_dir = "_".join(splitfilename[8:])
        print(" cmp "+cmp_dir)
        cmp_dir = cmp_dir.replace(".pcap","")        
        combined_dirs = os.path.join(target_directory,base_dir,cmp_dir)
        print("combine: "+combined_dirs)
        final_filename = splitfilename[0]+"_"+"_".join(splitfilename[8:])
        print("final"+final_filename)
        try:
            if os.path.exists(combined_dirs) == False:
                os.makedirs(combined_dirs)
            logging.debug("Copying: " + str(file) + " TO: " + str(os.path.join(combined_dirs, final_filename)))
            final_location = os.path.join(combined_dirs, final_filename)
            shutil.copy2(file, final_location)
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.error("Error during directory creation")
            traceback.print_exception(exc_type, exc_value, exc_traceback)
def check_system_type(file):
    if platform.system() == "Windows":
        return file.replace("\\","_")
    elif platform.system() == "Linux":
        return file.replace("/","_")
    else:
        logging.error("system is not windows or Linux...")
        exit(-1)

process_files()
