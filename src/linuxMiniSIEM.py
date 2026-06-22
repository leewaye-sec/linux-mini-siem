#!/usr/local/bin/python3
#==========================================================================
#
#           File : linuxMiniSIEM.py
#        Project : Mini-SIEM
#    Description : Ingests and analyses security logs for defined events
#
#==========================================================================
#--------------------
# Imports
#--------------------
import sys
import os
import argparse
import logging

from pathlib import Path
import textwrap
from datetime import datetime

#--------------------
# Global Variables
#--------------------
# Timestamp
global TIMESTAMP
timestamp_dirty = datetime.now()
TIMESTAMP = timestamp_dirty.strftime("%Y%m%d_%H%M%S")

# Path Definitions
global CWD
CWD = os.path.abspath(os.getcwd())
CWD = CWD + "/"

# Create root directory
global PROJECT_ROOT
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

#----------------
# Class Path / Definitions / Imports
#----------------
# Class directory path addition to path
global CLASS_PATH
CLASS_PATH = CWD + "SIEM_CLASSES"
sys.path.append(CLASS_PATH)

# Import DataClass and Class Definitions
from SIEM_CLASSES.SIEMLogParser import siemLogParser
from SIEM_CLASSES.SIEMDetectionEngine import SIEMDetectionEngine
from SIEM_CLASSES.ReportGeneration import ReportGeneration

#--------------------------------------------------------------------------
# Functions
#--------------------------------------------------------------------------
#==============
# Determines if passed path exists
#==============
def verifyFilePath(passed_log_path):

    logging.debug(f"Verifying log path [ {passed_log_path} ]")

    # Verify file exists
    passed_path = Path(passed_log_path)

    # Make sure the log exists
    if passed_path.is_file():
        return True
    else:
        return False

#==============
# Wrapper function for SIEM utilities
#==============
def siemWrapper(input_log):

    # Verify path exists
    if not verifyFilePath(input_log):
        logging.error(f"Unable to verify log path [ {input_log} ]")
        sys.exit()

    # Create the needed objects
    log_parser = siemLogParser()
    siem_engine = SIEMDetectionEngine()
    log_findings = []

    # Begin log ingest and processing
    logging.info(f"Attempting ingest of log file [ {input_log} ]")
    try:
        with open(input_log, "r") as ifile:
            # Iterate through the lines and standardize into an event
            logging.debug(f"Ingest log opened and ingesting")
            for line in ifile:
                # Skip empty lines
                if not line.strip():
                    continue

                log_event = log_parser.parseLogLine(line)

                # Ensure that the event isn't empty / None
                if not log_event:
                    continue

                # Once the log event is standardized:
                #   Proccess the event(s) and create findings via detectors
                #   Once findings are processed, add to log_findings array
                returned_log_finding = siem_engine.process(log_event)
                if returned_log_finding:
                    log_findings.extend(siem_engine.process(log_event))


        # Generate report from findings
        logging.info(f"Compiling findings in to JSON report")
        ReportGeneration().generate_json_report(log_findings, OUTPUT, PRINT)

    except FileNotFoundError:
        logging.exception(f"File not found [ {input_log} ]")
    except PermissionError:
        logging.exception(f"Permissions error for file [ {input_log} ]")
    except Exception as e:
        logging.exception(f"Unexpected error while reading file [ {e} ]")


#==========================================================================
# Main
#==========================================================================
def main():
    
    # Grab the script version
    script_version = sys.argv[0]

    # Initial Help Menu Output
    parser = argparse.ArgumentParser(
        prog = script_version,
        description = "Linux System Security Information and Even Management (SIEM)",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent(f'''
            Examples:
                Show options associated with script
                    => python3 {script_version} -h
                
                Run script with input log
                    => python3 {script_version} -f </path/to/input.log>
                
                Run script with input log and console only output
                    => python3 {script_version} -f </path/to/input.log> -p
                    
            '''))

    # Start considering logging
    global verbose_logging
    verbose_logging = False

    # Set some 'global' options
    parser.add_argument('-i', '--input', required=True, help='Specify input log path')
    parser.add_argument("-v", "--verbose", action="store_true", help="Logging output will be verbose")
    parser.add_argument('-p', '--print', action='store_true', help='Print results to STDOUT only')
    parser.add_argument('-o', '--output', help='Specify audit report path/name')


    #========================
    # Process Passed Arguments
    #========================
    args = parser.parse_args()

    # Set logging levels
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s \t[[ %(levelname)s ]] \t%(message)s',datefmt='%Y-%m-%d %I:%M:%S %p')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s \t[[ %(levelname)s ]] \t%(message)s',datefmt='%Y-%m-%d %I:%M:%S %p')

    # Handle some global variables
    global OUTPUT
    global PRINT

    # Determine output name (even if stdout only)
    output_filename = f"{CWD}{TIMESTAMP}_SIEM_Findings.json"
    OUTPUT = args.output if args.output else output_filename

    # Determine print
    PRINT = args.print

    # Call the SIEM wrapper - pass the input log path
    siemWrapper(args.input)

if __name__ == "__main__":
    main()