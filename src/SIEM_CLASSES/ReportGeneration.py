#!/usr/local/bin/python3
#==========================================================================
#
#           File : ReportGenerator.py
#        Project : Mini-SIEM
#    Description : Converts the findings provided into dictionaries to be output in to json
#
#==========================================================================
#----------------
# Imports
#----------------
import logging
import os.path
import json
import sys

class ReportGeneration:
    # Generate json report, if stdout-only else write to file
    def generate_json_report(self, passed_findings, output_file, stdout_only):
        report = {
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "findings": []
        }

        #print(f"{passed_findings}")
        # Work through the returned findings
        for finding in passed_findings:

            # Add the dataclass converted to a dict to the findings array
            logging.debug(f"Adding finding to report [ {finding} ]")
            report["findings"].append(finding.convert_to_dict())

            # Update counts
            if finding.severity_level == "CRITICAL":
                report["summary"]["critical"] += 1
            elif finding.severity_level == "HIGH":
                report["summary"]["high"] += 1
            elif finding.severity_level == "MEDIUM":
                report["summary"]["medium"] += 1
            elif finding.severity_level == "LOW":
                report["summary"]["low"] += 1
            elif finding.severity_level == "INFO":
                report["summary"]["info"] += 1

        # After working through the findings, add the summary to the array
        report["findings"].insert(0, report["summary"])

        # Create json output
        findings_summary_json = json.dumps(report["findings"], indent=4, sort_keys=False)

        # Output based on specifications passed
        if stdout_only:
            print(findings_summary_json)
        else:
            output_basename = os.path.basename(output_file)
            try:
                with open(output_file, "w") as file:
                    file.write(findings_summary_json)
                logging.info(f"Writing findings to output file [ {output_basename} ]")
            except PermissionError:
                logging.exception(f"Failed to write output file [ {output_basename} ] - Permission Error")
                print(findings_summary_json)
            except IOError as e:
                logging.exception(f"Failed to write output file [ {output_basename} ] - I/O Error : {e}")
                print(findings_summary_json)
            except Exception as ee:
                logging.exception(f"Failed to write output file [ {output_basename} ] - Unexpected error {ee}")
                print(findings_summary_json)

