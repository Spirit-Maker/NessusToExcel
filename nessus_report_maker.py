#!/usr/bin/env python3

import requests
import json
import time
import pandas as pd
import xlsxwriter
import datetime
import os
import glob
import ipaddress
import warnings
import config
import logging, coloredlog
from tabulate import tabulate
from sys import exit



warnings.filterwarnings("ignore")  # To ignore SSL errors if they occur
logging.basicConfig(
    format='%(asctime)s %(filename)s:%(lineno)d [%(levelname)s] %(message)s',
    handlers=[coloredlog.ConsoleHandler()],
    level=logging.DEBUG
)
logger = logging.getLogger(__name__)

# Validate IP address Nessus
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Download Nessus file
def download_file(url, file_name):
    # Note the stream=True parameter below
    try:
        payload = {}
        headers = {'X-ApiKeys': api_key}
        with requests.get(url, headers=headers, data=payload, verify=False, stream=True) as r:
            r.raise_for_status()
            with open(file_name, 'wb') as f:
                for chunk in r.iter_content(chunk_size=None):
                    if chunk:
                        f.write(chunk)
    except Exception as e:
        logger.error(f"Unknown Error Occured {e}")

# list folders and scans from nessus
def list_folders_and_scans():
    try:
        url = f"https://{s_address}/scans"
        payload = {}
        headers = {'X-ApiKeys': api_key}
        
        response = requests.request("GET", url, headers=headers, data=payload, verify=False)
        response.raise_for_status()
        
        data = json.loads(response.text)
        return data.get("folders", []), data.get("scans", [])
    
    except Exception as e:
        logger.error(f"Unknown Error Occured {e}")

# Export Nessus Report
def export_report(scan_id, report_format):
    logger.debug(f"Export Report against {scan_id}")
    try:
        url = f"https://{s_address}/scans/{scan_id}/export"
        payload = json.dumps({"format": report_format})
        headers = {'Content-Type': 'application/json', 'X-ApiKeys': api_key}

        response = requests.post(url, headers=headers, data=payload, verify=False)
        response.raise_for_status()

        return json.loads(response.text)
    
    except Exception as e:
        logger.error(f"Unknown Error Occured {e}")

# Downloading Report Wait
def wait_for_report(scan_id, file_id, timeout=600):
    try:
        url = f"https://{s_address}/scans/{scan_id}/export/{file_id}/status"
        payload = {}
        headers = {'X-ApiKeys': api_key}

        start_time = time.time()
        while True:
            response = requests.get(url, headers=headers, data=payload, verify=False)
            response.raise_for_status()

            status_data = json.loads(response.text)
            if status_data.get("status") == "ready":
                break

            if time.time() - start_time >= timeout:
                raise TimeoutError("Report export timed out")

            time.sleep(1)
    
    except Exception as e:
        logger.error(f"Unknown Error Occured {e}")


# Main function for nessus report download. Cmplete logic here
def nessus_downloader():
    logging.debug("Reading config from config file")
    # Reading config file
    global s_address,a_key, s_key, api_key, output_directory

    folders, scans = list_folders_and_scans()

    if not folders and not scans:
        logger.error("No folders or scans found on the server.")
        exit(0)
        
    logger.debug("Folders and Scans were found.")

    print("Folders: ")
    folder_data = [[folder["id"], folder["name"]] for folder in folders]
    folder_header = ["ID", "Name"]
    print(tabulate(folder_data, folder_header, tablefmt="pretty", colalign=["center", "right"]))

    scan_list_folder = 123
    folder_ids = [folder["id"] for folder in folders]

    logger.debug(f"{folder_ids}")

    while True:
        logger.debug("Input folder id for listing scans.")
        try:
            scan_list_folder = int(input("Please provide folder id to list scan: "))
        except Exception as e:
            logger.error("Cannot convert input to int, Invalid input")
            continue

        if scan_list_folder in folder_ids:
            break
        else:
            logger.warning("Please provide valid ID")
            continue
        
   
    scan_data = [[scan["folder_id"],scan["id"], scan["name"]] for scan in scans if scan["folder_id"] == scan_list_folder]
    scan_ids = [scan[1] for scan in scan_data]

    scan_header = ["Folder_ID","ID", "Name"]
    print(tabulate(scan_data, scan_header, tablefmt="pretty",colalign=["center","center", "right"]))

    logger.debug(f"{scan_ids}")


    selected_scan_ids = None

    while True:
        logger.debug("Input for scan ids")
        temp_scan_list_ids = input('Enter scan id (You can enter multiple scans. Example: 105,240,196) :')
        try:
            selected_scan_ids = [int(id.strip()) for id in temp_scan_list_ids.split(",")]
            for i in selected_scan_ids:
                if i not in scan_ids:
                    logger.critical(f"Cannot find scan id: {i}")
                    try:
                        selected_scan_ids.remove(i)
                        logger.debug(f"Removed Scan_id {i} from selected scan ids ")
                    except:
                        logger.warning(f"Could not remove Scan_id {i} from selected scan ids ")
            break
        except Exception as e:
            logger.error("Could not convert input to list of IDs. Retry")
            continue

    if not selected_scan_ids:
        logger.warning(f"Selected IDs are None, exiting.")
        exit(1)

    while True:
        logger.debug("Input for report output")
        # print("Choose the report format:")
        # print("1. CSV")
        # print("2. Nessus")
        # report_format = input()
        report_format_choice = "1"
        if report_format_choice == "1":
            report_format = "csv"
            break
        elif report_format_choice == "2":
            report_format = "nessus"
            break
        else:
            print("Invalid input. Please choose 1 or 2.")

    for scan_id in selected_scan_ids:
        try:
            scan = next(scan for scan in scans if scan["id"] == scan_id)
            file_name = f"{scan['name']}_{datetime.datetime.now():%d-%m-%Y}.{report_format}"
            file_path = os.path.join(output_directory, file_name)

            tf_json = export_report(scan_id, report_format)
            logger.info(f"Exporting {scan['name']} report...")

            wait_for_report(scan_id, tf_json["file"])

            url = f"https://{s_address}/scans/{scan_id}/export/{tf_json['file']}/download"
            download_file(url, file_path)

            print(f"Report saved as: {file_path}")
        except Exception as e:
            print(f"Error exporting scan {scan_id}: {str(e)}")

# Merge Nessus report and Assets details file   
def df_inner_join(combined_df, assets_file, on_column, header=0):
    try:
        if assets_file.endswith(".xlsx"):
            logger.info("Reading assets_list file via pandas - excel")
            assets_df = pd.read_excel(assets_file, header=header)
        elif assets_file.endswith(".csv"):
            logger.info("Reading assets_list file via pandas - csv")
            assets_df = pd.read_csv(assets_file, header=header)
        else:
            logger.warning("Please share valid file. ")
    except Exception as e:
        logger.error("Cannot read assets list, please check")

    # Preprocess the columns in the combined_df
    combined_df[on_column] = combined_df[on_column].str.strip()  # Strip spaces from the specified column

    # Preprocess the columns in the assets_df (assuming the column names match with combined_df)
    assets_df[on_column] = assets_df[on_column].str.strip()  # Strip spaces from the specified column
    
    result_inner = None
    try:
        result_inner = assets_df.merge(combined_df, on=on_column, how='inner')
    except Exception as e:
        logger.error(f"Exception occured while joining sheets. {e}")
        exit(4)
    # result_inner.to_excel("merged_data.xlsx", index=False)
    return result_inner

# Merge Nessus csv reports
def merge_nesssus_csv_reports():
    # """Merge nessus and csv reports into one."""
    logger.info("Finding all csv files for report")
    global output_directory, combined_directory
    nessus_csvs =  glob.glob(f"{output_directory}/*.csv")

    global combined_directory

    dataframes_list = []
    for csv_file in nessus_csvs:
        df = pd.read_csv(csv_file)
        dataframes_list.append(df)

    # Assuming you want to perform a union on the dataframes based on their column names
    if dataframes_list:
        union_df = None
        try:
            logger.info("Merging csv files.")
            union_df = pd.concat(dataframes_list, ignore_index=True)
            union_df.rename(columns={'Host': 'IP Address'}, inplace=True)
            union_df.to_excel(f"{combined_directory}/combined_report_" + datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S").replace(" ", "_") + ".xlsx", index=False)
            union_df.to_csv(f"{combined_directory}/combined_report_" + datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S").replace(" ", "_") + ".csv", index=False)

            logger.info("Merging of csv files is successful.")

        except Exception as e:
            logger.error("Could not combine csv files")
            exit(2)
        
        # Choice for deleting files.
        while True:
            delete_choice = input("Would you like to delete downloaded reports (Y/N): ")
            if delete_choice.lower().strip() in ['y', 'yes']:
                for filename in nessus_csvs:
                    try:
                        os.remove(filename)
                        logger.debug(f"Successfully deleted file: {filename}")
                    except Exception as e:
                        logger.error(f"Could not remove file: {filename}")
                break

            elif delete_choice.lower().strip() in ['n', 'no']:
                break
            else:
                print("Please choose a valid choice: Yes or No")

        return union_df
    else:
        logger.warning("No CSV files found in the directory. Cannot create combined csv report")
        exit(3)


def report_data_cleaning(report_df, headers):
    columns_to_keep = headers

    # Changing column names for report
    try:
        logger.debug("Changing column names from the report dataframe")
        report_df.rename(columns={'Name': 'Vulnerability Name'}, inplace=True)
        report_df.rename(columns={'Solution': 'Mitigation Steps'}, inplace=True)
        report_df.rename(columns={'Risk': 'Severity'}, inplace=True)
        report_df.rename(columns={'Synopsis': 'Risks'}, inplace=True)
        report_df.rename(columns={'Information Asset Detail': 'Affected Devices'}, inplace=True)
    except Exception as e:
        logger.error("Could not rename column names.")

    # drop columns that are not required
    columns_to_drop = [col for col in report_df.columns if col not in columns_to_keep]
    report_df = report_df.drop(columns=columns_to_drop)
    report_df["Team Comments"] = ""
    report_df["Status"] = "Open"

    # Fill empty cells in the "Criticality" column with the new value
    report_df['Severity'].fillna('Info', inplace=True)
    

    logger.debug("Removing all duplicates.")
    report_df = report_df.drop_duplicates()

    return report_df[headers]
    
# Generate Excel report
def excel_report_generator(report_df, headers):
    logger.info("Generating Excel Report.")
    # Create a Pandas Excel writer using xlsxwriter as the engine
    timestamp = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S").replace(" ", "_")
    excel_file = f"{report_output_directory}/va_report_{timestamp}.xlsx"

    # Reorder the DataFrame columns to match the specified order
    report_df = report_df[headers]
    report_df = report_df.fillna("")
    # Initialize the Excel writer with xlsxwriter
    writer = pd.ExcelWriter(excel_file, engine='xlsxwriter')

    # Convert the DataFrame to an Excel object
    report_df.to_excel(writer, index=False, sheet_name='Vulnerability Report')

    # Access the XlsxWriter workbook and worksheet objects
    workbook = writer.book
    worksheet = writer.sheets['Vulnerability Report']

    # Create a format for the header cells
    header_format = workbook.add_format({
        'bold': True,
        'text_wrap': True,
        'align': 'center',
        'valign': 'center',  # Align text to the top of the cell
        'fg_color': '#003300',  # Header background color (orange)
        'border': 1,
        'border_color': '#000000',  # Border color (black)
        'color' : 'white',
    })

    # Create a format for data cells
    data_format = workbook.add_format({
        'text_wrap': True,
        'align': 'top',  # Align text to the top of the cell
        'valign': 'top',  # Align text to the top of the cell
        'border': 1,
        'border_color': '#000000'  # Border color (black)
    })

    # Apply the header format to the header row
    for col_num, value in enumerate(headers):
        worksheet.write(0, col_num, value, header_format)
        max_len = max([len(str(value))] + [len(str(val)) for val in report_df.iloc[:, col_num]])
        if max_len > 40:
            max_len = 40
        elif max_len < 10:
            max_len = 10

        worksheet.set_column(col_num, col_num, max_len)  # Adjust column width

    # Apply the data format to all data cells
    for row_num in range(1, len(report_df) + 1):
        for col_num, value in enumerate(report_df.iloc[row_num - 1]):
            try:
                worksheet.write(row_num, col_num, value, data_format)
            except Exception as e:
                logger.debug(f"Could not write value row:{row_num}, column:{col_num}")
                logger.error(f"{e}")

    # Close the Pandas Excel writer and save the Excel file
    writer.close()


def main():
    # Declaring globals
    global s_address,a_key, s_key, api_key, output_directory, combined_directory, report_output_directory
    s_address = config.SERVER_ADDRESS
    a_key = config.ACCESS_KEY
    s_key = config.SECRET_KEY
    api_key = f"accessKey={a_key}; secretKey={s_key};"
    output_directory = config.OUTPUT_DIRECTORY
    combined_directory = config.COMBINED_OUTPUT_DIRECTORY
    report_output_directory = config.REPORT_OUTPUT_DIRECTORY

    assets_file = ""   # Excel Sheet to refer as master sheet

    # if output path does not exists
    if not os.path.exists(output_directory):
        logger.info(f"Creating directory {output_directory}.")
        os.makedirs(output_directory)

    if not os.path.exists(combined_directory):
        logger.info(f"Creating directory {combined_directory}.")
        os.makedirs(combined_directory)

    if not os.path.exists(report_output_directory):
        logger.info(f"Creating directory {report_output_directory}.")
        os.makedirs(report_output_directory)
                    
    # datafram for combining multiple nessus reports
    combined_df = None

    # Assets lists for details addition

    # Choice for combined_df from existing or download reports and generate
    while True:
        existing_report_choice = input("Would you like to use existing combined report (Y/N): ")
        if existing_report_choice.lower().strip() in ['y', 'yes']:
            combined_files = {}
            combined_files_list = glob.glob(f"{combined_directory}/*.csv")
            if combined_files_list:
                # Assign unique keys to each filename
                for i, filename in enumerate(combined_files_list):
                    combined_files[i] = filename
            else:
                logger.warning("Could not find cobined files. Please try download reports.")
                continue
            
            # Prompt user with list of available reports and allow them to select one by number
            print("Available Combined Files : ")
            folder_data = [[key, value] for key, value in combined_files.items()]
            folder_header = ["ID", "FileName"]
            print(tabulate(folder_data, folder_header, tablefmt="pretty", colalign=["center", "right"]))

            combined_files_choice = None
            while True:
                logger.debug("Input file id: ")
                try:
                    combined_files_choice = int(input("Please provide folder id to list scan: "))
                except Exception as e:
                    logger.error("Cannot convert input to int, Invalid input")
                    continue

                if combined_files_choice in combined_files.keys():
                    break
                else:
                    logger.warning("Please provide valid ID.")
                    continue
            
            # reading chosen combined file
            try:
                combined_df = pd.read_csv(combined_files[combined_files_choice])
            except:
                logger.error(f"Could not read {combined_df}. ")

            break
            
        elif existing_report_choice.lower().strip() in ['n', 'no']:
            nessus_downloader()
            combined_df = merge_nesssus_csv_reports()
            break
        else:
            print("Please choose a valid choice: Yes or No")


    final_df = None

    while True:
        existing_report_choice = input("Would you like to use merge report with master sheet (Y/N): ")
        if existing_report_choice.lower().strip() in ['y', 'yes']:
            final_df = df_inner_join(combined_df, assets_file, on_column='IP Address', header=1)
            headers = ["Vulnerability Name", "Description", "Severity", "Risks", "Mitigation Steps", "Affected Devices", "IP Address", "Port" ,  "Device Type", "Vendor & Company","OS Details", "Team Comments", "Status"]
            break
        elif existing_report_choice.lower().strip() in ['n', 'no']:
            final_df = combined_df
            headers = ["Vulnerability Name", "Description", "Severity", "Risks", "Mitigation Steps", "IP Address", "Port" ,"Team Comments", "Status"]
            break
        else:
            print("Please choose a valid choice: Yes or No")

    if final_df is None:
        logger.warning("Final Dataframe is None or Empty")
        exit(5)
    
    final_df = report_data_cleaning(final_df, headers)
    excel_report_generator(final_df, headers)
    # pdf_report_generator(final_df)

if __name__ == "__main__":
    main()
