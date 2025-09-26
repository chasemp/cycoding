import sys, json, os, argparse, requests
import cycode_lib.cycode_token as tok
import cycode_lib.rig_functions as rig

##
## Author: Wes MacKay
##
##

# load query file
def load_query_file(query_file):
    raw_query = ""
    if ".json" in query_file:
        # get data for query from file
        with open(os.path.normpath(query_file), 'r') as file:
            raw_query = json.load(file)
    # query contents should be passed directly
    else:
          print('Query is not a JSON file, exiting.')
          sys.exit(1)
    return raw_query

# write data to filename as JSON file
def write_report_file(data, filename):
    if filename == "" or filename == None:
        filename = "cycode_report"
    with open(filename, 'wb') as file:
        file.write(data)


## main function
if __name__=="__main__":
    ## Need to export CYCODE_CLIENT_ID and CYCODE_CLIENT_SECRET environment variables
    #os.environ['CYCODE_CLIENT_ID'] = '1234567890'
    #os.environ['CYCODE_CLIENT_SECRET'] = '1234567890'
    #OR
    #export CYCODE_CLIENT_ID=1234567890 && export CYCODE_CLIENT_SECRET=1234567890

    ## cli args below

    parser = argparse.ArgumentParser()

    parser.add_argument("-q", "--query-file", help = "A file featuring a RIG query from Cycode (.json)", required=True)
    parser.add_argument("-o", "--output-file", help = "The output file name (.csv or .json)", default="cycode_report")
    parser.add_argument("-f", "--output-format", help = "The output format (CSV or JSON)", default="CSV", choices=["CSV", "JSON"])
    args = parser.parse_args()

    output_file_name = args.output_file
    query_file_name = args.query_file
    output_format = args.output_format
    cycode_api_url = "https://api.cycode.com"
    try:
        token = tok.get_cycode_token(client_id=os.environ['CYCODE_CLIENT_ID'], client_secret=os.environ['CYCODE_CLIENT_SECRET'], cycode_api_url=cycode_api_url)
    except KeyError as k:
        print("Cannot find CYCODE_CLIENT_ID and/or CYCODE_CLIENT_SECRET environment variables.\nEnsure they exist by echoing them in your command environment")
    except requests.HTTPError as e:
        print(f"Error getting token, http error={e}")
        exit(1)

    ## load query from file
    query = load_query_file(query_file_name)

    try:
        report_text = rig.execute_and_download_rig_query(raw_query=query, output_format=output_format, cycode_api_url = cycode_api_url, token=token)
    except requests.HTTPError as e:
        print(f"Report not downloaded, HTTPError={e}")

    write_report_file(report_text, output_file_name)