import requests, logging,time

def execute_rig_query(raw_query: str, output_format: str, cycode_api_url:str, token:str) -> str:
    if output_format != "CSV" and output_format != "JSON":
        raise ValueError("file format must be CSV or JSON")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer " + token
    }

    query = {
                "output_format": output_format,
                "graph_query_entity": raw_query,
                "parameters": {
                    "name": "query-modified"
                }
            }
    logging.info("Creating report")
    url = f"{cycode_api_url}/report/api/v2/report/standalone-execute"

    response=requests.post(url,headers=headers, json=query)
    if response.ok != True:
        response.raise_for_status()
    execution_id = response.json().get('report_executions')[0].get('id')
    return execution_id

def download_rig_results(execution_id: str, cycode_api_url:str, token:str) -> str:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer " + token
    }

    url = f"{cycode_api_url}/report/api/v2/report/executions?executions_ids[0]={execution_id}&include_orphan_executions=true"

    status = "Pending"
    report_path = ""

    while (status != "Completed"):
        response = requests.get(url, headers=headers)
        status = response.json()[0].get("status")
        if status == "Failed":
            logging.error("Report failed")
            raise requests.HTTPError(response)
        logging.info(f" - - Report status: {status}")
        time.sleep(40)

    report_path = response.json()[0].get('storage_details').get('path')

    # --------------------------------
    #  Download Report
    # --------------------------------

    print('Downloading report')
    url = f"{cycode_api_url}/files/api/v1/file/reports/{report_path}"
    response = requests.get(url, headers=headers)
    content = response.content
    return content
 

def execute_and_download_rig_query(raw_query: str, output_format: str, cycode_api_url:str, token:str) -> str:
    execution_id = execute_rig_query(raw_query=raw_query, output_format=output_format, cycode_api_url=cycode_api_url, token=token)
    return download_rig_results(execution_id=execution_id, cycode_api_url=cycode_api_url, token=token)




