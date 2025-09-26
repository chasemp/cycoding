import requests, sys, logging, json


def get_cycode_token(client_id: str, client_secret:str, cycode_api_url:str) -> str:
    logging.info("Retrieving JWT Token...")
    token = ""

    auth_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    contents = {"clientId": client_id, "secret": client_secret}
    data = json.dumps(contents)
    r = requests.post(f"{cycode_api_url}/api/v1/auth/api-token", data=data, headers=auth_headers, timeout=3*60)
    response = r.json()
    if r.ok == True:
        token = response['token']
        logging.info("New JWT token was obtained.")
    else:
        logging.error(f"New JWT token could not be obtained, status_code={r.status_code}\nRaising Exception")
        r.raise_for_status() 
    return token


