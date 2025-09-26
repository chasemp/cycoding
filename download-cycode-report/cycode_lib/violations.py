import requests, logging

# resolve_secret_shas
# Take a solitary list of secret shas and use the api/violations/v2/secrets to close
# all of the shas in the secret_shas parameter.
# Optional parameters include the reason text
def resolve_secret_shas(cycode_app_url:str, secret_shas:list[str], token:str, reason_text="Resolved by automation"):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer " + token
    }

    body = {
        "sha512": secret_shas,
        "reason": "Revoked",
        "reasonText": reason_text,
        "value": "Revoked"
    }

    logging.info(f"Resolving secret shas{secret_shas}")

    res = requests.post(url = f"{cycode_app_url}/api/violations/v2/secrets", headers=headers, json=body)
    if res.ok != True:
        logging.error(f"http error resolving secret shas.  Error={res.status_code}")
        res.raise_for_status()

# ignore_violations
# Take a list of violation idsand use the api/alerts/status to ignore the violation IDS
# all of the shas in the secret_shas parameter.
# Optional parameters include the reason text
def ignore_violations(cycode_app_url:str, detection_ids:list[str], token:str, reason_text="Ignored by automation"):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer " + token
    }

    body = {
        "ids": detection_ids,
        "reason": "Ignored",
        "statusChangeMessage": reason_text,
        "value": "Dismissed"
    }

    res = requests.patch(url = f"{cycode_app_url}/api/alerts/status", headers=headers, json=body)
    if res.ok != True:
        logging.error(f"http error resolving secret shas.  Error={res.status_code}")
        res.raise_for_status()

def set_violations_status(cycode_app_url:str, detection_ids:list[str], status:str, token:str, reason_text="Status set by automation"):
    possible_status = ["Open", "Ignored", "FalsePositive", "Revoked"]
    if status not in possible_status:
        raise ValueError(f"Bad status value: {status}")

    body = {
        "ids": detection_ids,
    }

    value = ""
    if status == "Ignored" or status == "FalsePositive":
        body["value"] = "Dismissed"
        body["statusChangeMessage"] = reason_text
        body["reason"] = status
    elif status == "Revoked":
        body["value"] = "Resolved"
        body["statusChangeMessage"] = reason_text
        body["reason"] = status
    elif status == "Open":
        body["value"] = "Open"

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer " + token
    }

    res = requests.patch(url = f"{cycode_app_url}/api/alerts/status", headers=headers, json=body)
    if res.ok != True:
        logging.error(f"http error resolving secret shas.  Error={res.status_code}")
        res.raise_for_status()
