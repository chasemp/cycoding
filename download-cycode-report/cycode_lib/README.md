# cycode_lib

Cycode lib is group of python modules and functions that make interfacing with the Cycode platform eaier through the REST API.  It is meant to abstract several common functions and provide an easier, consistent interface to do the following tasks:
 - obtain bearer tokens
 - extract information from the Cycode platform
 - execute RIG queries and download results
 - create certain resources such as projects
 - onboard users

## Using cycode_lib
Import the module you want and call the functions you need.  All functions take a bearer token as a parameter.  You can get a bearer token through the cycode_token module.  An example of its use:
```
import cycode_lib.cycode_token as tok
id = os.environ['CYCODE_CLIENT_ID']
secret = os.environ['CYCODE_CLIENT_SECRET']
token = tok.get_cycode_token(id, secret)
# do something with your bearer token
```

## Modules

### cycode_token
Use to obtain a bearer token, passing a client id and secret.  Typically these will be passed into your program via environment variables.
Make sure your client ID and secret are for the correct tenant when you run your program.

#### ``def get_cycode_token(client_id: str, client_secret:str, cycode_api_url:str) -> str:``
**Parameters:**
    - ``client_id`` - Cycode client ID
    - ``client_secret`` - Cycode client secret
    - ``cycode_api_url`` - the Cycode API URL, for example  ``https://api.cycode.com`` or ``https:://api.eu.cycode.com`` or whatever the API URL is for an on-premesis installation of Cycode Enterprise Server.

**Returns:**
A Bearer token

**Raises:**
HTTPError if the request is bad.  

### rig_functions
Execute RIG queries, represented as JSON objects, and download reports in CSV or JSON

#### ``def execute_rig_query(raw_query: str, output_format: str, cycode_api_url:str, token:str) -> str:``
**Parameters:**
    - ``raw_query``:  JSON string representing the RIG query to be executed
    - ``output_format``:  either "CSV" or "JSON"
    - ``cycode_api_url``:  The Cycode API URL, for example  ``https://api.cycode.com`` or ``https:://api.eu.cycode.com`` or whatever the API URL is for an on-premesis installation of Cycode Enterprise Server.
    - ``token``: Bearer token
**Returns:**

    An execution ID of a query that can be used to access the resulting file to download.  
    See ``download_rig_query``

**Raises:**
InvalidArgument if output format is not "JSON" or "CSV"
HTTPError if the request returns a not OK

#### ``def download_rig_results(execution_id: str, cycode_api_url:str, token:str) -> str:``
**Parameters:**
    - ``execution_id``:  The execution_id, obtained via the execute_rig_query function or known from ahead of time.
    - ``cycode_api_url``:  The Cycode API URL, for example  ``https://api.cycode.com`` or ``https:://api.eu.cycode.com`` or whatever the API URL is for an on-premesis installation of Cycode Enterprise Server.
    - ``token``: Bearer token
**Returns:**

    The contents of the file in either JSON or CSV format

**Raises:**
HTTPError if the request returns a not OK

#### ``def execute_and_download_rig_query(raw_query: str, output_format: str, cycode_api_url:str, token:str) -> str:``
Execute the RIG query and download the results immediately.  The reason why the two are separated and publicly available for usage is that it may be desireable to make the download of the query asynchronous.  You can execute the RIG query asynchronously and then download the RIG query asynchronously as well.  This will be a synchronous execute and download.

**Parameters:**
   - ``raw_query``:  JSON string representing the RIG query to be executed
    - ``output_format``:  either "CSV" or "JSON"
    - ``cycode_api_url``:  The Cycode API URL, for example  ``https://api.cycode.com`` or ``https:://api.eu.cycode.com`` or whatever the API URL is for an on-premesis installation of Cycode Enterprise Server.
    - ``token``: Bearer token
**Returns:**

    The contents of the file in either JSON or CSV format

**Raises:**
InvalidArgument if output format is not "JSON" or "CSV"
``HTTPError`` if the request returns a not OK


### violations
#### ``def resolve_secret_shas(cycode_app_url:str, secret_shas:list[str], token:str, reason_text="Resolved by automation"):``
Marks all of the secrets in the ``secret_shas`` list as revoked
**Parameters:**
 - ``cycode_app_url``:  Cycode app URL, for example  ``https://app.cycode.com`` or ``https:://app.eu.cycode.com``
 - ``secret_shas``:  List of secret shas to mark as `revoked`.
 - ``token``:  bearer token
 - ``reason_text``: optional parameter to fill in the reasons

**Raises:**
``HTTPError`` if the request returns a not OK


#### ``def ignore_violations(cycode_app_url:str, detection_ids:list[str], token:str, reason_text="Ignored by automation"):``
Marks all of the individual violations in the ``detection_ids`` list as ignored.
This function marks all violation ids as ignored regardless of type.  It will ignore the individual violation, not mark it as ignored.

**Parameters:**
 - ``cycode_app_url``:  Cycode app URL, for example  ``https://app.cycode.com`` or ``https:://app.eu.cycode.com``
 - ``detection_ids``:  List of violation IDs to mark as `ignored`.
 - ``token``:  bearer token
 - ``reason_text``: optional parameter to fill in the reasons

**Raises:**
``HTTPError`` if the request returns a not OK

#### ``set_violations_status(cycode_app_url:str, detection_ids:list[str], status:str, token:str, reason_text="Status set by automation")``
Marks all of the individual violations in the list ``detection_ids`` list to the status provided. 

**Parameters:**
 - ``cycode_app_url``:  Cycode app URL, for example  ``https://app.cycode.com`` or ``https:://app.eu.cycode.com``
 - ``detection_ids``:  List of violation IDs to mark as `ignored`.
 - ``status``:  The updated status. Must be one of ``Opened``, ``Ignored``, ``FalsePostive``, or ``Revoked``. 
 - ``token``:  bearer token
 - ``reason_text``: optional parameter to fill in the reasons

**Raises:**
``HTTPError`` if the request returns a not OK
``ValueError`` if the status value isn't one of the correct status values

