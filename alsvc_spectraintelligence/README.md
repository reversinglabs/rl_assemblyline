# ReversingLabs Spectra Intelligence service for AssemblyLine


## Introduction
ReversingLabs Spectra Intelligence service for AssemblyLine is a solution for obtaining detailed and high precision file reputation and analysis information on submitted files. The results are returned in the form of JSON file reputation, JSON File analysis, anti-virus scanner cross-reference reports and can be used in detailed threat investigation in your workflows.
 
## Requirements
- AssemblyLine
- ReversingLabs Spectra Intelligence service package
- ReversingLabs Spectra Intelligence account

## Add the service to your deployment
To install the ReversingLabs Spectra Intelligence service on your AssemblyLine do the following steps while on the AssemblyLine server:

1. Follow this [Guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment) to add container to your deployment

2. Using your web browser, go to the service management page: https://localhost/admin/services

3. Click the **Add service** button

4. Paste the entire content of the service_manifest.yaml file in the text box.

5. Click the **Add** button

Your service information has been added to the system. The scaler component should automatically start a container of your newly created service.

## Configuring the service
After the service is installed and registered, proceed to configuring it. 


Enable the service in the Settings menu or at  
`https://<assemblyline_host>/settings`   
Make sure that the service is selected in the Services Selection section.


Check the service configuration and update the configuration parameters in the Services menu or at  
`https://<assemblyline_host>/admin/services`  
Fill out the service configuration under the Service Parameters section:
- **Spectra Intelligence address** (string) - the address of Spectra Intelligence services
- **Spectra Intelligence password** (string) - the password of your Spectra Intelligence account
- **Spectra Intelligence username** (string) - the username of your Spectra Intelligence account

## Using the service
Upload a file or select URL using Submit menu.

Under Submission Report you can find summed up various information about the current submission alongside with the summed score (Max Score) of all active services returning malware score.

By clicking on the desired file under Files you can enter the detailed result page for the selected file.
Under Service Results you can expand results of each enabled and configured service.

### Service results
The Spectra Intelligence service for AssemblyLine features three separate cloud service calls and their result sections:
- **ReversingLabs File Reputation**
- **ReversingLabs AV Scanners**
- **ReversingLabs File Analysis**

Each cloud service returns its own variation of results depending on the outcome of its query.

The following represents the possible input and output options separated by cloud service.  

**INPUT**:
- file

#### File Reputation
**OUTPUT**: 
- **if the file was found on File Reputation and its result returned:**
    - File Reputation JSON and its malware score

- **if the file was not found on File Reputation**
    - File Reputation
        - In case there is no reference for the file on File Reputation, no results will be returned

#### AV Scanners
**OUTPUT**: 
- **if the file was found on AV Scanners and its result returned:**
    - AV Scanners JSON and its cross reference results

#### File Analysis
**OUTPUT**: 
- **if the file was found on File Reputation and its result returned:**
    - File Analysis JSON

- **if the file was not found on File analysis**
    - File analysis message
        - In case there is no reference for the file on File analysis no results will be returned.

JSON output in each result section can be expanded and collapsed per need.

### File analysis score
ReversingLabs Spectra Intelligence service for AssemblyLine contains a malware score calculation functionality.
Each analyzed file will receive a ReversingLabs malware score mapped to the AssemblyLine score table. The higher the score the higher the maliciousness of the file and the risk of having it in your system.

The following is the score enumeration and interpretation for one single file.


|   |   |
|---|---|
| Malicious | > 2000 | 
| Likely malicious | < 2000 |
| Highly suspicious | < 1000 |
| Suspicious | < 500 |
| Nothing found | 0 | 
| Whitelisted | <= -1000 | 



## Troubleshooting
Check the following section for information about errors and debugging:
`https://<assemblyline_host>/admin/errors`


## Additional information
All additional information on Spectra Intelligence services usage and report JSON interpretation can be found in the Spectra Intelligence service’s respective user documentation.

## Useful links
**ReversingLabs home page:**
https://www.reversinglabs.com/

**ReversingLabs Spectra Intelligence:**
https://www.reversinglabs.com/products/spectra-intelligence

**AssemblyLine:**
https://www.cyber.gc.ca/en/assemblyline


