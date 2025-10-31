
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/2cbeecb7-c2ef-4ada-afc3-f81c5bb5bcec" />


# Defense Information Systems Agency - Security Technical Implementation Guides (DISA - STIGs)

[STIG Remediation Template](https://github.com/behan101/DISA-STIGs/blob/main/stig_remediation_template.ps1)

**Windows 11 STIG Remediation Scripts:**

[WN11-AU-000050](https://github.com/behan101/DISA-STIGs/blob/main/WN11-AU-000050_Remediation_Script.ps1)

[WN11-CC-000005](https://github.com/behan101/DISA-STIGs/blob/main/WN11-CC-000005_Remediation_Script.ps1)

[WN11-CC-000090](https://github.com/behan101/DISA-STIGs/blob/main/WN11-CC-000090_Remediation_Script.ps1)

[WN11-CC-000315](https://github.com/behan101/DISA-STIGs/blob/main/WN11-CC-000315_Remediation_Script.ps1)

[WN11-EP-000310](https://github.com/behan101/DISA-STIGs/blob/main/WN11-EP-000310_Remediation_Script.ps1)

**Linux STIG Remediation Scripts:**


## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- Tenable
- Windows PowerShell

##  Scenario

An internal audit has revealed that various Windows 11 machines have numerous failures in regards to Windows Compliance Checks. I have been tasked to remediate these vulnerabilities using automation and confirm that the STIG has been sucuessfully implemented.

###  Discovery

- Scan the virtual machine associated with the Windows Compliance Check failures using tenable.
- Select Audits and discover the STIG-ID associated with the failure.
- Research remediation for the STIG-ID.

---

## Steps Taken

### 1. Perform a vulnerability scan using Tenable using the Windows Compliance Checks.
<img width="1557" height="908" alt="image" src="https://github.com/user-attachments/assets/a8dbe6c2-0469-466e-8563-65045d4a9ec7" />

---

### 2. Searched the STIG-ID using Tenable Audits.

Searched for `STIG-ID` within the Tenable Audits database (https://www.tenable.com/audits).

<img width="1475" height="895" alt="image" src="https://github.com/user-attachments/assets/2f715814-4e4e-47a7-8ac1-db56a5187176" />

---

### 3. Researched the solution.

After searching for the specified STIG-ID within the Tenable Audit database, the solution to remediate the vulnerbility was given in steps. 

**Example solution:**

<img width="1448" height="727" alt="image" src="https://github.com/user-attachments/assets/abc452f2-ecb3-45f0-991b-b5fe84d9a60e" />

---

### 4. Used the Stig Remediation Template to write a PowerShell script solution.

**Stig Remediation Template used: https://github.com/behan101/DISA-STIGs/blob/main/stig_remediation_template**

<img width="2126" height="948" alt="image" src="https://github.com/user-attachments/assets/e132d851-1b7b-4b0e-8ba8-5310417c7ace" />

---

### 5. Using PowerShell ISE, I began the process of testing and executing the script.

**Running the script:**

<img width="2549" height="1221" alt="image" src="https://github.com/user-attachments/assets/5f53b646-3c32-4d74-9095-92676c08bdeb" />

---

### 6. Remediation Validation post PowerShell Script execution.

**Remediation Validation:**

After executing the script, I validate the changes by finding the policy on the Windows machine and checking the values. I then scanned the machine using Tenable again and checked the results with the STIG-ID remediated in the script. When the scan results did not have the STIG-ID as a failure for compliance, I confirmed that the vulnerability has been remediated.

<img width="2359" height="114" alt="image" src="https://github.com/user-attachments/assets/c9e90e7d-4715-4b31-90e4-4b03b9417dd6" />

Checking the HKEY_LOCAL_MACHINE path for creation and correct value of the DWORD.

<img width="2555" height="1218" alt="image" src="https://github.com/user-attachments/assets/8173019c-2edf-4329-a1e1-3176d4ecbde3" />

After validating, I restart the machine before scanning with Tenable for another audit to ensure the changes are saved and implemented.

**Scan Results:**

<img width="1917" height="731" alt="image" src="https://github.com/user-attachments/assets/16fd9076-5634-40ec-8bbe-9be76f9f8685" />

---

## Summary

The vulnerability with the associated STIG-ID has been identified using Tenable. The scan was configured internally on the Local-Scan-Engine-01 with the target specified as the private IP address of the virtual machine. Administrative credentials were given so that the scan would be thorough. The compliance audit used in the scan was configured to the appropriate operating system and version (DISA Microsoft Windows 11 STIG v2r4). All plugins were disabled with the exception of the Windows Compliance Checks (Plugin ID: 24760) in order to expedite the scanning process and reduce resource consumption. The identified STIG-ID compliance failure was then remediated using PowerShell scripting and the `STIG Remediation Template` . After the script executed, the remediation validation process began with looking up the policy configuration in the Registry Editor of the machine. The machine was then restarted before another scan was conducted using the same parameters in Tenable. The results were confirmed to have passed the compiance check associated with the STIG-ID.

---

## Response Taken

The InfoSec / SecOps department was then notified and sent the documentation and scripts for review and deployment.

---
