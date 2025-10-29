
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/2cbeecb7-c2ef-4ada-afc3-f81c5bb5bcec" />


# Defense Information Systems Agency - Security Technical Implementation Guides (DISA - STIGs)
- [STIG Remediation Template](https://github.com/behan101/DISA-STIGs/blob/main/stig_remediation_template)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- Tenable
- EDR Platform: Microsoft Defender for Endpoint
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

**Example solution:

<img width="1448" height="727" alt="image" src="https://github.com/user-attachments/assets/abc452f2-ecb3-45f0-991b-b5fe84d9a60e" />

---

### 4. Used the Stig Remediation Template to write a PowerShell script solution.

**Stig Remdiation Template used: https://github.com/behan101/DISA-STIGs/blob/main/stig_remediation_template**

<img width="2126" height="948" alt="image" src="https://github.com/user-attachments/assets/e132d851-1b7b-4b0e-8ba8-5310417c7ace" />

---

### 5. Using PowerShell ISE, I began the process of testing and executing the script.

<img width="2549" height="1221" alt="image" src="https://github.com/user-attachments/assets/5f53b646-3c32-4d74-9095-92676c08bdeb" />


## Summary


---

## Response Taken

---
