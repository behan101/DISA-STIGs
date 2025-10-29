
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
- Research remdiation for the STIG-ID.

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

After searching for the specified STIG-ID within the Tenable Audit database, the solution to remdiate the vulnerbility was given in steps. 

**Example solution:

<img width="1448" height="727" alt="image" src="https://github.com/user-attachments/assets/abc452f2-ecb3-45f0-991b-b5fe84d9a60e" />

---

### 4. Used the Stig Remediation Template to write a PowerShell script solution.



**Stig Remdiation Template used: https://github.com/behan101/DISA-STIGs/blob/main/stig_remediation_template**

<img width="2126" height="948" alt="image" src="https://github.com/user-attachments/assets/e132d851-1b7b-4b0e-8ba8-5310417c7ace" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-10-23T08:22:56.493006Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.8.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.8.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-10-23T08:24:26.7848041Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.8.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.8.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.8.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-10-23T08:24:53.7808645Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-10-23T08:26:31.7541945Z`
- **Event:** A network connection to IP `66.222.102.232` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-10-23T08:27:28.5356418Z` - Connected to `91.143.88.62` on port `443`.
  - `2025-10-23T08:26:28.1769754Z` - Connected to `54.37.255.75` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-10-23T08:45:50.2680247Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-bra" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-bra` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
