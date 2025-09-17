# HP-Driver-Firmware-Bios-Updates
Updates all drivers on HP devices using PSADT 4.1.5

Requires the workstation to have HPCMSL installed. (HP Client Management Script Library 1.8.2 or later)
https://www.hp.com/us-en/solutions/client-management-solutions/download.html

Important : You need to drop your password bin file in the files directory with the name Pass.Bin.
If you are using HP Sure admin you can comment out the If statement on line 170.
This example adds a scheduled task called 'HP Driver Firmware Bios Updates' that removes the registry key detection rule after 1 hour so the app shows as avaliable again later via company portal.

This is using PSADT 4.1.5 which no longer requires serviceui.exe to be interactive.
Commandline for install is : Invoke-AppDeployToolkit.exe Install Interactive


<img width="725" height="417" alt="image" src="https://github.com/user-attachments/assets/b891497c-6a94-43c2-85da-1d38c6629440" />

<img width="725" height="350" alt="image" src="https://github.com/user-attachments/assets/c1252673-7e63-46b0-a415-7ff896827561" />

<img width="725" height="285" alt="image" src="https://github.com/user-attachments/assets/df073765-1b29-4d52-a037-3af688f20aa3" />

<img width="725" height="285" alt="image" src="https://github.com/user-attachments/assets/77d19531-8b73-4f25-888b-bc842602d18b" />

softpaqs download to C:\Windows\Temp\HPDrivers

<img width="982" height="1202" alt="image" src="https://github.com/user-attachments/assets/5ea1ee60-3131-4884-81a7-3a32064bd588" />

Additional registry keys get written to HKLM:\Software\HP\ImageAssistant and can be used with Configuration Manager custom Inventory.

<img width="1445" height="592" alt="image" src="https://github.com/user-attachments/assets/71753c65-c56e-4104-9f52-a9c960e68676" />

HPIA logs created in C:\Windows\Logs\Software\HP\HPIALogs

<img width="1109" height="366" alt="image" src="https://github.com/user-attachments/assets/85aa450c-80b6-48b6-9ab8-0479a2ab612d" />






