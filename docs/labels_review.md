# Proposed labels for review

Accept or change each row. Order matches data/sample_for_review.txt.

| # | alert_id | Rule | Proposed | Reason | Your call |
|---|---|---|---|---|---|
| 1 | 291acda8306c7889 | Potentially Suspicious AccessMask Requested From LSASS | malicious | step 1: ProcessId 1648 (0x670) = attacker PowerShell; reads lsass memory (mask 0x10) | |
| 2 | 32a60c4fa80ff99c | Potential Credential Dumping Attempt Via PowerShell | malicious | step 1: SourceProcessGUID = attacker GUID; PID 1648 opens lsass with 0x1010 (the credential dump) | |
| 3 | 3a4887cac00a4869 | Potentially Suspicious AccessMask Requested From LSASS | malicious | step 1: ProcessId 1648 (0x670) requests lsass handle with 0x1010 | |
| 4 | 41f1e61b69cd3d00 | LSASS Access From Non System Account | malicious | step 1: ProcessId 1648 (0x670); same event as alert 3a4887cac00a4869 (Security:202269) | |
| 5 | 7af8fafa0f3b02f5 | Process Ran With High Privilege | malicious | step 1: ProcessId 1648 (0x670) calls a privileged service during the lsass access | |
| 6 | 8a8dfebceff68756 | Raw Access Read | benign | step 5: lsass.exe (704) on MORDORDC, no attacker PID, GUID or 10.10.10.5 in surrounding events | |
| 7 | ab27deec42fac6af | Process Ran With High Privilege | malicious | step 1: ProcessId 1648 (0x670) calls a privileged service during the lsass access | |
| 8 | aeeb5148df3ed07b | Raw Access Read | benign | step 4: svchost.exe (1784, SysMain per call traces) raw disk read; no attacker link in surrounding events | |
| 9 | ed0ca583106c12d0 | Raw Access Read | benign | step 5: lsass.exe (704) on MORDORDC, adjacent to 8a8dfebceff68756; no attacker link | |
| 10 | 44f255f374992221 | Local Accounts Discovery | malicious | step 1: whoami.exe /user, ParentProcessId 1648 / parent GUID = attacker | |
| 11 | 596bfcb2255d5785 | Local Accounts Discovery | malicious | step 1: 4688 creator ProcessId 0x670 = attacker starts whoami.exe /user | |
| 12 | 3272105ca1ce8305 | Network Connection Initiated By PowerShell Process | malicious | step 1/2: ProcessId 1648 (0x670), DestAddress 10.10.10.5:80 | |
| 13 | 07026301434ec360 | Network Connection Initiated By PowerShell Process | malicious | step 1/2: attacker GUID, DestinationIp 10.10.10.5:80 | |
| 14 | 6c71ca4b71c80672 | Network Connection Initiated By PowerShell Process | malicious | step 1/2: attacker GUID, DestinationIp 10.10.10.5:80 | |
| 15 | 5e5e7b31791c4752 | Network Connection Initiated By PowerShell Process | malicious | step 1/2: attacker GUID, DestinationIp 10.10.10.5:80 | |
| 16 | 54881d84f2c83f45 | Network Connection Initiated By PowerShell Process | malicious | step 1/2: attacker GUID, DestinationIp 10.10.10.5:80 | |
| 17 | 3846ccc12ddc25f4 | Proc Access | benign | step 4: lsass (768) opens svchost (2440) with 0x1000 via lsasrv/SspiSrv, routine authentication | |
| 18 | 2db5a6f88af687da | Proc Access | malicious | UNSURE: lsass (768) opens the ATTACKER process (TargetProcessId 1648) with 0x1000 via SspiSrv; a side effect of the attacker's calls, but rubric step 1 does not name target processes | |
| 19 | f975e831ffb50404 | Proc Access | benign | step 4: svchost (1784, SysMain) opens vssvc with 0x2000, routine | |
| 20 | c69c93079157d036 | Proc Access | benign | step 4: svchost (452, lsm.dll) opens svchost (3140) with 0x1000, routine session management | |
| 21 | 27881e43475ab248 | Proc Access | benign | step 4: svchost (452, lsm.dll) opens svchost (3140) with 0x1000, routine | |
| 22 | d5f41fc3bb2180d6 | Proc Access | benign | step 4: svchost (908) opens backgroundTaskHost with 0x1000, routine | |
| 23 | 9e3de478c757bbfc | Proc Access | benign | step 4: svchost (1784, SysMain) opens svchost (2600) with 0x2000, routine | |
| 24 | 0e6c6f655ddb3b77 | Proc Access | benign | step 4: svchost (1784, SysMain) opens svchost (3124) with 0x2000, routine | |
| 25 | 04a6be0a2d4206b5 | Proc Access | benign | step 4: MORDORDC svchost (340, lsm.dll) opens svchost (3052) with 0x1000, routine | |
| 26 | 0ea0538ca5d32b15 | Proc Access | benign | step 4: MORDORDC svchost (340, lsm.dll) opens svchost (1824) with 0x1000, routine | |
| 27 | 2aaa7ecdfd1e90cd | Proc Access | benign | step 4: MORDORDC svchost (340, lsm.dll) opens svchost (1824) with 0x1000, routine | |
| 28 | 760bf9479ecb02ec | Proc Access | benign | step 4: WORKSTATION6 svchost (380, lsm.dll) opens svchost (1048) with 0x40, routine | |
| 29 | e24ba5969287ab48 | Proc Access | benign | step 4: WORKSTATION6 svchost (380, lsm.dll) opens svchost (3268) with 0x1000, routine | |
| 30 | 13a434e809806a27 | Proc Access | benign | step 4: WORKSTATION6 svchost (380, lsm.dll) opens svchost (1048) with 0x40, routine | |
