-- create scan table --
CREATE TABLE scan (
    scan_id     CHAR(4)    PRIMARY KEY,
    started_at  TIMESTAMP,
    ended_at    TIMESTAMP,
    status      CHAR(10)   CHECK (status IN ('Scheduled', 'Running', 'Completed', 'Failed'))
);


-- create file table --
CREATE TABLE file (
    file_id     CHAR(4)    PRIMARY KEY,
    file_path   VARCHAR(255)
);


-- create malware table --
CREATE TABLE malware (
    malware_id  CHAR(4)    PRIMARY KEY,
    name        VARCHAR(255),
    description TEXT
);


-- create YARA rule table --
CREATE TABLE yara_rule (
    rule_id          CHAR(4)    PRIMARY KEY,
    malware_id       CHAR(4)    NOT NULL,
    rule_name        VARCHAR(255),
    rule_strings TEXT,
    FOREIGN KEY (malware_id) REFERENCES malware (malware_id)
);


-- create detection table --
CREATE TABLE detection (
    detection_id    CHAR(4)    PRIMARY KEY,
    scan_id         CHAR(4)    NOT NULL,
    file_id         CHAR(4)    NOT NULL,
    malware_id      CHAR(4),
    rule_id         CHAR(4),
    time_detected   TIMESTAMP,
    status          CHAR(20)   CHECK (status IN ('Quarantined', 'Deleted', 'Ignored')),
    FOREIGN KEY (scan_id) REFERENCES scan (scan_id),
    FOREIGN KEY (file_id) REFERENCES file (file_id),
    FOREIGN KEY (malware_id) REFERENCES malware (malware_id),
    FOREIGN KEY (rule_id) REFERENCES yara_rule (rule_id)
);


-- create remediation table --
CREATE TABLE remediation (
    remediation_id   CHAR(6)   PRIMARY KEY,
    malware_id       CHAR(4)   NOT NULL,
    remediation_name           VARCHAR(255),
    remediation_steps          TEXT,
    resource_link              VARCHAR(255),
    FOREIGN KEY (malware_id) REFERENCES malware (malware_id)
);


-- insert data into the file table --
INSERT INTO file (file_id, file_path) VALUES 
    ('f001', 'C:\Users\aster\Documents\remediation-project\samples\cobaltStrike');

INSERT INTO file (file_id, file_path) VALUES 
    ('f002', 'C:\Users\aster\Documents\remediation-project\samples\coinMiner');

INSERT INTO file (file_id, file_path) VALUES 
    ('f003', 'C:\Users\aster\Documents\remediation-project\samples\massLogger');

INSERT INTO file (file_id, file_path) VALUES 
    ('f004', 'C:\Users\aster\Documents\remediation-project\samples\mirai');

INSERT INTO file (file_id, file_path) VALUES 
    ('f005', 'C:\Users\aster\Documents\remediation-project\samples\netWire');

INSERT INTO file (file_id, file_path) VALUES 
    ('f006', 'C:\Users\aster\Documents\remediation-project\samples\redLineStealer');

INSERT INTO file (file_id, file_path) VALUES 
    ('f007', 'C:\Users\aster\Documents\remediation-project\samples\snakeKeyLogger');

INSERT INTO file (file_id, file_path) VALUES 
    ('f008', 'C:\Users\aster\Documents\remediation-project\samples\sock5Systemz');

INSERT INTO file (file_id, file_path) VALUES 
    ('f009', 'C:\Users\aster\Documents\remediation-project\samples\valleyRAT');

INSERT INTO file (file_id, file_path) VALUES 
    ('f010', 'C:\Users\aster\Documents\remediation-project\samples\vidar');


-- insert data into the malware table --
INSERT INTO malware (malware_id, name, description) VALUES
    ('m001', 'Cobalt Strike', 'Cobalt Strike is a licensed penetration software package developed by Forta 
                               that helps red teams simulate an adversary attack in red-vs-blue games.
                               While the software itself is completely legal and designed for cybersecurity 
                               testing, over the years, many versions of it have been cracked and leaked 
                               into the wild and have been adopted by malicious actors.');

INSERT INTO malware (malware_id, name, description) VALUES
    ('m002', 'CoinMiner', 'Coinminer malware is malicious software that infiltrates the system of a
                           victim and uses its hardware, such as the CPU, GPU, and RAM, to mine cryptocurrency. 
                           Coinminers often use stealth techniques, such as being designed to mine only during 
                           certain hours, to ensure they remain undetected.');

INSERT INTO malware (malware_id, name, description) VALUES 
    ('m003', 'MassLogger', 'MassLogger is a sophisticated malware classified as a credential stealer 
                            and keylogger. It was first observed in April 2020 and is used by malicious 
                            actors to steal sensitive information from infected systems, including login 
                            credentials, browser data, and system information. MassLogger is typically 
                            distributed through phishing campaigns and malicious email attachments, making 
                            it a significant threat to individuals and organizations alike.');

INSERT INTO malware (malware_id, name, description) VALUES 
    ('m004', 'Mirai', 'Mirai is a self-propagating malware that scans the internet for 
                       vulnerable IoT devices and infects them to create a botnet.
                       It targets Internet of Things (IoT) devices and was first 
                       discovered in September 2016 and is used for launching 
                       distributed denial-of-service (DDoS) attacks, but it has 
                       also been used for cryptocurrency mining.'); 

INSERT INTO malware (malware_id, name, description) VALUES 
    ('m005', 'NetWire', 'Netwire is a remote access trojan-type malware. 
                         A RAT is malware used to control an infected machine remotely. 
                         This particular RAT can perform over 100 malicious actions on 
                         infected machines and can attack multiple Operating Systems, 
                         including Windows, MacOS, and Linux.');

INSERT INTO malware (malware_id, name, description) VALUES 
    ('m006', 'RedLine Stealer', 'RedLine Stealer is a malicious information-stealing software 
                                 that uses a customizable file-grabber to collects victims 
                                 sensitive data from web browsers, applications, emailing 
                                 and messaging apps, and cryptocurrency wallets. This malware 
                                 can gather detailed information about the infected device, such as: 
                                 its programs, antivirus products, and running processes, and 
                                 then proceed to carry out ransomware attacks on an infected system.');

INSERT INTO malware (malware_id, name, description) VALUES 
    ('m007', 'Snake KeyLogger', 'Snake KeyLogger malware is a infostealer and keylogger that 
                                 was initially discovered in November 2020. Malicious actors use 
                                 this malware to exfiltrate confidential data, such as keystrokes, 
                                 screen captures, and login credentials.');

INSERT INTO malware (malware_id, name, description) VALUES 
    ('m008', 'Sock5 Systemz', 'Socks5systemz malware is a botnet that utilizes its infection 
                               capabilities to establish a network of compromised devices. 
                               These devices are then used to forward malicious traffic. 
                               The criminal actors behind this malware then sell access to 
                               the infected endpoints to other threat actors. The malware 
                               maintains control over thousands of devices and 
                               communicates with them using specific commands.');

INSERT INTO malware (malware_id, name, description) VALUES 
    ('m009', 'ValleyRAT', 'ValleyRAT is a remote access trojan that was first documented 
                           in 2023, and mainly targets Windows systems. 
                           It is used by threat actors to gain persistent access to 
                           infected devices. Afterwards they steal data, and control compromised machines.');

INSERT INTO malware (malware_id, name, description) VALUES 
    ('m010', 'Vidar', 'Vidar is a dangerous malware that steals information and 
                       cryptocurrency from infected users and was first observed in 2018.
                       Vidar is used to steal information from infected systems, 
                       take screenshots, steal cryptocurrency, and more.');


-- insert data into the YARA rule table --
INSERT INTO yara_rule (rule_id, malware_id, rule_name, rule_strings) VALUES 
                      ('r001', 'm001', 'cobaltStrike_rule', '{ strings: 
                                                                        $string1 = "f:\\dd\\vctools\\vc7libs\\ship\\atlmfc\\src\\mfc\\auxdata.cpp"
                                                                        $string2 = "f:\\dd\\vctools\\vc7libs\\ship\\atlmfc\\include\\afxwin2.inl"
                                                                        $string3 = "f:\\dd\\vctools\\vc7libs\\ship\\atlmfc\\src\\mfc\\appcore.cpp"
                                                                        $string4 = "GetSystemTimeAsFileTime"}');

INSERT INTO yara_rule (rule_id, malware_id, rule_name, rule_strings) VALUES 
                      ('r002', 'm002', 'coinMiner_rule', '{ strings: 
                                                                    $hex_string = {4D 5A 78}
                                                                    $string1 = "Panicked during a panic. Aborting."
                                                                    $string2 = "Unable to dump stack trace: debug info stripped"}');

INSERT INTO yara_rule (rule_id, malware_id, rule_name, rule_strings) VALUES 
                      ('r003', 'm003', 'massLogger_rule', '{ strings: 
                                                                    $hex_string1 = {4D 5A}
                                                                    $hex_string2 = {40 2E 72 65 6C 6F 63}
                                                                    $string1 = "This program cannot be run in DOS mode." 
                                                                    $string3 = "<AnalyzeNetworkSecurityLogs>b__0"}');

INSERT INTO yara_rule (rule_id, malware_id, rule_name, rule_strings) VALUES 
                      ('r004', 'm004', 'mirai_rule', '{ strings: 
                                                                $hex_string = {7F 45 4C 46}
                                                                $string1 = "Chrome/100.0.4896.127"
                                                                $string2 = "Firefox/99.0"
                                                                $string3 = "Safari/605.1.15"
                                                                $string4 = "Edg/100.0.1185.39"
                                                                $string5 = "/bin/busybox wget http://"
                                                                $string6 = "/bin/busybox curl http://"}');
                                                        
INSERT INTO yara_rule (rule_id, malware_id, rule_name, rule_strings) VALUES 
                      ('r005', 'm005', 'netWire_rule', '{ strings: 
                                                                $hex_string = {4D 5A}
                                                                $string1 = "!This program cannot be run in DOS mode."
                                                                $string2 = "winhttp.dll"
                                                                $string3 = "MT_qUDrj\\F4Y0W6W85\\U4RSWg6\\PQ00dR5zd064WR\\rQR\\"
                                                                $string4 = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"}');

INSERT INTO yara_rule (rule_id, malware_id, rule_name, rule_strings) VALUES 
                      ('r006', 'm006', 'redLineStealer_rule', '{ strings: 
                                                                        $hex_string = {4D 5A}
                                                                        $string1 = "baiohttp\\_http_parser.cp314-win_amd64.pyd"
                                                                        $string2 = "baiohttp\\_websocket\\reader_c.cp314-win_amd64.pyd"
                                                                        $string3 = "HttpSendRequestW"
                                                                        $string4 = "HttpOpenRequestW"}');

INSERT INTO yara_rule (rule_id, malware_id, rule_name, rule_strings) VALUES 
                      ('r007', 'm007', 'snakeKeyLogger_rule', '{ strings: 
                                                                        $string1 = "http://varders.kozow.com:8081,http://aborters.duckdns.org:8081,http://anotherarmy.dns.army:8081" ascii wide
                                                                        $string2 = "https://reallyfreegeoip.org/xml/" ascii wide
                                                                        $string3 = "http://checkip.dyndns.org/" ascii wide
                                                                        $string4 = "https://api.telegram.org/bot" ascii wide
                                                                        $string5 = "http://51.38.247.67:8081/_send_.php?L" ascii wide
                                                                        $string6 = "/sendDocument?chat_id=" ascii wide
                                                                        $string7 = "/sendMessage?chat_id=" ascii wide}');

INSERT INTO yara_rule (rule_id, malware_id, rule_name, rule_strings) VALUES 
                      ('r008', 'm008', 'sock5Systemz_rule', '{ strings: 
                                                                    $hex_string = {4D 5A 50}
                                                                    $string1 = "This program must be run under Win32."
                                                                    $string2 = "Specifies the password to use"
                                                                    $string3 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline"}');

INSERT INTO yara_rule (rule_id, malware_id, rule_name, rule_strings) VALUES 
                      ('r009', 'm009', 'valleyRAT_rule', '{ strings: 
                                                                    $hex_string = {4D 5A}
                                                                    $hex_string2 = {40 2E 78 64 61 74 61}
                                                                    $string1 = "!This program cannot be run in DOS mode."}');

INSERT INTO yara_rule (rule_id, malware_id, rule_name, rule_strings) VALUES 
                      ('r010', 'm010', 'vidar_rule', '{ strings: 
                                                                $hex_string = {4D 5A}
                                                                $string1 = "Stop reversing the binary"
                                                                $string2 = "Reconsider your life choices"
                                                                $string3 = "And go touch some grass"
                                                                $string4 = "C:\\tgbotsideloading\\sideload\\x64\\AdvancedPolymorph.h"}');


-- insert data into the remediation table --
INSERT INTO remediation (remediation_id, malware_id, remediation_name, remediation_steps, resource_link) VALUES 
    ('rem001', 'm001', 'Cobalt Strike Remediation', 
     'For an easy and automatic removal process, the Malwarebytes software can detect and remove Trojan.CobaltStrike without requiring further user interaction. 
        Step 1: Please download Malwarebytes to your desktop. 
        Step 2: Double-click MBSetup.exe and follow the prompts to install the program. 
        Step 3: When your Malwarebytes for Windows installation completes, the program opens to the Welcome to Malwarebytes screen. 
        Step 4: Click on the Get started button. 
        Step 5: Click Scan to start a Threat Scan. 
        Step 6: Click Quarantine to remove the found threats. 
        Step 7: Reboot the system if prompted to complete the removal process.', 
     'This link provides the resource article(s) used: https://www.malwarebytes.com/blog/detections/trojan-cobaltstrike'); 

INSERT INTO remediation (remediation_id, malware_id, remediation_name, remediation_steps, resource_link) VALUES 
    ('rem002', 'm002', 'CoinMiner Remediation', 
     'When a system has been affected, it is best to first isolate it from the internet to prevent it spreading to other devices on the network and then run a virus check.
        Manual removal is lengthy and complicated process that requires the user to possess a good level of technical skills. The steps involved are: 
        Step 1: Identify the name of the malware you are trying to remove 
        Step 2: Download a program called Autoruns. This is a program that automatically starts applications 
        Step 3: Restart your computer into Safe Mode 
        Step 4: Extract the downloaded archive and run the Autoruns.exe file 
        Step 5: Open the Autoruns application and inside click "Options" at the top and uncheck "Hide Empty Locations" and "Hide Windows Entries". After unchecking those options click the "Refresh" icon. 
        Step 6: Check the list provided by the Autoruns application and locate the malware file that you want to eliminate. 
        Step 7: Note down the file path to the file wish to delete and be careful not to delete legitimate system processes. 
        Step 8: Then right click on the file and select "Delete". This ensure that malware will not run automatically on the next system startup. 
        Step 9: Search your system on "File Explorer" for the malware name and if found delete it. 
        Step 10: Finally, reboot your computer in normal mode. ', 
     'This link provides the resource article(s) used: https://www.pcrisk.com/removal-guides/12088-coinminer-malware#a1');

INSERT INTO remediation (remediation_id, malware_id, remediation_name, remediation_steps, resource_link) VALUES 
    ('rem003', 'm003', 'MassLogger Remediation', 
     'Note that the manual approach is a lengthy and complicated process and would require the advanced IT skills. The steps below are an easy guide to follow.
        Step 1: Reboot the system in safe mode.
        Step 2: Press CTRL + SHIFT + ESC to load the “processes Tab”, then try to determine which processes are dangerous. 
        Step 3: Right-click on each of the processes and select “Open Fie Location”.
        Step 4: Scan each file using a virus scanner online. 
        Step 5: Hold the “Start key” and “R” then type in “appwiz.cpi” then select “OK”. This loads up the control panel. 
        Step 6: Look for suspicious entries, and when identified, uninstall them. 
        Step 7: Type “msconfig” in the windows search bar. 
        Step 8: Open the “Startup” tab and uncheck entries that have “Unknown” as the manufacturer.
        Step 9: Hold the “Start key” and “R” then paste in the following “notepad %windir%/system32/Drivers/etc/hosts” and click “OK” 
        Step 10: A new file will open. If you are hacked, there will be a bunch of other IPs connected to your device at the bottom instead of just the local host IP address 
        Step 11: Type “Regedit” in the windows search 
        Step 12: Once inside, press “CTRL” and “F” together and type the name of the virus. Right click and “delete” any entries you find with a similar name 
        Step 13: Finally, reboot your computer in normal mode.
                                                                    
                                                                    
     Another method that can be taken involves:
        Step 1: Identify the name of the malware you are trying to remove.
        Step 2: Download a program called Autoruns. This is a program that automatically starts applications.
        Step 3: Restart your computer into Safe Mode. 
        Step 4: Extract the downloaded archive and run the Autoruns.exe file.
        Step 5: Open the Autoruns application and inside click "Options" at the top and uncheck "Hide Empty Locations" and "Hide Windows Entries". After unchecking those options click the "Refresh" icon. 
        Step 6: Check the list provided by the Autoruns application and locate the malware file that you want to eliminate. 
        Step 7: Note down the file path to the file wish to delete and be careful not to delete legitimate system processes. 
        Step 8: Then right click on the file and select "Delete". This ensure that malware will not run automatically on the next system startup. 
        Step 9: Search your system on "File Explorer" for the malware name and if found delete it. 
        Step 10: Finally, reboot your computer in normal mode.', 
     'This link provides the resource article(s) used: https://howtoremove.guide/how-to-remove-malware/ and https://www.pcrisk.com/removal-guides/17861-masslogger-virus');        

INSERT INTO remediation (remediation_id, malware_id, remediation_name, remediation_steps, resource_link) VALUES 
    ('rem004', 'm004', 'Mirai Remediation', 
     'A manual fix in the event an IoT device is infected would involve:
        Performing a factory reset on the infected system and then afterwards address the root vulnerability that was exploited (e.g. using a weak or default password). 


     Precautionary steps that can be taken to prevent a system being infected include: 
        Step 1: Ensuring the IoT devices are updated to the latest products available.
        Step 2: Reconfiguring the default factory settings and logins of IoT devices.
        Step 3: Implementing network segmentation to ensure the IoT devices are on a separate network from critical daily operation and to limit the effects in the event one segment gets infected. 
        Step 4: Implement a safe password policy.
        Step 5: Use and maintain suitable anti-virus software.', 
        'This link provides the resource article(s) used: https://www.aeanet.org/how-to-migrate-itunes-library-to-new-computer/');

INSERT INTO remediation (remediation_id, malware_id, remediation_name, remediation_steps, resource_link) VALUES 
    ('rem005', 'm005', 'NetWire Remediation', 
     'Manual removal is lengthy and complicated process that requires the user to possess a good level of technical skills. The steps involved are: 
        Step 1: Identify the name of the malware you are trying to remove.
        Step 2: Download a program called Autoruns. This is a program that automatically starts applications. 
        Step 3: Restart your computer into Safe Mode.
        Step 4: Extract the downloaded archive and run the Autoruns.exe file. 
        Step 5: Open the Autoruns application and inside click "Options" at the top and uncheck "Hide Empty Locations" and "Hide Windows Entries". After unchecking those options click the "Refresh" icon. 
        Step 6: Check the list provided by the Autoruns application and locate the malware file that you want to eliminate. 
        Step 7: Note down the file path to the file wish to delete and be careful not to delete legitimate system processes. 
        Step 8: Then right click on the file and select "Delete". This ensure that malware will not run automatically on the next system startup. 
        Step 9: Search your system on "File Explorer" for the malware name and if found delete it. 
        Step 10: Finally, reboot your computer in normal mode.', 
     'This link provides the resource article(s) used: https://www.pcrisk.com/removal-guides/15614-netwire-rat#a2');

INSERT INTO remediation (remediation_id, malware_id, remediation_name, remediation_steps, resource_link) VALUES 
    ('rem006', 'm006', 'RedLine Stealer Remediation', 
     'To manually remove the malware from a Windows system the Windows operating system offers a pre-installed feature called Windows Malicious Software Removal Tool, allowing users to detect and remove malware themselves. 
        The steps involved are: 
            Step 1: Write “mrt” in the search box in the Menu and click to run it. 
            Step 2: Click the “Next” button. 
            Step 3: You can choose from three scan modes: “Quick scan,” “Customize scan,” and “Full scan.” We recommend choosing a full scan of your system. 
            Step 4: Click the “Next” button. 
            Step 5: Click on “View detailed results of the scan link,” examine the scan results, and remove malicious programs if they are found. 
            Step 6: Click the “Finish” button. 


        Another method that can be taken involves the use of multiple antivirus tools and some technical skills from the user. The steps involved are: 
            Step 1: Uninstall the malicious program from your system. Steps to take: 
                + Press the “Windows Key” and “I” to open the “Settings” app. 
                + In the Settings app, click on “Apps” then click on “Apps & features”. 
                + Identify the malicious program in the list of installed apps and uninstall it. 
                + Follow the prompts provided to uninstall the program. 
                + If you have trouble while attempting to uninstall a program, use “Revo Uninstaller” to completely remove the unwanted program from your computer. 
            Step 2: Reset the browser back to default settings. Steps to take: 
                + Open your browser menu. 
                + Go to settings 
                + Select “Reset settings” 
                + Click on “Restore settings to their original defaults” 
                + Confirm the reset by clicking “Reset settings” 
            Step 3: Use Rkill to terminate suspicious programs. Steps to take: 
                + Download Rkill. 
                + Run Rkill. 
            Step 4: Use Malwarebytes to remove the Trojans and unwanted programs. Steps to takes: 
                + Download Malwarebytes. 
                + Install Malwarebytes. 
                + Follow the on-screen prompts to install Malwarebytes. 
                + On the final screen, click “Open Malwarebytes” to start the program. 
                + In the Malwarebytes program open settings and enable the “Scan for rootkits” option 
                + Return to the main screen of the program by clicking on “Dashboard” on the left pane and then click the “Scan” button. 
                + Wait for Malware bytes to complete the scan. 
                + Quarantine the detected malware by clicking the “Quarantine” button. 
                + After Malwarebytes has quarantined and deleted the malwares found, restart your computer. 
            Step 5: Use HitmanPro to remove Rootkits and other malware persisting on the system. Steps to take: 
                + Download HitmanPro 
                + Install HitmanPro 
                + Follow the on-screen prompts. 
                + After the installation completes, wait for HitmanPro to complete scanning your computer. 
                + After the scan completes click on “Next” and then click on “Activate free license”. 
                + After the removal process is complete, reboot your computer if prompted by HitmanPro. 
            Step 6: Use AdwCleaner to remove malicious browser policies and Adware.  Steps to take: 
                + Download AdwCleaner 
                + Double click on the setup file to run the installer. 
                + After installing AdwCleaner, click on “Settings” and enable “Reset Chrome policies” 
                + Return to the Dashboard and then click “Scan” to perform a scan on your device. 
                + Wait for scan to complete and then click on “Quarantine” to remove any malicious programs found on your computer. 
                + Click on “Continue” to finish the removal process. 
            Step 7: Perform a final check with ESET Online scanner. Steps to take: 
                + Download ESET Online scanner. 
                + Double click on the setup file to run the installer.  
                + Follow the on-screen prompts to install the program. 
                + Start a full scan with ESET Online scanner and enable the program to detect and quarantine malicious file before starting the scan. 
                + Wait for the scan to finish. 
                + Once the scan is completed, ESET Online scanner automatically removes any malicious files found.', 
     'This link provides the resource article(s) used: https://nordvpn.com/blog/redline-stealer-malware/?msockid=0d132eb6dd8c6bff0c0f3cc3dc996a6d and https://malwaretips.com/blogs/remove-spyware-redlinestealer-trojan/');

INSERT INTO remediation (remediation_id, malware_id, remediation_name, remediation_steps, resource_link) VALUES 
    ('rem007', 'm007', 'Snake KeyLogger Remediation', 
     'Manual removal is lengthy and complicated process that requires the user to possess a good level of technical skills. The steps involved are: 
        Step 1: Identify the name of the malware you are trying to remove. 
        Step 2: Download a program called Autoruns. This is a program that automatically starts applications. 
        Step 3: Restart your computer into Safe Mode.
        Step 4: Extract the downloaded archive and run the Autoruns.exe file. 
        Step 5: Open the Autoruns application and inside click "Options" at the top and uncheck "Hide Empty Locations" and "Hide Windows Entries". After unchecking those options click the "Refresh" icon. 
        Step 6: Check the list provided by the Autoruns application and locate the malware file that you want to eliminate. 
        Step 7: Note down the file path to the file wish to delete and be careful not to delete legitimate system processes. 
        Step 8: Then right click on the file and select "Delete". This ensure that malware will not run automatically on the next system startup. 
        Step 9: Search your system on "File Explorer" for the malware name and if found delete it. 
        Step 10: Finally, reboot your computer in normal mode.', 
     'This link provides the resource article(s) used: https://www.pcrisk.com/removal-guides/19570-snake-keylogger');

INSERT INTO remediation (remediation_id, malware_id, remediation_name, remediation_steps, resource_link) VALUES 
    ('rem008', 'm008', 'Sock5 Systemz Remediation', 
     'Manual removal is a lengthy and complicated process that requires the user to possess a good level of technical skills. The steps involved are: 
        Step 1: Disconnect the infected device from the network immediately to stop it from forwarding the proxy traffic and communicating with the C2 servers. 
        Step 2: Run a full system scan using reputable antivirus software such as Norton, Malwarebytes, or Windows Defender to detect and remove the malware.  
        Step 3: Ensure the antivirus software are fully updated before you start the scan. 
        Step 4: Open Task Manager by pressing “CTRL + SHIFT + ESC”.  
        Step 5: Identify any suspicious or unknown processes, right-click each unfamiliar process found and select “Open File Location”. 
        Step 6: End the process and delete the associated file if confirmed to be malicious. 
        Step 7: Check startup entries by pressing “WIN + R”, then type “msconfig”. 
        Step 8: Click on the “Startup” tab, then disable any entries with “Unknown” as the manufacturer or that point to unfamiliar file locations. 
        Step 9: As a preventative measure for the future, ensure all devices have strong, unique passwords (not factory defaults) and keep all software and firmware updated to patch known vulnerabilities.',
     NULL); 

INSERT INTO remediation (remediation_id, malware_id, remediation_name, remediation_steps, resource_link) VALUES 
    ('rem009', 'm009', 'ValleyRAT Remediation', 
     'Manual removal is lengthy and complicated process that requires the user to possess a good level of technical skills. The steps involved are: 
        Step 1: Identify the name of the malware you are trying to remove.
        Step 2: Download a program called Autoruns. This is a program that automatically starts applications. 
        Step 3: Restart your computer into Safe Mode.
        Step 4: Extract the downloaded archive and run the Autoruns.exe file.
        Step 5: Open the Autoruns application and inside click "Options" at the top and uncheck "Hide Empty Locations" and "Hide Windows Entries". After unchecking those options click the "Refresh" icon. 
        Step 6: Check the list provided by the Autoruns application and locate the malware file that you want to eliminate. 
        Step 7: Note down the file path to the file wish to delete and be careful not to delete legitimate system processes. 
        Step 8: Then right click on the file and select "Delete". This ensure that malware will not run automatically on the next system startup. 
        Step 9: Search your system on "File Explorer" for the malware name and if found delete it. 
        Step 10: Finally, reboot your computer in normal mode.', 
     'This link provides the resource article(s) used: https://www.pcrisk.com/removal-guides/27867-valleyrat-malware');

INSERT INTO remediation (remediation_id, malware_id, remediation_name, remediation_steps, resource_link) VALUES 
    ('rem010', 'm010', 'Vidar Remediation', 
     'Immediately disconnect the infected device from the internet to prevent further data from being sent to the C2 server. 
      Manual removal is lengthy and complicated process that requires the user to possess a good level of technical skills. 
      The steps below provide a guide to follow when attempting to manually remove the Vidar malware: 
        Step 1: Identify the name of the malware you are trying to remove.
        Step 2: Download a program called Autoruns. This is a program that automatically starts applications.
        Step 3: Restart your computer into Safe Mode.
        Step 4: Extract the downloaded archive and run the Autoruns.exe file. 
        Step 5: Open the Autoruns application and inside click Option at the top and uncheck "Hide Empty Locations" and "Hide Windows Entries". After unchecking those options click the "Refresh" icon. 
        Step 6: Check the list provided by the Autoruns application and locate the malware file that you want to eliminate. 
        Step 7: Note down the file path to the file wish to delete and be careful not to delete legitimate system processes. 
        Step 8: Then right click on the file and select "Delete". This ensure that malware will not run automatically on the next system startup. 
        Step 9: Search your system on "File Explorer" for the malware name and if found delete it. 
        Step 10: Finally, reboot your computer in normal mode. 


     The steps involved for an automatic removal are: 
        Step 1: Please download Malwarebytes to your desktop. 
        Step 2: Double-click MBSetup.exe and follow the prompts to install the program. 
        Step 3: When your Malwarebytes for Windows installation completes, the program opens to the Welcome to Malwarebytes screen. 
        Step 4: Click on the Get started button. 
        Step 5: Click Scan to start a Threat Scan. 
        Step 6: Click Quarantine to remove the found threats. 
        Step 7: Reboot the system if prompted to complete the removal process.', 
     'This link provides the resource article(s) used: https://www.pcrisk.com/removal-guides/14274-vidar-trojan and https://www.malwarebytes.com/blog/detections/spyware-vidar');

