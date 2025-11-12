# CIS F5 Benchmark Reporter

The CIS_F5_Benchmark_Reporter.py script can be run from a F5 BIG-IP and will check if the configuration is compliant with the *[CIS Benchmark for F5](https://www.cisecurity.org/benchmark/f5)*.

Use the appropriate arguments to report to file, mail or screen. See the help page below.
```
[root@bigipa:Active:Standalone] # ./CIS_F5_Benchmark_Reporter.py
Usage: CIS_F5_Benchmark_Reporter.py [OPTION]...

Mandatory arguments to long options are mandatory for short options too.
  -f, --file=FILE            output report to file.
  -m, --mail                 output report to mail.
  -s, --screen               output report to screen.

Report bugs to nvansluis@gmail.com
[root@bigipa:Active:Standalone] #
```

Below is a screenshot that shows what the report will look like if sent by e-mail.

![Screenshot of the actual report](/assets/screenshot-01.png "Screenhot 01")

### Settings
In the script, there is a section named 'User Options'. These options should be modified to reflect your setup.
```
#-----------------------------------------------------------------------
# User Options - Configure as desired
#-----------------------------------------------------------------------
```

#### E-mail settings
Here the e-mail setting can be configured, so the script will be able to send a report by e-mail. 
```
# e-mail settings
port = 587
smtp_server = "smtp.example.com"
sender_email = "johndoe@example.com"
receiver_email = "johndoe@example.com"
login = "johndoe"
password = "mySecret"
```

#### SNMP settings
Here you can add additional SNMP clients. These are necessary to be compliant with control 6.1.
```
# list containing trusted IP addresses and networks that have access to SNMP (control 6.1)
snmp_client_allow_list = [
    "127.0.0.0/8",
]
```

#### Exceptions
Sometimes there are valid circumstances, why a specific requirement of a security control can't be met. In this case you can add an exception. See the example below.
```
# set exceptions (add your own exceptions)
exceptions = {
    '2.1' : "Exception in place, because TACACS is used instead of RADIUS.",
    '2.2' : "Exception in place, because TACACS is used and there are two TACACS-servers present."
}
```

### Recommendations
Store the script somewhere in the /shared partition. The data stored on this partition will still be available after an upgrade.

### Feedback
The script has been tested on F5 BIG-IP version 17.x. If you have any questions, remarks or feedback, just let me know.
