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

### Recommendations
Store the script somewhere in the /shared partition. The data stored on this partition will still be available after an upgrade.

### Feedback
The script has been tested on F5 BIG-IP version 17.x. If you have any questions, remarks or feedback, just let me know.
