# GoRedShell
A cross platform tool for verifying credentials and executing single commands


## USAGE

```
Usage of ./GoRedShell:
  -host string
    	indicate the host or ip address to brute force
  -hostList string
    	indicate wordlist file that has hosts or ips on each line
  -cred string
    	a single un:pw credential pair to use
  -credList string
    	a username:password wordlist list, with unique un:pw combos on each line
  -exec string
    	a single command to execute when auth is successful
  -method string
    	the auth mechanism to use for the brute force (winrm or ssh)
  -verbose
    	verbosly send messages to the console
  -log
    	a switch to turn logging on or off (default off)
  -logName string
    	indicate a file to log verbosly to (default "logFile.txt")
  -nobanner
    	a switch to silence the banner when run (default off)
  -timeout duration
    	set timeout for an ssh response (default 300ms)
  -delay duration
    	add a delay to each scan, ex: 1s || 1000ms  (default 0s)
```

### Required Params
- method
- host or hostList
- cred or credList
- exec


## Shoutoutz
- Ne0nd0g
- Gen0cide
- Vyrus001
- Jackson5-sec
- byt3bl33d3r
