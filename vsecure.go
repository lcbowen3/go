package main

import (
  "fmt"
  "os"
  "strings"
  "syscall"
  "crypto/tls"
  "net/http"
  "encoding/base64"
  "io/ioutil"
  "golang.org/x/crypto/ssh/terminal"
  vault "github.com/hashicorp/vault/api"
)

// Initialize global variables/constants

const VAULTSERVER = "<set to the full URL of your Vault instance, including port>"

const LISTNAME = "elements"

// Global variable to hold tokens so user only has to log in once
var ATOKEN,TOKEN string

var ADNAME string // This will hold the username after the auth
var ADPASS string // This holds the user's password - this will be used
// after creating a new policy to generate another token
 
var FNAME string // This will hold the base filename, if any (no path)
var FDATAOUT string // data to store to value

// The following username and password has very limited access to Vault
// it's used specifically for adding new user paths and policies
const VLNAME = "<admin username>"
const VLPASS = "<admin password>"

// The next constants hold the start and end of the default user policy.
// The ADNAME is added to the end of the start and mid
const POLICYSTART = `path "secret/usr/`
const POLICYMID = `" {
  policy = "write"
}

path "secret/usr/`
const POLICYEND = `/*" { 
  policy = "write" 
}

path "auth/token/lookup-self" { 
  policy = "read"
}`


// Functions

// errorString is a trivial implementation of error.
type errorString struct {
    s string
}

// This allows me to return any text as an error value
func (e *errorString) Error() string {
    return e.s
}

// This function prints help for the program and exits
func Usage() {
  fmt.Println()
  fmt.Println("This program stores, deletes, retrieves, or lists key names of data")
  fmt.Println("stored in the secured data store.")
  fmt.Println()
  fmt.Println("Usage:")
  fmt.Println("vsecure store <key name> \"<value>\" || @<filename>")
  fmt.Println("vsecure remove <key name>")
  fmt.Println("vsecure get <key name>")
  fmt.Println("vsecure list")
  fmt.Println()
  fmt.Println("\"store\" will put the contents of the \"value\" into the <key name>")
  fmt.Println("Alternately, it can store the contents of <filename> to the <key name>")
  fmt.Println("as long as the file size is no more than 200kb")
  fmt.Println()
  fmt.Println("\"remove\" will delete the \"<key name>\"")
  fmt.Println()
  fmt.Println("\"get\" retrieves the \"value\" or file stored in <key name>")
  fmt.Println()
  fmt.Println("\"list\" will list the <key names> which you have stored")
  fmt.Println()
fmt.Println("\"help\" or \"-h\" will print this message")
  fmt.Println()
  os.Exit(1)
}


// This function logs into Vault and returns a TOKEN.
func vLogin(uname, passwd, ltype string) string {

  switch strings.ToLower(ltype) {
     case "ldap": 
        var uName string
        var uPass []byte
        if uname == "" || passwd == "" {
          fmt.Print("Enter UserName: ")
          fmt.Scanln(&uName)
          ADNAME = uName
          fmt.Print("Enter Password: ")
          oldState, err := terminal.MakeRaw(int(syscall.Stdin))
          if err != nil {
             panic(err.Error())
          }
          defer terminal.Restore(int(syscall.Stdin), oldState)
          uPass, _ = terminal.ReadPassword(int(syscall.Stdin))
          fmt.Println("")
          terminal.Restore(int(syscall.Stdin), oldState)
        } else {
          uName = uname
          uPass = []byte(passwd)
        }
        s := map[string]interface{}{ "password": string(uPass[:]) }
        ADPASS = string(uPass)
        config := tls.Config{InsecureSkipVerify: true}

        cnfg := vault.DefaultConfig()
        cnfg.Address = VAULTSERVER
        cnfg.HttpClient.Transport = &http.Transport{
             TLSClientConfig: &config,
        }
        client, err := vault.NewClient(cnfg)
        if err != nil {
          panic(err.Error())
        }
        URL := []string{"/auth/ldap/login/",uName}
        UPATH := strings.Join(URL, "")
        response, err := client.Logical().Write(UPATH, s)
        if err != nil {
          fmt.Println("User not recognized.")
          return ""
        }
        return response.Auth.ClientToken
     case "userpass": 
        s := map[string]interface{}{ "password": passwd }
        config := tls.Config{InsecureSkipVerify: true}

        cnfg := vault.DefaultConfig()
        cnfg.Address = VAULTSERVER
        cnfg.HttpClient.Transport = &http.Transport{
             TLSClientConfig: &config,
        }
        client, err := vault.NewClient(cnfg)
        if err != nil {
          panic(err.Error())
        }
        URL := []string{"/auth/userpass/login/",uname}
        UPATH := strings.Join(URL, "")
        response, err := client.Logical().Write(UPATH, s)
        if err != nil {
          fmt.Println("User not recognized.")
          return ""
        }
        return response.Auth.ClientToken
     default: return ""
  }
}

// This function is the main STORE function.  It calls several others
func store(keyname, vstring string) error {
  // Verify the path exists, create if not
  err := pathVerify()
  if err != nil {
    return err
  }

// Path has been verified.  

// Read the element list so the new value can be added
  SECRETPATH := fmt.Sprint("secret/usr/", ADNAME)
  response := getVaultValue(SECRETPATH, TOKEN)
  ELEMENTLIST := response.Data[LISTNAME].(string)
  
// Check the value to see if it's a file
  if string(vstring[0]) == "@" {
  // Save the filename
    FNAME = string(vstring[1:])

  // Open the file and get it's info
    fi, err := os.Lstat(FNAME)
    if err != nil {
        return err 
    }

  // If it's bigger than 200kb, print error and exit
    if fi.Size() > 204800 {
       fmt.Println("The file size must be under 200kb.")
       return err
    }

  // Read the file contents
    FDATA, err := ioutil.ReadFile(FNAME)
    if err != nil {
      fmt.Println("File read error: ",err)
      return err
    }

  // Encode the data so we can store it
    FDATAOUT = base64.StdEncoding.EncodeToString(FDATA)
  
  // And save the actual name of the file in FNAME
    FNAME = fi.Name()
  } else {
// Not a file, we'll store the value string
    FNAME = ""
    FDATAOUT = vstring
  }

  // Prepare to write the new key (create the payload)
  s := map[string]interface{}{ 
     "value": FDATAOUT,
     "filename": FNAME }
  
  // Write the key
  KEYPATH := fmt.Sprint("secret/usr/", ADNAME, "/", strings.ToLower(keyname))
  err = putVaultValue(KEYPATH, TOKEN, s)
  if err != nil {
     fmt.Println("Error writing key")
     return err
  }

  // Write the element name to the list
  EOUT := ""
  if ELEMENTLIST == "" {
       EOUT = fmt.Sprint(strings.ToLower(keyname))
  } else {
       EOUT = fmt.Sprint(ELEMENTLIST,",",strings.ToLower(keyname))
  }
  s = map[string]interface{}{ LISTNAME: EOUT }
  EPATH := fmt.Sprint("secret/usr/", ADNAME)
  err = putVaultValue(EPATH, TOKEN, s)
  if err != nil {
     fmt.Println("Error Writing Element list")
     return err
  }
  fmt.Println("Successfully stored ", keyname)
  if FNAME != "" {
     fmt.Println("Please be sure to remove the file ",FNAME," to ensure security.")
  }
  return nil
}

func getVaultValue(keypath, tokenstr string) *vault.Secret {

  config := tls.Config{InsecureSkipVerify: true}
  cnfg := vault.DefaultConfig()
  cnfg.Address = VAULTSERVER
  cnfg.HttpClient.Transport = &http.Transport{
     TLSClientConfig: &config,
  }
  client, err := vault.NewClient(cnfg)
  if err != nil {
    panic(err.Error())
  }
  client.SetToken(tokenstr)
  SPATH := keypath
  response, err := client.Logical().Read(SPATH)
  if err != nil {
     fmt.Println("Error Reading Path")
  }
  return response

}

func putVaultValue(keypath, tokenstr string, s map[string]interface{}) error {

  config := tls.Config{InsecureSkipVerify: true}
  cnfg := vault.DefaultConfig()
  cnfg.Address = VAULTSERVER
  cnfg.HttpClient.Transport = &http.Transport{
     TLSClientConfig: &config,
  }
  client, err := vault.NewClient(cnfg)
  if err != nil {
    panic(err.Error())
  }
  client.SetToken(tokenstr)
  SPATH := keypath
  _, err = client.Logical().Write(SPATH, s)

  return err

}

func pathVerify() error {
 // Get admin token so we can check the path
  ATOKEN = vLogin(VLNAME, VLPASS, "userpass")
  if ATOKEN == "" {
    return fmt.Errorf("%s","Admin Login failed")
  }
 // Get user login token so we can know the path
  TOKEN = vLogin("", "", "ldap")
  if TOKEN == "" {
    return fmt.Errorf("%s","User Login failed")
  }

  SECRETPATH := fmt.Sprint("secret/usr/", ADNAME)
  response := getVaultValue(SECRETPATH, TOKEN)

  if response == nil {
  // Path does not exist.  Create it
    s := map[string]interface{}{ "elements": "" }
    err := putVaultValue(SECRETPATH, ATOKEN, s)
    if err != nil {
       return err
    }
  // Create policy for user
    p := strings.Join([]string{POLICYSTART,ADNAME,POLICYMID,ADNAME,POLICYEND},"")
    s = map[string]interface{}{ "rules": p }
    POLICYPATH := fmt.Sprint("sys/policy/", ADNAME)
    err = putVaultValue(POLICYPATH, ATOKEN, s)
    if err != nil {
       return err
    }
  // Add it to a new ldap group <sigh>, then
    s = map[string]interface{}{ "policies": ADNAME }
    GRPPATH := fmt.Sprint("auth/ldap/groups/", ADNAME)
    err = putVaultValue(GRPPATH, ATOKEN, s)
    if err != nil {
       return err
    }
  // Add it to the user's account
    s = map[string]interface{}{ "groups": ADNAME }
    USERPATH := fmt.Sprint("auth/ldap/users/", ADNAME)
    err = putVaultValue(USERPATH, ATOKEN, s)
    if err != nil {
       return err
    }
  // Generate a new token to take into account the new policy
    TOKEN = vLogin(ADNAME, ADPASS, "ldap")
  }
  return nil
}

func remove(keyname string) error {

  TOKEN = vLogin("", "", "ldap")
  if TOKEN == "" {
    return fmt.Errorf("%s","User Login failed")
  }

 // Get element list
  EPATH := fmt.Sprint("secret/usr/", ADNAME)
  ELIST := getVaultValue(EPATH, TOKEN)

 //Split the list into an array
  EARRAY := strings.Split(ELIST.Data[LISTNAME].(string),",")
  TNUM := -1
 // Search the array for the keyname value
  for lup, v := range EARRAY {
     if v == keyname {
        TNUM = lup
        break
     }
  }
 // If value isn't found, report it
  if TNUM == -1 {
     fmt.Println("Key name was not found in the list")
     return &errorString{"KeyError"} 
  }

 // Delete the keyname
  config := tls.Config{InsecureSkipVerify: true}
  cnfg := vault.DefaultConfig()
  cnfg.Address = VAULTSERVER
  cnfg.HttpClient.Transport = &http.Transport{
     TLSClientConfig: &config,
  }
  client, err := vault.NewClient(cnfg)
  if err != nil {
    return err
  }
  client.SetToken(TOKEN)
  SPATH := fmt.Sprint("secret/usr/", ADNAME, "/", keyname)
  _, err = client.Logical().Delete(SPATH)
  if err != nil {
    return err
  }

 //Remove the key from the key list
  var s map[string]interface{}
  if TNUM == -1 || TNUM == 0 {
    s = map[string]interface{}{ LISTNAME: "" }
  } else if TNUM > 0 {
    elst1 := strings.Join(EARRAY[:TNUM],",")
    elst2 := strings.Join(EARRAY[TNUM+1:],",")
    elst := strings.Join([]string{elst1,elst2},",")
    s = map[string]interface{}{ LISTNAME: elst }
  }
 // And write it to the Vault
  err = putVaultValue(EPATH, TOKEN, s) 
  return err
}

func get(keyname string) error {
  TOKEN = vLogin("", "", "ldap")
  if TOKEN == "" {
    return fmt.Errorf("%s","User Login failed")
  }

 // Get element list
  EPATH := fmt.Sprint("secret/usr/", ADNAME)
  ELIST := getVaultValue(EPATH, TOKEN)

 //Split the list into an array
  EARRAY := strings.Split(ELIST.Data[LISTNAME].(string),",")
  TNUM := -1
 // Search the array for the keyname value
  for lup, v := range EARRAY {
     if v == keyname {
        TNUM = lup
        break
     }
  }
 // If value isn't found, report it
  if TNUM == -1 {
     fmt.Println("Key name was not found in the list")
     return &errorString{"KeyError"}
  }
 //Get the value from Vault
  SPATH := fmt.Sprint("secret/usr/", ADNAME, "/", keyname)
  res := getVaultValue(SPATH, TOKEN)
  if res.Data["filename"].(string) != "" {
 // File was stored, need to create the file and decode contents before writing
     FNAME = fmt.Sprint("./",res.Data["filename"].(string))
 //Check to see if file exists in current directory
     _, err := os.Stat(FNAME)
     if err == nil {
 // File exists, fail out
        return &errorString{"File exists in current directory.  Remove or change directory before requesting."}
     }
     valstring, _ :=  base64.StdEncoding.DecodeString(res.Data["value"].(string))
     err = ioutil.WriteFile(FNAME, []byte(valstring), 0600)
     if err != nil {
        return err
     }
 //Return success message
     fmt.Println("Successfully retieved file ",res.Data["filename"].(string)," to current directory.")    
     return nil
  } else {
     rvalue := res.Data["value"].(string)
 // Print the value
     fmt.Println("Key: ",keyname)
     fmt.Println("Value: ",rvalue)
  }
  return nil
}

//This function lists the contents of the user's vault area
func list () error {

  TOKEN = vLogin("", "", "ldap")
  if TOKEN == "" {
    return fmt.Errorf("%s","User Login failed")
  }

 // Get element list
  EPATH := fmt.Sprint("secret/usr/", ADNAME)
  ELIST := getVaultValue(EPATH, TOKEN)

 //Split the list into an array
  EARRAY := strings.Split(ELIST.Data[LISTNAME].(string),",")
 
 // Search the array for the keyname value
  for _, v := range EARRAY {
     fmt.Println("Key(s): ",v)
  }
  return nil

}

// Main

func main() {

// Verify that the program was properly called
  commandline := os.Args[1:]
  if len(commandline) > 3 || len(commandline) < 1 {
     Usage()
  }

// And call the proper function for the call
  switch strings.ToLower(string(commandline[0])) {
    case "help","-h": Usage()
    case "store":
      if len(commandline) != 3 {
         Usage()
      }
      err := store(commandline[1],commandline[2])
      if err != nil {
         fmt.Println(err)
         os.Exit(1)
      }
    case "remove": 
      if len(commandline) != 2 {
         Usage()
      }
      err := remove(commandline[1])
      if err != nil {
         fmt.Println(err)
         os.Exit(1)
      }
      fmt.Println("Successfully removed ",commandline[1])
    case "get":
      if len(commandline) != 2 {
         Usage()
      }
      err := get(commandline[1])
      if err != nil {
         fmt.Println(err)
         os.Exit(1)
      }
    case "list": 
      if len(commandline) != 1 {
         Usage()
      }
      err := list()
      if err != nil {
         fmt.Println(err)
         os.Exit(1)
      }
    default: Usage()
  }

}

