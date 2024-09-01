#!/bin/bash
#
# Author  : Andrew Barnett - https://github.com/AndrewMBarnett
# Created : 12/08/2023
# Updated : 12/21/2023
# Version : v1.1
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Description:
#	Script to display the JAMF LAPS account and password
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Script Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

scriptLog="${4:-"/var/log/com.company.log"}"    							# Parameter 4: Log File Location
TEAMSURL="${5:-""}"															# Parameter 5: Teams webhook URL 
SLACKURL="${6:-""}"															# Parameter 6: Slack webhook URL
SERVICEDESK="${7:-""}"														# Parameter 7: Service Desk website URL 
useOverlayIcon="${8:-"true"}" 												# Parameter 8: User Jamf Icon for overlay icon [ true (default) | false ] 

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Jamf and Dialog Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

jamfBinary="/usr/local/bin/jamf"
dialogBinary="/usr/local/bin/dialog"
dialog="/Library/Application Support/Dialog/Dialog.app"
swiftDialogMinimumRequiredVersion="2.3.2.4726"
dialogVersion=$( /usr/local/bin/dialog --version )
scriptVersion="1.0"

# Dialog Icon and Banner

appTitle="Swift LAPS"				# Update the title of the Dialog windows
brandingBanner=""                               # Banner image to show behind title text
brandingIconLight="SF=lock.icloud"
brandingIconDark="SF=lock.icloud.fill"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# JSON file Path
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

LAPSPromptJSONFile=$( mktemp -u /var/tmp/LAPSPromptJSONFile.XXX )
LAPSPromptCommandFile=$( mktemp -u /var/tmp/dialogCommandFileLAPSPrompt.XXX )
resultsJSONFile=$( mktemp -u /var/tmp/resultsJSONFile.XXX )
resultsCommandFile=$( mktemp -u /var/tmp/dialogCommandFileResults.XXX )

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Operating System, Computer Model Name, etc.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

computerNameOfAdmin=$( scutil --get ComputerName )
DEVICE=`hostname`
osVersion=$( sw_vers -productVersion )
osMajorVersion=$( echo "${osVersion}" | awk -F '.' '{print $1}' )
osBuild=$( sw_vers -buildVersion )
modelName=$( /usr/libexec/PlistBuddy -c 'Print :0:_items:0:machine_name' /dev/stdin <<< "$(system_profiler -xml SPHardwareDataType)" )
dialogVersion=$( /usr/local/bin/dialog --version )
timestamp="$( date '+%Y-%m-%d-%H%M%S' )"
serialNumber=$( ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformSerialNumber/{print $4}' )
currentURL=$(/usr/bin/defaults read /Library/Preferences/com.jamfsoftware.jamf.plist jss_url | sed 's|/$||')

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Login Prompt Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Variables to show on the login window before text is entered 

jamfURLPrompt="Enter Jamf URL"
jamfUsernamePrompt="Enter Jamf Username"
computerSerialPrompt="Enter Computer Serial Number"
reasonPrompt="Reason for LAPS Request"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# IT Support Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

supportTeamName="Add IT Support"
supportTeamPhone="Add IT Phone Number"
supportTeamEmail="Add email"
supportTeamWebsite="Add IT Help site"
supportTeamHyperlink="[${supportTeamWebsite}](https://${supportTeamWebsite})"

# Create the help message based on Support Team variables
helpMessage="If you need assistance, please contact ${supportTeamName}:  \n- **Telephone:** ${supportTeamPhone}  \n- **Email:** ${supportTeamEmail}  \n- **Help Website:** ${supportTeamHyperlink}  \n\n**Computer Information:**  \n- **Operating System:**  $osVersion ($osBuild)  \n- **Serial Number:** $serialNumber  \n- **Dialog:** $dialogVersion  \n- **Started:** $timestamp"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Setup Client-side Logging
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ ! -f "${scriptLog}" ]]; then
touch "${scriptLog}"
fi

function updateScriptLog() {
echo -e "$( date +%Y-%m-%d\ %H:%M:%S ) - ${1}" | tee -a "${scriptLog}"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Current Logged-in User Function
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function currentLoggedInUser() {
loggedInUser=$( echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ { print $3 }' )
updateScriptLog "Current Logged-in User: ${loggedInUser}"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Current Logged-in User Computer Function
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function currentLoggedInUserComputer() {
updateScriptLog "Current Logged-in User Computer: ${computerNameOfAdmin}"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Logging Info
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "\n\n###\n# Jamf Laps (${scriptVersion})\n# https://github.com/AndrewMBarnett"
updateScriptLog "Initiating Jamf Laps…"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Confirm Dock is running / user is at Desktop
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

until pgrep -q -x "Finder" && pgrep -q -x "Dock"; do
    updateScriptLog "Finder & Dock are NOT running; pausing for 1 second"
    sleep 1
done

updateScriptLog "Finder & Dock are running; proceeding …"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Validate Logged-in System Accounts
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "Check for Logged-in System Accounts …"
currentLoggedInUser

counter="1"

until { [[ "${loggedInUser}" != "_mbsetupuser" ]] || [[ "${counter}" -gt "180" ]]; } && { [[ "${loggedInUser}" != "loginwindow" ]] || [[ "${counter}" -gt "30" ]]; } ; do

    updateScriptLog "Logged-in User Counter: ${counter}"
    currentLoggedInUser
    sleep 2
    ((counter++))

done

loggedInUserFullname=$( id -F "${loggedInUser}" )
loggedInUserFirstname=$( echo "$loggedInUserFullname" | sed -E 's/^.*, // ; s/([^ ]*).*/\1/' | sed 's/\(.\{25\}\).*/\1…/' | awk '{print ( $0 == toupper($0) ? toupper(substr($0,1,1))substr(tolower($0),2) : toupper(substr($0,1,1))substr($0,2) )}' )
loggedInUserID=$( id -u "${loggedInUser}" )
updateScriptLog "Current Logged-in User First Name: ${loggedInUserFirstname}"
updateScriptLog "Current Logged-in User ID: ${loggedInUserID}"


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Confirm script is running as root
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ $(id -u) -ne 0 ]]; then
updateScriptLog "This script must be run as root; exiting."
exit 1
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Parse JSON via osascript and JavaScript
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function get_json_value() {
    # set -x
    JSON="$1" osascript -l 'JavaScript' \
        -e 'const env = $.NSProcessInfo.processInfo.environment.objectForKey("JSON").js' \
        -e "JSON.parse(env).$2"
    # set +x
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Parse JSON via osascript and JavaScript for the start prompt dialog (thanks, @bartreardon!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function get_json_value_startPromptDialog() {
    # set -x
    for var in "${@:2}"; do jsonkey="${jsonkey}['${var}']"; done
    JSON="$1" osascript -l 'JavaScript' \
        -e 'const env = $.NSProcessInfo.processInfo.environment.objectForKey("JSON").js' \
        -e "JSON.parse(env)$jsonkey"
    # set +x
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Functions / Validate / install swiftDialog 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 


function extract_from_json() {
  echo "$1" | awk -v key="$2" '
    BEGIN {
      RS = "[},]";
      FS = "[:,]";
    }
    {
      for (i = 1; i <= NF; i += 2) {
        if ($i ~ "\"" key "\"") {
          gsub(/["{}]/, "", $(i + 1));
          gsub(/^[\t ]+|[\t ]+$/, "", $(i + 1));
          print $(i + 1);
          exit;
        }
      }
    }
  '
}

function dialogInstall() {

    # Get the URL of the latest PKG From the Dialog GitHub repo
    dialogURL=$(curl -L --silent --fail "https://api.github.com/repos/swiftDialog/swiftDialog/releases/latest" | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")

    # Expected Team ID of the downloaded PKG
    expectedDialogTeamID="PWA5E9TQ59"

    updateScriptLog "Installing swiftDialog..."

    # Create temporary working directory
    workDirectory=$( basename "$0" )
    tempDirectory=$( mktemp -d "/private/tmp/$workDirectory.XXXXXX" )

    # Download the installer package
    curl --location --silent "$dialogURL" -o "$tempDirectory/Dialog.pkg"

    # Verify the download
    teamID=$(spctl -a -vv -t install "$tempDirectory/Dialog.pkg" 2>&1 | awk '/origin=/ {print $NF }' | tr -d '()')

    # Install the package if Team ID validates
    if [[ "$expectedDialogTeamID" == "$teamID" ]]; then

        /usr/sbin/installer -pkg "$tempDirectory/Dialog.pkg" -target /
        sleep 2
        dialogVersion=$( /usr/local/bin/dialog --version )
        updateScriptLog "swiftDialog version ${dialogVersion} installed; proceeding..."

    else

        # Display a so-called "simple" dialog if Team ID fails to validate
        osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\r• Dialog Team ID verification failed\r\r" with title "'"${scriptFunctionalName}"': Error" buttons {"Close"} with icon caution'
        exitCode="1"
        quitScript

    fi

    # Remove the temporary working directory when done
    rm -Rf "$tempDirectory"

}

function dialogCheck() {

    # Check for Dialog and install if not found
    if [ ! -e "/Library/Application Support/Dialog/Dialog.app" ]; then

        updateScriptLog "swiftDialog not found. Installing..."
        dialogInstall

    else

        dialogVersion=$(/usr/local/bin/dialog --version)
        if [[ "${dialogVersion}" < "${swiftDialogMinimumRequiredVersion}" ]]; then
            
            updateScriptLog "swiftDialog version ${dialogVersion} found but swiftDialog ${swiftDialogMinimumRequiredVersion} or newer is required; updating..."
            dialogInstall
            
        else

        updateScriptLog "swiftDialog version ${dialogVersion} found; proceeding..."

        fi
    
    fi

}

dialogCheck

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Branding Functions
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function branding(){
    # Icon set to either light or dark, based on user's Apperance setting (thanks, @mm2270!)
    appleInterfaceStyle=$( /usr/bin/defaults read /Users/"${loggedInUser}"/Library/Preferences/.GlobalPreferences.plist AppleInterfaceStyle 2>&1 )
    if [[ "${appleInterfaceStyle}" == "Dark" ]]; then
        if [[ -n "$brandingIconDark" ]]; then startIcon="$brandingIconDark";
        else startIcon="https://cdn-icons-png.flaticon.com/512/740/740878.png"; fi
    else
        if [[ -n "$brandingIconLight" ]]; then startIcon="$brandingIconLight";
        else startIcon="https://cdn-icons-png.flaticon.com/512/979/979585.png"; fi
    fi

    if [[ "$useOverlayIcon" == "true" ]]; then
        # Create `overlayicon` from Self Service's custom icon (thanks, @meschwartz!)
        xxd -p -s 260 "$(defaults read /Library/Preferences/com.jamfsoftware.jamf self_service_app_path)"/Icon$'\r'/..namedfork/rsrc | xxd -r -p > /var/tmp/overlayicon.icns
        overlayicon="/var/tmp/overlayicon.icns"
    fi

    if [[ -n "${brandingBanner}" ]]; then
    bannerImage="${brandingBanner}"
    else
    bannerImage="https://img.freepik.com/free-photo/orange-texture_64049-250.jpg" # Image by kdekiara on Freepik.com
    fi
}

# Call branding function
branding

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Request auth token
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function requestAuthToken() {

authToken=$( /usr/bin/curl \
--request POST \
--silent \
--url "$URL1/api/v1/auth/token" \
--user "$USER:$PASSWORD" )

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Bearer token validation
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function bearerToken() {

apitokenCheck=$(/usr/bin/curl --write-out %{http_code} --silent --output /dev/null "${URL1}/api/v1/auth" --request GET --header "Authorization: Bearer ${token}")

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Token Expiration Info
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function tokenExpiration() {

tokenExpiration=$( /usr/bin/plutil \
-extract expires raw - <<< "$authToken" )

localTokenExpirationEpoch=$( TZ=GMT /bin/date -j \
-f "%Y-%m-%dT%T" "$tokenExpiration" \
+"%s" 2> /dev/null )

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# API request for Computer ID
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function apiResponse() {

response=$(curl -s -X GET \
  -H "Authorization: Bearer $token" \
  -H "Accept: application/xml" \
  "$URL1/JSSResource/computers/serialnumber/$serialNumber")

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Get Computer ID
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function computerIDScript() {

# Extract the computer ID based on the serial number from the response using xmllint and sed
computer_id=$(echo "$response" | xmllint --xpath 'string(/computer/general/id)' - | sed 's/[^0-9]*//g')

# Print the computer ID
# updateScriptLog "Computer ID: $computer_id"

# Send API request to get the computer inventory details
response2=$(curl -s -X GET \
   -H "Authorization: Bearer $token" \
   -H "accept: application/json" \
   "$URL1/api/v1/computers-inventory-detail/$computer_id")

   # Extract the management ID from the response using awk
management_id=$(extract_from_json "$response2" "managementId")

# If the managementId is not directly in the top-level JSON object,
# try extracting from the "general" key
if [ -z "$management_id" ]; then
  management_id=$(extract_from_json "$response2" "general:managementId")
fi

# Print the management ID
# updateScriptLog "Management ID: $management_id"

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Get LAPS Info
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function lapsIDLogin() {

# Send API request to get the LAPS username
laps_username_response=$(curl -s -X GET \
   -H "Authorization: Bearer $token" \
   -H "accept: application/json" \
   "$URL1/api/v2/local-admin-password/$management_id/accounts")

# Extract the LAPS username from the response using awk
laps_username=$(extract_from_json "$laps_username_response" "username")

# Send API request to get the LAPS password
laps_password_response=$(curl -s -X GET \
   -H "Authorization: Bearer $token" \
   -H "accept: application/json" \
   "$URL1/api/v2/local-admin-password/$management_id/account/$laps_username/password")

# Extract the LAPS password from the response using awk
laps_password=$(extract_from_json "$laps_password_response" "password")
# updateScriptLog $laps_password

# Get the LAPS accounts
accountInfo=$( curl -X 'GET' \
    --silent \
  "$URL1"/api/v2/local-admin-password/"$management_id"/accounts \
  -H 'accept: application/json' \
  -H "Authorization: Bearer $token"
)


}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Expire Token
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function invalidateToken() {
	responseCode=$(curl -w "%{http_code}" -H "Authorization: Bearer ${token}" "$URL1"/api/v1/auth/invalidate-token -X POST -s -o /dev/null)
	if [[ ${responseCode} == 204 ]]
	then
		updateScriptLog "Token successfully invalidated"
		token=""
		tokenExpirationEpoch="0"
	elif [[ ${responseCode} == 401 ]]
	then
		updateScriptLog "Token already invalid"
	else
		updateScriptLog "An unknown error occurred invalidating the token"
	fi
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Kill a specified process (thanks, @grahampugh!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function killProcess() {
    process="$1"
    if process_pid=$( pgrep -a "${process}" 2>/dev/null ) ; then
        echo "Attempting to terminate the '$process' process …"
        echo "(Termination message indicates success.)"
        kill "$process_pid" 2> /dev/null
        if pgrep -a "$process" >/dev/null ; then
            echo "ERROR: '$process' could not be terminated."
        fi
    else
        echo "The '$process' process isn't running."
    fi
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Quit Script
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function quitScript() {
    # Set Exit Code
    exitCode="$1"

    if [[ $exitCode = "0" ]]; then
        exitReason="Successfully processed"
    elif [[ $exitCode = "1" ]]; then
        exitReason="User clicked 'Quit'"
    else
        exitReason="Something else happened ..."
    fi

    echo "$exitReason"

    # Clean up temp dialog files
    if [[ -e /var/tmp/dialog.log ]]; then
        updateScriptLog "QUIT: Removing dialog.log ..."
        rm /var/tmp/dialog.log
    fi

    if [[ -e ${LAPSPromptCommandFile} ]]; then
        updateScriptLog "QUIT: Removing ${LAPSPromptCommandFile} ..."
        rm "${LAPSPromptCommandFile}"
    fi   

     if [[ -e ${LAPSPromptJSONFile} ]]; then
        updateScriptLog "QUIT: Removing ${LAPSPromptJSONFile} ..."
        rm "${LAPSPromptJSONFile}"
    fi  

    if [[ -e ${resultsCommandFile} ]]; then
        updateScriptLog "QUIT: Removing ${resultsCommandFile} ..."
        rm "${resultsCommandFile}"
    fi 

    if [[ -e ${resultsJSONFile} ]]; then
        updateScriptLog "QUIT: Removing ${resultsJSONFile} ..."
        rm "${resultsJSONFile}"
    fi 

    if [[ -e ${overlayicon} ]]; then
        updateScriptLog "QUIT: Removing ${overlayicon} ..."
        rm "${overlayicon}"
    fi


    invalidateToken

    killProcess "Dialog"
    updateScriptLog "Closing any Dialog open"

    updateScriptLog "EXIT CODE: $exitCode"
    
    exit

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Get JAMF API Credentials
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# First message to get JAMF Details
DETAILS=$(dialog \
--bannertext "$appTitle" \
--position center \
--icon "$startIcon" \
--overlayicon "$overlayicon" \
--message "Please enter your JAMF tenant details and computer details." \
--button1text "Continue" \
--button2text "Quit" \
--height 420 \
--width 740 \
--moveable \
--alignment center \
--bannerimage "$bannerImage" \
--titlefont 'shadow=true, size=45, colour=#FFFDF4' \
--messagefont 'name=Arial,size=14' \
--helpmessage "$helpMessage" \
--infobox "Computer Name:  $computerNameOfAdmin \n\n macOS Version: $osVersion" \
--infotext "V. $scriptVersion" \
--textfield "Jamf URL",required,value="$currentURL",prompt="$jamfURLPrompt" \
--textfield "Jamf Username",required,prompt="$jamfUsernamePrompt" \
--textfield "Jamf Password",required,secure \
--textfield "Serial Number",required,value="$serialNumber",prompt="$computerSerialPrompt" \
--textfield "Reason",required,prompt="$reasonPrompt" \
--json
)

# Gather URL, Username and Password

reason=$(echo $DETAILS | awk -F '"Reason" : "' '{print$2}' | awk -F '"' '{print$1}')
URL=$(echo $DETAILS | awk -F '"Jamf URL" : "' '{print$2}' | awk -F '"' '{print$1}')	
USER=$(echo $DETAILS | awk -F '"Jamf Username" : "' '{print$2}' | awk -F '"' '{print$1}')
PASSWORD=$(echo $DETAILS | awk -F '"Jamf Password" : "' '{print$2}' | awk -F '"' '{print$1}')
serialNumber=$(echo $DETAILS | awk -F '"Serial Number" : "' '{print$2}' | awk -F '"' '{print$1}') 
		
if [[ $serialNumber == "" ]] || [[ $reason == "" ]] || [[ $USER == "" ]] || [[ $PASSWORD == "" ]] || [[ $URL == "" ]]; then
	updateScriptLog "Aborting, blank information textfield submitted"
 	quitscript
	exit 1
fi

updateScriptLog "Requested by (Jamf Username): $USER"
updateScriptLog "Reason for request: $reason"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Get Device Selected URL and Format
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

URL1=$(echo $URL | sed 's#https:\\/\\/##' | sed 's#\\/##')
URL1="https://$URL1"
updateScriptLog "Selected URL for API: $URL1" 

requestAuthToken
updateScriptLog "Requesting Auth Token"

#  Extract token, use awk if OS is below macOS 12 and use plutil if 12 or above.
updateScriptLog "OS Version: $osVersion"
if [[ "${osMajorVersion}" -lt 12 ]]; then
   token=$(/usr/bin/awk -F \" 'NR==2{print $4}' <<< "${authToken}" | /usr/bin/xargs)
else
   token=$(/usr/bin/plutil -extract token raw -o - - <<< "${authToken}")
fi

bearerToken
updateScriptLog "API Token Check"

  if [[ ${apitokenCheck} != 200 ]]; then  

tokenError=$(dialog \
--title "LAPS Authorization Error" \
--titlefont "name=Arial, size=22" \
--icon "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns" \
--iconsize 80 \
--message "The information you entered was incorrect. \n\n Please try again." \
--messagefont "name=Arial,size=18" \
--messagealignment center \
--height "200" \
--width "400" \
--button1text "Exit" \
--helpmessage "$helpMessage" \
--infotext "$infotext" \
--ontop \
--moveable \
--json \
--messagealignment left \
)
    updateScriptLog "Error: ${apitokenCheck}; exiting."
    quitScript
    exit 1
  fi

tokenExpiration
updateScriptLog "Gathering token expiration info"

apiResponse
updateScriptLog "Send the API request to get the computer ID"

computerIDScript
updateScriptLog "Gathering Computer ID"

lapsIDLogin
updateScriptLog "Gathering LAPS login information"

# Math for populating a list of LAPS accounts to present in dialog
totalCount=$(get_json_value "$accountInfo" 'totalCount')
startingElement="0"

until [ $startingElement = "$totalCount" ]; do
    lapsUsernames+=($(echo "$(get_json_value "$accountInfo" 'results['"'$startingElement'"'].username')"))
    ((startingElement++))
done

for username in "${lapsUsernames[@]}"; do
    updateScriptLog "LAPS user found: $username"
done

# Additional formatting
sortedUniquelapsUsernames=($(echo "${lapsUsernames[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
lapsUsersString=$( echo "${sortedUniquelapsUsernames[@]}" | sed 's/.*/"&"/' | sed 's/\ /",\ "/g' )
computerJSSLink="[${computerName}](${URL1}/computers.html?id=${computer_id}&o=r})"

# Get computer information via API
generalComputerInfo=$( /usr/bin/curl -H "Authorization: Bearer ${token}" -H "Accept: text/xml" -sfk "${URL1}"/JSSResource/computers/id/"${computer_id}/subset/General" -X GET )
hardwareComputerInfo=$( /usr/bin/curl -H "Authorization: Bearer ${token}" -H "Accept: text/xml" -sfk "${URL1}"/JSSResource/computers/id/"${computer_id}/subset/Hardware" -X GET )

# Parse individual details
computerName=$( echo "${generalComputerInfo}" | xpath -q -e "/computer/general/name/text()" )
computerSerialNumber=$( echo "${generalComputerInfo}" | xpath -q -e "/computer/general/serial_number/text()" )
computerModel=$( echo "${hardwareComputerInfo}" | xpath -q -e "/computer/hardware/model/text()" )
computerOSVersion=$( echo "${hardwareComputerInfo}" | xpath -q -e "/computer/hardware/os_version/text()" )
computerIpAddress=$( echo "${generalComputerInfo}" | xpath -q -e "/computer/general/ip_address/text()" ) 
computerIpAddressLastReported=$( echo "${generalComputerInfo}" | xpath -q -e "/computer/general/last_reported_ip/text()" )
computerInventoryGeneral=$( /usr/bin/curl -H "Authorization: Bearer ${token}" -s "${URL1}/api/v1/computers-inventory?section=GENERAL&filter=id==${computer_id}" -H "accept: application/json" -X GET )
managementID=$(get_json_value "$computerInventoryGeneral" 'results[0].general.managementId' )

# URL of computer we are searching
jamfProComputerURL="[$computerName](${URL1}/computers.html?id=${computer_id}&o=r)"

updateScriptLog "• Name: $computerName"
updateScriptLog "• Serial Number: $computerSerialNumber"
updateScriptLog "• Model: $computerModel"
updateScriptLog "• OS Version: ${computerOSVersion}"
updateScriptLog "• IP Address: $computerIpAddress"
updateScriptLog "• IP Address (LR): $computerIpAddressLastReported"
updateScriptLog "• Server: ${URL1}"
updateScriptLog "• Computer ID: ${computer_id}"

# Get the correct SF symbols based on model
# CatchAll
computerModelIcon="SF=laptopcomputer"
caseModel=$(echo $computerModel | tr '[:upper:]' '[:lower:]')

# Match the model to a SF icon
case $caseModel in
	*"book"*)
		computerModelIcon="SF=macbook"
	;;
	*"imac"*)
		computerModelIcon="SF=desktopcomputer"
	;;
	*"mini"*)
		computerModelIcon="SF=macmini"
	;;
	*"studio"*)
		computerModelIcon="SF=macstudio"
	;;
	*"macpro"*)
		computerModelIcon="SF=macpro.gen3"
	;;
esac

# Determine icon for OS Version
if [[ "$computerOSVersion" =~ ^10.10.* ]]; then
	computerOSIcon="https://upload.wikimedia.org/wikipedia/en/a/ae/Osx-yosemite-logo.png"
elif [[  "$computerOSVersion" =~ ^10.11.* ]]; then
	computerOSIcon="https://upload.wikimedia.org/wikipedia/commons/thumb/b/bb/OS_X_El_Capitan_logo.svg/1024px-OS_X_El_Capitan_logo.svg.png"
elif [[  "$computerOSVersion" =~ ^10.12.* ]]; then
	computerOSIcon="https://is1-ssl.mzstatic.com/image/thumb/Purple128/v4/83/99/67/839967c5-d5f8-9c65-44bd-ca7cc3f90a97/ProductPageIcon.png/1200x630bb.png"
elif [[  "$computerOSVersion" =~ ^10.13.* ]]; then
	computerOSIcon="https://static.wikia.nocookie.net/ipod/images/e/ec/MacOSHighSierraCircle.png/revision/latest?cb=20170927214102"
elif [[  "$computerOSVersion" =~ ^10.14.* ]]; then
	computerOSIcon="https://upload.wikimedia.org/wikipedia/it/thumb/5/5b/MacOS_Mojave_logo.png/600px-MacOS_Mojave_logo.png"
elif [[  "$computerOSVersion" =~ ^10.15.* ]]; then
	computerOSIcon="https://support.apple.com/library/APPLE/APPLECARE_ALLGEOS/SP803/macos-catalina-roundel-240.png"
elif [[  "$computerOSVersion" =~ ^11.* ]]; then
	computerOSIcon="https://upload.wikimedia.org/wikipedia/it/0/0f/MacOS_Big_Sur_logo.png"
elif [[  "$computerOSVersion" =~ ^12.* ]]; then
	computerOSIcon="https://upload.wikimedia.org/wikipedia/commons/c/c8/MacOS_Monterey_logo.png"
elif [[  "$computerOSVersion" =~ ^13.* ]]; then
	computerOSIcon="https://upload.wikimedia.org/wikipedia/commons/c/c8/MacOS_Monterey_logo.png"
elif [[  "$computerOSVersion" =~ ^14.* ]]; then
	computerOSIcon="https://cdn.jim-nielsen.com/macos/512/macos-sonoma-2023-09-26.png"
else
	computerOSIcon="SF=apple.logo"
fi

LAPSPromptJSON='
{
    "commandfile" : "'"${LAPSPromptCommandFile}"'",
    "bannertitle" : "'"${appTitle}"'",
    "bannerimage" : "'"${bannerImage}"'",
    "icon" : "'"${startIcon}"'",
    "overlayicon" : "'"${overlayicon}"'",
    "iconsize" : "120",
    "button1text" : "Continue",
    "button2text" : "Quit",
    "selectitems": [
        {
            "title" : "LAPS User",
            "required" : true,
            "values" : [
                '${lapsUsersString}'
            ]
        },
    ],
    "ontop" : "true",
    "position" : "center",
    "moveable" : true,
    "height" : "560",
    "width" : "750",
    "messagefont" : "size=14",
    "helpmessage" : "'"${helpMessage}"'",
    "infotext" : "'"V. ${scriptVersion}"'",
    "message" : "  \n Review the following information before selecting a LAPS account from the drop down below. \n\n For more details, view the computer record in Jamf Pro: '"${jamfProComputerURL}"'",
    "titlefont" : "shadow=true, size=45, colour=#FFFDF4",
    "liststyle" : "compact",
    "listitem" : [
        {"title" : "Computer Name", "icon" : "SF=pencil", "statustext" : "'"${computerName}"'"},
        {"title" : "Computer Serial", "icon" : "SF=ellipsis.rectangle, size=14", "statustext" : "'"${computerSerialNumber}"'"},
        {"title" : "Computer Model", "icon" : "'"${computerModelIcon}"'", "statustext" : "'"${computerModel}"'"},
        {"title" : "OS Version", "icon" : "'"${computerOSIcon}"'", "statustext" : "'"${computerOSVersion}"'"},
        {"title" : "Computer IP Address", "icon" : "SF=network.badge.shield.half.filled", "statustext" : "'"${computerIpAddress}"'"},
        {"title" : "Computer Local IP Address", "icon" : "SF=network", "statustext" : "'"${computerIpAddressLastReported}"'"}
    ]
}
'

echo "$LAPSPromptJSON" > "$LAPSPromptJSONFile"

# Display LAPS Prompt dialog
updateScriptLog "Displaying LAPS prompt to user"
LAPSPromptResults=$( eval "${dialogBinary} --jsonfile ${LAPSPromptJSONFile} --json" )

if [[ -z "${LAPSPromptResults}" ]]; then
    LAPSPromptReturnCode="2"
else
    LAPSPromptReturnCode="0"
fi

case "${LAPSPromptReturnCode}" in

    0) # Process exit code 0 scenario here
    # set the variable for the selected item
        selectedUser=$(get_json_value_startPromptDialog "$LAPSPromptResults" "LAPS User" "selectedValue")
        updateScriptLog "LAPS User ${selectedUser} selected."
        ;;
    2) # Process exit code 2 scenario here
        quitScript "1"
        ;;
    *) # Process catch-all scenario here
        quitScript "2"
        ;;
esac

# Use the API to get the password for the selected user

passwordInfomation=$( curl -X 'GET' \
  "${URL1}"/api/v2/local-admin-password/"${management_id}"/account/"${selectedUser}"/password \
  -H 'accept: application/json' \
  -H "Authorization: Bearer ${token}"
)

password=$(get_json_value "$passwordInfomation" 'password' )

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Results Dialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

resultsJSONFile=$( mktemp -u /var/tmp/resultsJSONFile.XXX )
resultsCommandFile=$( mktemp -u /var/tmp/dialogCommandFileResults.XXX )

resultsPromptJSON='
{
    "commandfile" : "'"${resultsCommandFile}"'",
    "bannertitle" : "'"${appTitle}"'",
    "bannerimage" : "'"${bannerImage}"'",
    "icon" : "'"${startIcon}"'",
    "overlayicon" : "'"${overlayicon}"'",
    "iconsize" : "120",
    "button1text" : "Quit",
    "ontop" : "true",
    "position" : "center",
    "moveable" : true,
    "height" : "465",
    "width" : "640",
    "helpmessage" : "'"${helpMessage}"'",
    "infotext" : "'"V. ${scriptVersion}"'",
    "titlefont" : "shadow=true, size=45, colour=#FFFDF4",
    "message" : "  \n Review the following information for the LAPS account below. \n\n For more details, view the computer record in Jamf Pro: \n '"${jamfProComputerURL}"'",
    "messagefont" : "size=14",
    "liststyle" : "compact",
    "listitem" : [
        {"title" : "Computer Name", "icon" : "SF=pencil", "statustext" : "'"${computerName}"'"},
        {"title" : "Computer Serial", "icon" : "SF=ellipsis.rectangle, size=14", "statustext" : "'"${computerSerialNumber}"'"},
        {"title" : "LAPS User", "icon" : "SF=person.circle", "statustext" : "'"${selectedUser}"'"},
        {"title" : "Password", "icon" : "SF=lock.open.fill", "statustext" : "'"${password}"'"},
    ],
    "checkbox" : [
	  {"label" : "Copy Password to Clipboard", "checked" : true, "disabled" : false, "icon" : "SF=doc.on.doc.fill" }
	],
}
'

echo "$resultsPromptJSON" > "$resultsJSONFile"

# Display LAPS Prompt dialog

updateScriptLog "Displaying results to user"
resultsPromptResults=$( eval "${dialogBinary} --jsonfile ${resultsJSONFile} --json" )

checkbox=$(get_json_value_startPromptDialog "$resultsPromptResults" "Copy Password to Clipboard")


if [[ -z "${resultsPromptResults}" ]]; then
    resultsPromptReturnCode="2"
else
    resultsPromptReturnCode="0"
fi

case "${resultsPromptReturnCode}" in

    0) # Process exit code 0 scenario here
if [[ $checkbox == *true* ]]; then 
      echo -n "$password" | pbcopy
      updateScriptLog "LAPS copied to Clipboard"
else
    updateScriptLog "No password copied to Clipboard, Sending Webhook"
fi
        ;;
    2) # Process exit code 2 scenario here
        quitScript "1"
        ;;
    *) # Process catch-all scenario here
        quitScript "2"
        ;;
esac

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Get URL for notification button
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

jamfProComputerURL="${URL1}/computers.html?id=${computer_id}&o=r"

updateScriptLog "Jamf Computer URL: $jamfProComputerURL"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Slack notification
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

	if [[ $SLACKURL == "" ]]; then
		updateScriptLog "No slack URL configured"
	else
		if [[ $SERVICEDESK == "" ]]; then
			SERVICEDESK="https://www.slack.com"
		fi
		updateScriptLog "Sending Slack WebHook"
		curl -s -X POST -H 'Content-type: application/json' \
		-d \
		'{
	"blocks": [
		{
			"type": "header",
			"text": {
				"type": "plain_text",
				"text": "Jamf LAPS Password Requested:closed_lock_with_key:",
			}
		},
		{
			"type": "divider"
		},
		{
			"type": "section",
			"fields": [
				{
					"type": "mrkdwn",
					"text": ">*Serial Number and Computer Name:*\n>'"$serialNumber"' on '"$computerNameOfAdmin"'"
				},
                {
					"type": "mrkdwn",
					"text": ">*Computer Model:*\n>'"$computerModel"'"
				},
				{
					"type": "mrkdwn",
					"text": ">*Requested by:*\n>'"$USER"' on '"$computerNameOfAdmin"'"
				},
				{
					"type": "mrkdwn",
					"text": ">*Reason for Request:*\n>'"$reason"'"
				},
                {
					"type": "mrkdwn",
					"text": ">*Computer Record:*\n>'"$jamfProComputerURL"'"
				},
			]
		},
		{
		"type": "actions",
			"elements": [
				{
					"type": "button",
					"text": {
						"type": "plain_text",
						"text": "Challenge Request",
						"emoji": true
					},
					"style": "danger",
					"action_id": "actionId-0",
					"url": "'"$SERVICEDESK"'"
				}
			]
		}
	]
}' \
$6
fi
	
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Teams notification (Credit to https://github.com/nirvanaboi10 for the Teams code)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

	if [[ $TEAMSURL == "" ]]; then
		updateScriptLog "No teams Webhook configured"
	else
		if [[ $SERVICEDESK == "" ]]; then
			SERVICEDESK="https://www.microsoft.com/en-us/microsoft-teams/"
		fi
		updateScriptLog "Sending Teams WebHook"
		jsonPayload='{
	"@type": "MessageCard",
	"@context": "http://schema.org/extensions",
	"themeColor": "0076D7",
	"summary": "Admin has been used",
	"sections": [{
		"activityTitle": "Jamf LAPS Password Requested",
		"activityImage": "https://raw.githubusercontent.com/PezzaD84/macOSLAPS/main/Icons/Open%20Lock%20Icon.png",
		"facts": [{
			"name": "Serial Number and Computer Name:",
			"value": "'"$serialNumber"' on '"$computerName"'"
		}, {
			"name": "Computer Model:",
			"value": "'"$computerModel"'"
		}, {
			"name": "Requested by (Jamf Username):",
			"value": "'"$USER"' on '"$computerNameOfAdmin"'"
		}, {
			"name": "Reason for Request:",
			"value": "'"$reason"'"
        }, {
			"name": "Computer Record:",
			"value": "'"$jamfProComputerURL"'"
		}],
		"markdown": true
	}],
	"potentialAction": [{
		"@type": "OpenUri",
		"name": "View in Jamf Pro",
		"targets": [{
			"os": "default",
			"uri":
			"'"$jamfProComputerURL"'"
		}]
	}]
}'
		
# Send the JSON payload using curl
curl -s -X POST -H "Content-Type: application/json" -d "$jsonPayload" "$TEAMSURL"
fi

updateScriptLog "Token expired, Exiting Script"

quitScript
