#!/bin/bash

old="https://join.slack.com/t/steampipe/shared_invite/zt-oij778tv-lYyRTWOTMQYBVAbtPSWs3g"
new="https://steampipe.io/community/join"

# var1=""


file_name="/Users/ved/turbot/steampipe-plugin-virustotal/README.md"

# sed -i "s~${var1}~${var2}" ${file_name}
# find ./ -type f -exec sed -i '' -e "s~${var1}~${var2}" {} \;

# sed -i "s|${old}|${new}|g" ${file_name}
data=$(sed "s|${old}|${new}|g" /Users/ved/turbot/steampipe-plugin-virustotal/README.md)
echo -e "$data" > /Users/ved/turbot/steampipe-plugin-virustotal/README.md

data=$(sed "s|${old}|${new}|g" /Users/ved/turbot/steampipe-plugin-virustotal/docs/index.md)
echo -e "$data" > /Users/ved/turbot/steampipe-plugin-virustotal/docs/index.md