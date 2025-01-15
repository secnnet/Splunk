#!/usr/bin/env python

import subprocess
import os

# Define variables
SPLUNK_PACKAGE_URL = "https://download.splunk.com/products/universalforwarder/releases/8.2.1/linux/splunkforwarder-8.2.1-ae6821b7c64b-Linux-x86_64.tgz"
INSTALL_LOCATION = "/opt/splunkforwarder"

# Download Splunk package
subprocess.call(["wget", SPLUNK_PACKAGE_URL])

# Extract package
subprocess.call(["tar", "-xvf", "splunkforwarder-8.2.1-ae6821b7c64b-Linux-x86_64.tgz"])

# Move extracted folder to install location
subprocess.call(["mv", "splunkforwarder", INSTALL_LOCATION])

# Set Splunk user ownership
subprocess.call(["chown", "-R", "splunk:splunk", INSTALL_LOCATION])

# Start Splunk Universal Forwarder
os.system("{}/bin/splunk start --accept-license --answer-yes".format(INSTALL_LOCATION))
