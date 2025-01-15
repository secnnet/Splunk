# Splunk Universal Forwarder Installation for Windows

	1. Modifying inputs.conf.
	Get-Content $InputFileSource | Out-File $InputFile

	2. Copying outputs.conf.
	Copy-Item $OutputFileSource $OutputFile -Force

	3. Starting Splunk forwarder service.
	Start-Service splunkforwarder -Verbose -ErrorAction SilentlyContinue

	4. Installation of Splunk forwarder is complete.

Summary:
This script installs the Splunk forwarder service on client machines. It checks if the Splunk forwarder is already installed and exits if found, unless -Force parameter is specified. The script proceeds to install the forwarder using the designated MSI file, set the server, default hostname, and modify inputs.conf and outputs.conf files. It concludes by starting the forwarder service and confirming the installation.