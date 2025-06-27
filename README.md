# plex-qbit-unraid

This Python script, `plex-qbit-unraid.py`, is designed to enhance the media streaming experience on an Unraid server running Plex and qBittorrent. It automatically manages resource-intensive background tasks (qBittorrent downloads, Unraid parity checks, and the Unraid mover) by pausing them when Plex streams are active and resuming them when the server is idle.

## Table of Contents

- [Features](https://gemini.google.com/app/#features "null")
- [Prerequisites](https://gemini.google.com/app/#prerequisites "null")
- [Installation and Setup](https://gemini.google.com/app/#installation-and-setup "null")
	- [1\. Environment Variables](https://gemini.google.com/app/#1-environment-variables "null")
	- [2\. Dependencies](https://gemini.google.com/app/#2-dependencies "null")
	- [3\. SSH Access to Unraid](https://gemini.google.com/app/#3-ssh-access-to-unraid "null")
	- [4\. Plex Token](https://gemini.google.com/app/#4-plex-token "null")
	- [5\. qBittorrent Web UI Access](https://gemini.google.com/app/#5-qbittorrent-web-ui-access "null")
- [Usage](https://gemini.google.com/app/#usage "null")
	- [Running Manually](https://gemini.google.com/app/#running-manually "null")
	- [Scheduling with Cron](https://gemini.google.com/app/#scheduling-with-cron "null")
- [Configuration](https://gemini.google.com/app/#configuration "null")
- [Logging](https://gemini.google.com/app/#logging "null")
- [Files Created by the Script](https://gemini.google.com/app/#files-created-by-the-script "null")
- [Troubleshooting](https://gemini.google.com/app/#troubleshooting "null")

## Features

- **Intelligent Stream Detection:** Monitors active Plex streams, differentiating between local and remote connections.
- **Dynamic qBittorrent Throttling:** Automatically limits qBittorrent download speeds when active Plex streams are detected to prioritize streaming bandwidth. Speed limits are restored when the server is idle.
- **Unraid Parity Management:** Pauses the Unraid array's parity check during active Plex streaming and resumes it once streaming ceases.
- **Unraid Mover Control:** Halts the Unraid mover process during active streaming to prevent disk contention and resumes it only if it was previously interrupted by the script.
- **Concurrency Protection:** Implements a file-based lock to prevent multiple instances of the script from running simultaneously, ensuring stable operation.
- **Detailed Logging:** Provides comprehensive logging of all actions and status updates for monitoring and debugging.

## Prerequisites

Before running this script, ensure you have the following:

- **Python 3.x:** Installed on the system where the script will run (e.g., Unraid itself, a Docker container, or an LXC container).
- **Unraid Server:** With SSH enabled and accessible.
- **Plex Media Server:** Running and accessible.
- **qBittorrent:** With its Web UI enabled and accessible.

## Installation and Setup

### 1\. Environment Variables

Create a `.env` file in the same directory as the script. This file will store your sensitive credentials and configuration settings.

```
# Unraid Server Details
UNRAID_IP=<Your_Unraid_IP_Address>
UNRAID_USERNAME=<Your_Unraid_SSH_Username>
UNRAID_PASSWORD=<Your_Unraid_SSH_Password>

# Plex Media Server Details
PLEX_IP=<Your_Plex_IP_Address>
PLEX_PORT=<Your_Plex_Port_Default_32400>
PLEX_TOKEN=<Your_Plex_X-Plex-Token>

# qBittorrent Web UI Details
QBIT_IP=<Your_qBittorrent_IP_Address>
QBIT_PORT=<Your_qBittorrent_WebUI_Port>
QBIT_USERNAME=<Your_qBittorrent_WebUI_Username>
QBIT_PASSWORD=<Your_qBittorrent_WebUI_Password>

# Optional: Ignore local streams when deciding to throttle/pause operations
# Set to 'True' to ignore local streams (only remote streams will trigger actions)
# Set to 'False' (default) to include both local and remote streams
IGNORE_LOCAL_STREAMS=False
```

**How to get your Plex Token:**

1. Open your Plex Web UI in your browser.
2. Go to any page (e.g., dashboard).
3. View the page source (e.g., `Ctrl+U` or right-click -> `View page source`).
4. Search for `X-Plex-Token`. The value associated with it is your token.

### 2\. Dependencies

Install the required Python libraries using pip:

```
pip install paramiko requests python-dotenv qbittorrentapi
```

### 3\. SSH Access to Unraid

Ensure SSH access is enabled on your Unraid server (`Settings` -> `SSH`). The script connects using the provided username and password. For enhanced security, consider configuring SSH key-based authentication for the user and modifying the `paramiko` connection accordingly.

### 4\. Plex Token

The script requires a Plex `X-Plex-Token` to query active sessions. Ensure the token is correct and has the necessary permissions to access session information.

### 5\. qBittorrent Web UI Access

Verify that the qBittorrent Web UI is enabled and accessible from where you run the script, using the provided IP, port, username, and password.

## Usage

### Running Manually

For testing or manual execution, simply run the script from your terminal:

```
python plex-qbit-unraid.py
```

### Scheduling with Cron

For continuous monitoring, it is recommended to schedule the script to run periodically using `cron` (e.g., every minute or every few minutes).

1. **Open Crontab:**
	```
	crontab -e
	```
2. **Add the following line:** Replace `/path/to/your/script/` with the actual path to your script.
	```
	* * * * * /usr/bin/python3 /path/to/your/script/plex-qbit-unraid.py >> /path/to/your/script/cron.log 2>&1
	```
	- `* * * * *`: Runs every minute. Adjust as needed.
	- `/usr/bin/python3`: Ensure this is the correct path to your Python 3 executable. Use `which python3` to find it.
	- `>> /path/to/your/script/cron.log 2>&1`: Redirects all output (stdout and stderr) to a log file for cron-specific debugging.
	**Note:** Ensure the user under which the cron job runs has the necessary permissions to execute the script, read the `.env` file, and create/write to the log and status files.

## Configuration

The script's behavior can be fine-tuned via the `.env` file:

- `UNRAID_IP`, `PLEX_IP`, `PLEX_PORT`, `QBIT_IP`, `QBIT_PORT`: Network addresses and ports for the respective services.
- `PLEX_TOKEN`, `QBIT_USERNAME`, `QBIT_PASSWORD`, `UNRAID_USERNAME`, `UNRAID_PASSWORD`: Authentication credentials.
- `IGNORE_LOCAL_STREAMS`:
	- `True`: Only remote Plex streams will trigger performance optimizations (qBittorrent throttling, pausing parity/mover).
	- `False` (default): Both local and remote Plex streams will trigger optimizations.

## Logging

The script logs its operations to `playback_actions.log` in the same directory. This log file automatically rotates to prevent it from growing too large.

The log level is set to `INFO`, providing general status updates. For more detailed debugging, you can temporarily change `level=logging.INFO` to `level=logging.DEBUG` in the script's logging configuration section.

## Files Created by the Script

The script creates the following files in its working directory to manage state and concurrency:

- `playback_actions.log`: Stores detailed operational logs.
- `script.lock`: A lock file to prevent multiple script instances from running concurrently. Automatically created at script start and removed at script end.
- `mover.status`: Stores `1` if the Unraid mover was interrupted by the script, `0` otherwise.
- `stream_count.status`: Stores the last detected total active Plex stream count.

## Troubleshooting

- **Missing Environment Variables:** If the script exits with "Missing environment variables," double-check your `.env` file for all required entries.
- **SSH Connection Failed:**
	- Verify `UNRAID_IP`, `UNRAID_USERNAME`, and `UNRAID_PASSWORD` in your `.env` file.
	- Ensure SSH is enabled on your Unraid server.
	- Check network connectivity between the script's host and your Unraid server.
- **Plex/qBittorrent Connection Failed:**
	- Verify `PLEX_IP`, `PLEX_PORT`, `PLEX_TOKEN`, `QBIT_IP`, `QBIT_PORT`, `QBIT_USERNAME`, `QBIT_PASSWORD` in your `.env` file.
	- Ensure Plex and qBittorrent Web UI are running and accessible from the script's host.
- **Lock File Exists:** If the script reports "Lock file exists. Exiting...", it means a previous instance did not terminate gracefully. Manually delete `script.lock` if you are certain no other instance is running.
- **Permissions Issues:** Ensure the user running the script (especially for cron jobs) has read/write permissions for the script's directory and the files it creates (`.env`, `.log`, `.lock`, `.status`).
- **Check Logs:** Always consult `playback_actions.log` for detailed error messages and clues. For cron issues, check the `cron.log` you configured.
