# plex-qbit-unraid

This Python script, `plex-qbit-unraid.py`, is designed to enhance the media streaming experience on an Unraid server running Plex and qBittorrent. It automatically manages resource-intensive background tasks (qBittorrent downloads, Unraid parity checks, and the Unraid mover) by pausing them when Plex streams are active and resuming them when the server is idle.

## Table of Contents
* [Features](#features)
* [Prerequisites](#prerequisites)
* [Installation and Setup](#installation-and-setup)
  * [1. Environment Variables](#1-environment-variables)
  * [2. Dependencies](#2-dependencies)
  * [3. SSH Access to Unraid](#3-ssh-access-to-unraid)
  * [4. Plex Token](#4-plex-token)
  * [5. qBittorrent Web UI Access](#5-qbittorrent-web-ui-access)
* [Usage](#usage)
  * [Running Manually](#running-manually)
  * [Scheduling with Cron](#scheduling-with-cron)
  * [Scheduling with Tautulli Notification Agent](#scheduling-with-tautulli-notification-agent)
* [Configuration](#configuration)
* [Logging](#logging)
* [Files Created by the Script](#files-created-by-the-script)
* [Troubleshooting](#troubleshooting)

## Features
* **Intelligent Stream Detection:** Monitors active Plex streams, differentiating between local and remote connections.

* **Dynamic qBittorrent Throttling:** Automatically limits qBittorrent download speeds when active Plex streams are detected to prioritize streaming bandwidth. Speed limits are restored when the server is idle.

* **Unraid Parity Management:** Pauses the Unraid array's parity check during active Plex streaming and resumes it once streaming ceases.

* **Unraid Mover Control:** Halts the Unraid mover process during active streaming to prevent disk contention and resumes it only if it was previously interrupted by the script.

* **Concurrency Protection:** Implements a file-based lock to prevent multiple instances of the script from running simultaneously, ensuring stable operation.

* **Detailed Logging:** Provides comprehensive logging of all actions and status updates for monitoring and debugging.

## Prerequisites

Before running this script, ensure you have the following:

* **Python 3.x:** Installed on the system where the script will run (e.g., Unraid itself, a Docker container, or an LXC container).

* **Unraid Server:** With SSH enabled and accessible.

* **Plex Media Server:** Running and accessible.

* **qBittorrent:** With its Web UI enabled and accessible.

* **Dedicated Script User:** A dedicated system user for running the script (e.g., `tautulli`), configured with a proper home directory and permissions, especially if using SSH key-based authentication.

## Installation and Setup

### 1. Environment Variables

Create a `.env` file in the same directory as the script. This file will store your sensitive credentials and configuration settings.

```ini
# Unraid Server Details
UNRAID_IP=<Your_Unraid_IP_Address>
UNRAID_USERNAME=<Your_Unraid_SSH_Username>
# Choose ONE of the following for SSH authentication:
# UNRAID_PASSWORD=<Your_Unraid_SSH_Password> # Uncomment and set if using password auth
UNRAID_PRIVATE_KEY_PATH=~/.ssh/unraid_plex_qbit_key # Uncomment and set for key-based auth (recommended)

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
````

**Note on `UNRAID_PASSWORD` vs `UNRAID_PRIVATE_KEY_PATH`:** If `UNRAID_PRIVATE_KEY_PATH` is defined, the script will attempt key-based authentication first. `UNRAID_PASSWORD` will only be used as a fallback if key authentication fails or if `UNRAID_PRIVATE_KEY_PATH` is not set.

**How to get your Plex Token:**

1.  Open your Plex Web UI in your browser.

2.  Go to any page (e.g., dashboard).

3.  View the page source (e.g., `Ctrl+U` or right-click -\> `View page source`).

4.  Search for `X-Plex-Token`. The value associated with it is your token.

### 2\. Dependencies

Install the required Python libraries using pip:

```bash
pip install paramiko requests python-dotenv qbittorrentapi
```

### 3\. SSH Access to Unraid

Ensure SSH access is enabled on your Unraid server (`Settings` -\> `SSH`). The script connects using the provided username and either a password or, preferably, an SSH private key.

**Key-based Authentication (Recommended for Automation):**
For enhanced security and headless automation, use SSH key-based authentication. This involves generating an SSH key pair on the machine running the script and adding the public key to your Unraid user's `authorized_keys`.

1.  **Generate SSH Key Pair:**
    On the system where you're running the script (e.g., your Tautulli LXC/VM, or the Unraid server itself if running locally), generate an Ed25519 key pair:

    ```bash
    ssh-keygen -t ed25519 -f unraid_plex_qbit_key
    ```

      * **Crucial:** When prompted for a passphrase, **press Enter twice** to leave it empty. A passphrase would require manual input, which is not suitable for automated scripts.
      * This will create two files: `unraid_plex_qbit_key` (your private key) and `unraid_plex_qbit_key.pub` (your public key).

2.  **Copy Public Key to Unraid Server:**
    Add the public key to your Unraid user's `authorized_keys` file. Replace `<UNRAID_USERNAME>` and `<UNRAID_IP>` with your Unraid SSH username and IP.

    ```bash
    ssh-copy-id -i unraid_plex_qbit_key.pub <UNRAID_USERNAME>@<UNRAID_IP>
    ```

    You will be prompted for your Unraid user's password. This command securely places the public key on your Unraid server.

3.  **Ensure Script User Has a Home Directory:**
    The script relies on `~/.ssh/` to resolve the private key path when `UNRAID_PRIVATE_KEY_PATH=~/.ssh/your_key`. If the user running the script (e.g., `tautulli`) was initially created without a home directory (e.g., using `useradd --system --no-create-home`), you must ensure it has one.

      * If `/home/tautulli` does not exist:
        ```bash
        sudo mkdir -p /home/tautulli
        sudo chown tautulli:tautulli /home/tautulli
        sudo chmod 700 /home/tautulli
        ```
      * **Update `/etc/passwd`:** Ensure the `tautulli` user's entry in `/etc/passwd` points to its new home directory (e.g., `/home/tautulli`).
        *(Example line, replace with your user's actual ID/GID/Shell if different):*
        `tautulli:x:999:997::/home/tautulli:/bin/bash`
        If you change this, you may need to **restart the Tautulli service** (`systemctl restart tautulli.service`) for the changes to take effect in its execution environment.

4.  **Move Private Key to Script User's Home Directory and Set Permissions:**
    Move the `unraid_plex_qbit_key` (the private key file generated in step 1) to the `.ssh` directory within the script user's home folder.

      * Assuming the user running the script is `tautulli`, and its home directory is `/home/tautulli`:
        ```bash
        # Create .ssh directory if it doesn't exist
        sudo mkdir -p /home/tautulli/.ssh
        # Set ownership for the .ssh directory
        sudo chown tautulli:tautulli /home/tautulli/.ssh
        # Set permissions for the .ssh directory (owner full access, others no access - CRITICAL)
        sudo chmod 700 /home/tautulli/.ssh

        # Move the private key from where you generated it (e.g., /root/.ssh/)
        # Adjust source path as necessary!
        sudo mv /root/.ssh/unraid_plex_qbit_key /home/tautulli/.ssh/unraid_plex_qbit_key
        # Set ownership for the private key file
        sudo chown tautulli:tautulli /home/tautulli/.ssh/unraid_plex_qbit_key
        # Set permissions for the private key (owner read/write only - CRITICALLY IMPORTANT FOR SSH)
        sudo chmod 600 /home/tautulli/.ssh/unraid_plex_qbit_key
        ```

### 4\. Plex Token

The script requires a Plex `X-Plex-Token` to query active sessions. Ensure the token is correct and has the necessary permissions to access session information.

### 5\. qBittorrent Web UI Access

Verify that the qBittorrent Web UI is enabled and accessible from where you run the script, using the provided IP, port, username, and password.

## Usage

### Running Manually

For testing or manual execution, simply run the script from your terminal:

```bash
python plex-qbit-unraid.py
```

### Scheduling with Cron

For continuous monitoring, it is recommended to schedule the script to run periodically using `cron` (e.g., every minute or every few minutes) under the dedicated script user (e.g., `tautulli`).

1.  **Open Crontab for the dedicated user:**
    If logged in as `root`:

    ```bash
    crontab -u tautulli -e
    ```

    If logged in as the `tautulli` user directly:

    ```bash
    crontab -e
    ```

2.  **Add the following line:** Replace `/opt/Tautulli/scripts/plex-qbit-unraid` with the actual path to your script's directory.

    ```bash
    */5 * * * * cd /opt/Tautulli/scripts/plex-qbit-unraid && /usr/bin/python3 plex-qbit-unraid.py >> playback_actions.log 2>&1
    ```

      * `*/5 * * * *`: Runs every 5 minutes. Adjust as needed.
      * `cd /opt/Tautulli/scripts/plex-qbit-unraid`: **Crucial** for the script to find its `.env`, `.log`, and `.status` files. Adjust to your script's directory.
      * `/usr/bin/python3`: Ensure this is the correct path to your Python 3 executable. Use `which python3` to find it.
      * `>> playback_actions.log 2>&1`: Redirects all output (stdout and stderr) to the script's main log file for cron-specific debugging.

### Scheduling with Tautulli Notification Agent

This is a convenient way to run the script automatically based on Plex events:

1.  **Navigate in Tautulli:** Go to `Settings` -\> `Notification Agents`.

2.  **Add Agent:** Click `Add a Notification Agent` and choose `Script`.

3.  **Configuration:**

      * **Description:** Give it a descriptive name (e.g., `Plex Stream Optimizer`).

      * **Script File:** Provide the full path to your `plex-qbit-unraid.py` script (e.g., `/opt/Tautulli/scripts/plex-qbit-unraid/plex-qbit-unraid.py`).

      * **Working Directory:** Set this to the directory containing your script and `.env` file (e.g., `/opt/Tautulli/scripts/plex-qbit-unraid/`). This is **critical** for `load_dotenv()` to find your `.env` file and for `playback_actions.log`, `script.lock`, etc., to be created in the correct place.

      * **Triggers:** Select the Plex events that should trigger the script. Recommended triggers include `Playback Start` and `Playback Stop`. You might also consider `Playback Pause` and `Playback Resume` if you want immediate adjustments.

      * **Conditions:** (Optional) Set any conditions if you only want the script to run under specific circumstances.

4.  **Test:** Use the "Test Notification" button for a selected event or trigger a Plex stream to verify the script runs correctly and logs its actions.

## Configuration

The script's behavior can be fine-tuned via the `.env` file:

  * `UNRAID_IP`, `PLEX_IP`, `PLEX_PORT`, `QBIT_IP`, `QBIT_PORT`: Network addresses and ports for the respective services.

  * `PLEX_TOKEN`, `QBIT_USERNAME`, `QBIT_PASSWORD`, `UNRAID_USERNAME`: Authentication credentials.

  * `UNRAID_PRIVATE_KEY_PATH`: Path to the SSH private key file for key-based authentication. If provided, the script will attempt to use this key. It expects a path that `os.path.expanduser()` can resolve (e.g., `~/.ssh/your_key_name`). If key authentication fails or this variable is not set, `UNRAID_PASSWORD` will be used as a fallback.

  * `IGNORE_LOCAL_STREAMS`:

      * `True`: Only remote Plex streams will trigger performance optimizations (qBittorrent throttling, pausing parity/mover).

      * `False` (default): Both local and remote Plex streams will trigger optimizations.

## Logging

The script logs its operations to `playback_actions.log` in the same directory. This log file automatically rotates to prevent it from growing too large.

The log level is set to `INFO`, providing general status updates. For more detailed debugging, you can temporarily change `level=logging.INFO` to `level=logging.DEBUG` in the script's logging configuration section, or run the script with the `--log-level DEBUG` argument.

## Files Created by the Script

The script creates the following files in its working directory to manage state and concurrency:

  * `playback_actions.log`: Stores detailed operational logs.

  * `script.lock`: A lock file to prevent multiple script instances from running concurrently. Automatically created at script start and removed at script end.

  * `mover.status`: Stores `1` if the Unraid mover was interrupted by the script, `0` otherwise.

  * `stream_count.status`: Stores the last detected total active Plex stream count. This file is removed if no active streams are detected during a script run.

## Troubleshooting

  * **Missing Environment Variables:** If the script exits with "Missing environment variables," double-check your `.env` file for all required entries.

  * **SSH Connection Failed:**

      * **Password Authentication:** Verify `UNRAID_IP`, `UNRAID_USERNAME`, and `UNRAID_PASSWORD` in your `.env` file.

      * **Key-based Authentication:**

          * Verify `UNRAID_PRIVATE_KEY_PATH` in your `.env` points to the correct private key file (e.g., `~/.ssh/unraid_plex_qbit_key`).

          * Ensure the private key file (e.g., `/home/tautulli/.ssh/unraid_plex_qbit_key`) has permissions `600` and its containing directory (e.g., `/home/tautulli/.ssh`) has `700`. Both should be owned by the user running the script (e.g., `tautulli:tautulli`).

          * Confirm the user running the script (e.g., `tautulli`) has a properly defined home directory in `/etc/passwd` (e.g., `/home/tautulli`). After modifying `/etc/passwd`, you may need to **restart the Tautulli service** (`systemctl restart tautulli.service`) for the changes to take effect in its environment.

      * **General SSH:** Ensure SSH is enabled on your Unraid server and check network connectivity between the script's host and your Unraid server.

  * **Plex/qBittorrent Connection Failed:**

      * Verify `PLEX_IP`, `PLEX_PORT`, `PLEX_TOKEN`, `QBIT_IP`, `QBIT_PORT`, `QBIT_USERNAME`, `QBIT_PASSWORD` in your `.env` file.

      * Ensure Plex and qBittorrent Web UI are running and accessible from the script's host.

  * **Lock File Exists:** If the script reports "Lock file exists. Exiting...", it means a previous instance did not terminate gracefully. Manually delete `script.lock` if you are certain no other instance is running.

  * **Permissions Issues:** Ensure the user running the script (especially for cron jobs or Tautulli notification agents) has read/write permissions for the script's directory and the files it creates (`.env`, `.log`, `.lock`, `.status`).

  * **Check Logs:** Always consult `playback_actions.log` for detailed error messages and clues. For cron issues, ensure your cron job redirects output to a log file.
