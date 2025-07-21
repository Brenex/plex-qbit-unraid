"""
Plex, qBittorrent, and Unraid Server Automation Script

This script monitors active Plex streams and adjusts Unraid server operations
(qBittorrent speed, parity check status, mover status) to optimize performance.
It aims to reduce resource contention during media streaming and restore full
server performance when no streams are active.

Usage:
1.  **Dependencies:** Ensure `paramiko`, `requests`, `python-qbittorrent`, and `python-dotenv` are installed (`pip install ...`).
2.  **Configuration:** Create a `.env` file in the script's directory with the required environment variables (UNRAID_IP, PLEX_IP, PLEX_TOKEN, QBIT_IP, QBIT_USERNAME, QBIT_PASSWORD, UNRAID_USERNAME, PLEX_PORT, QBIT_PORT, IGNORE_LOCAL_STREAMS).
    * For SSH to Unraid, provide either `UNRAID_PRIVATE_KEY_PATH` OR `UNRAID_PASSWORD`. `UNRAID_PRIVATE_KEY_PATH` is preferred.
3.  **Execution:** Run the script periodically (e.g., via a cron job or Tautulli custom script).

Environment Variables:
-   `UNRAID_IP`: Hostname or IP of Unraid.
-   `UNRAID_USERNAME`: SSH username for Unraid.
-   `UNRAID_PRIVATE_KEY_PATH`: (Optional) Full path to the SSH private key for Unraid. Used preferentially over password.
-   `UNRAID_PASSWORD`: (Optional, fallback if UNRAID_PRIVATE_KEY_PATH not used) SSH password for Unraid.
-   `PLEX_IP`: Hostname or IP of Plex Media Server.
-   `PLEX_PORT`: Plex port (default: 32400).
-   `PLEX_TOKEN`: Plex API token.
-   `QBIT_IP`: Hostname or IP of qBittorrent Web UI.
-   `QBIT_PORT`: qBittorrent Web UI port (default: 8080).
-   `QBIT_USERNAME`: qBittorrent Web UI username.
-   `QBIT_PASSWORD`: qBittorrent Web UI password.
-   `IGNORE_LOCAL_STREAMS`: 'True' to ignore local Plex streams for optimization, 'False' otherwise (default: 'False').
"""

# Standard library imports
import argparse # Command-line argument parsing
import logging  # Logging infrastructure
import os  # OS-level operations
import re # Import for regular expressions
import sys  # System-specific parameters and functions
import time  # Time-related functions
import traceback  # Stack trace formatting
from enum import Enum  # Enumeration support
from logging.handlers import RotatingFileHandler  # Rotating log file handler
import xml.etree.ElementTree as ET  # XML parsing and tree handling

# Third-party imports
import paramiko  # SSH connection library
import requests  # HTTP requests library
from dotenv import load_dotenv  # .env file loader
from qbittorrentapi import Client as qbitClient  # qBittorrent API client
from qbittorrentapi.exceptions import (
    APIConnectionError,
)  # qBittorrent API connection error

# === Argument Parsing ===
parser = argparse.ArgumentParser(
    description="Plex, qBittorrent, and Unraid Server Automation Script."
)
parser.add_argument(
    "--log-level",
    "-l",
    choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
    default='INFO', # Default to INFO level if not specified
    help="Set the logging level for the script. (default: INFO)"
)
args = parser.parse_args()

# Map string log levels to logging constants
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}
chosen_log_level = LOG_LEVELS.get(args.log_level.upper(), logging.INFO)


# === Setup Logging ===
LOG_FILE = "playback_actions.log"
logging.basicConfig(
    handlers=[RotatingFileHandler(LOG_FILE, maxBytes=25000, backupCount=0)],
    level=chosen_log_level,
    format="%(asctime)s %(process)d - %(levelname)s - %(message)s",
)
log = logging.getLogger()

# === Suppress Paramiko's INFO level logs ===
# Note: Paramiko's own logger level needs to be managed separately if you want its debug messages.
# If you want to see Paramiko's DEBUG messages, you would set its level to DEBUG as well.
# logging.getLogger("paramiko").setLevel(logging.DEBUG) # Uncomment this if you want paramiko's debug logs
logging.getLogger("paramiko").setLevel(logging.WARNING) # Keeping original level to avoid excessive Paramiko output

# Add this section for the log delimiter
log.info(f"--- Script Execution Started @ {time.strftime('%Y-%m-%d %H:%M:%S')} ---")

# === Load Environment Variables ===
load_dotenv()
# Basic check for essential environment variables
required_envs = [
    "UNRAID_IP",
    "PLEX_IP",
    "PLEX_TOKEN",
    "PLEX_PORT",
    "QBIT_IP",
    "QBIT_PORT",
    "QBIT_USERNAME",
    "QBIT_PASSWORD",
    "UNRAID_USERNAME",
]
missing = [var for var in required_envs if not os.environ.get(var)]
if missing:
    log.critical(f"Missing environment variables: {', '.join(missing)}. Exiting.")
    sys.exit(1)

UNRAID_IP = os.environ.get("UNRAID_IP")
PLEX_IP = os.environ.get("PLEX_IP")
PLEX_TOKEN = os.environ.get("PLEX_TOKEN")
PLEX_PORT = os.environ.get("PLEX_PORT")
QBIT_IP = os.environ.get("QBIT_IP")
QBIT_PORT = os.environ.get("QBIT_PORT")
QBIT_USERNAME = os.environ.get("QBIT_USERNAME")
QBIT_PASSWORD = os.environ.get("QBIT_PASSWORD")
UNRAID_USERNAME = os.environ.get("UNRAID_USERNAME")
UNRAID_PASSWORD = os.environ.get("UNRAID_PASSWORD") # Keep this, it's the fallback
UNRAID_PRIVATE_KEY_PATH = os.environ.get("UNRAID_PRIVATE_KEY_PATH") # New optional variable

# Check that at least one of password or private key path is provided for SSH
if not UNRAID_PRIVATE_KEY_PATH and not UNRAID_PASSWORD:
    log.critical("Either UNRAID_PRIVATE_KEY_PATH or UNRAID_PASSWORD must be set in the .env file for Unraid SSH. Exiting.")
    sys.exit(1)

# === Constants and Configuration ===
# Define an Enum for parity status for clarity and robustness
class ParityStatus(Enum):
    """Represents the possible states of Unraid's parity check."""

    NOT_RUNNING = "no_operation"
    PAUSED = "paused"
    RUNNING = "running"
    UNKNOWN = "unknown"


# SSH Commands
PARITY_STATUS_COMMAND = 'mdcmd status | egrep "mdResync="'
PAUSE_PARITY_COMMAND = "parity.check pause"
RESUME_PARITY_COMMAND = "parity.check resume"
START_MOVER_COMMAND = "mover"
STOP_MOVER_COMMAND = "mover stop"
MOVER_RUNNING_CHECK_COMMAND = "pgrep -f 'mover'" # Command to check if mover process is running

# Expected SSH output snippets for parsing
MOVER_NOT_RUNNING_MESSAGE = "mover: not running"

DEFAULT_MOVER_FILE_NAME = "mover.status"
STREAM_COUNT_FILE = "stream_count.status"
LOCK_FILE = "script.lock"

# Convert environment variable string to boolean
# Defaults to False if IGNORE_LOCAL_STREAMS is not set in the environment.
IGNORE_LOCAL_STREAMS = os.environ.get("IGNORE_LOCAL_STREAMS", "False").lower() == "true"

# === Utility Functions ===


def writeStatusFile(
    interrupted: bool, fileLocation: str = DEFAULT_MOVER_FILE_NAME
) -> bool:
    """
    Writes the mover interruption status to a file.

    Args:
        interrupted (bool): True if mover was interrupted, False otherwise.
        fileLocation (str): Path to the status file.

    Returns:
        bool: True if write was successful, False otherwise.
    """
    try:
        with open(fileLocation, "w") as f:
            f.write("1" if interrupted else "0")
        return True
    except IOError as e:
        log.error(f"Failed to write status file {fileLocation}: {e}")
        return False


def readStatusFile(fileLocation: str = DEFAULT_MOVER_FILE_NAME) -> int:
    """
    Reads the mover interruption status from a file.

    Args:
        fileLocation (str): Path to the status file.

    Returns:
        int: 1 if mover was interrupted, 0 if not or file not found.
    """
    try:
        with open(fileLocation, "r") as f:
            return int(f.read())
    except FileNotFoundError:
        return 0
    except ValueError:
        log.warning(f"Invalid content in status file {fileLocation}. Resetting to 0.")
        return 0
    except IOError as e:
        log.error(f"Failed to read status file {fileLocation}: {e}")
        return 0


def get_connected_ssh_client(
    unraidHostname: str,
    unraidUser: str,
    unraidPass: str | None, # Make password optional as key is preferred
    privateKeyPath: str | None = None, # New: Optional path to private key
    timeout: int = 10
) -> paramiko.SSHClient | None:
    """
    Establishes and returns a connected Paramiko SSH client,
    attempting key-based authentication first if a private key path is provided,
    then falling back to password authentication.

    Args:
        unraidHostname (str): IP address or hostname of Unraid.
        unraidUser (str): SSH username for Unraid.
        unraidPass (str | None): SSH password for Unraid. Can be None if using a private key.
        privateKeyPath (str | None): Optional. Full path to the SSH private key file.
        timeout (int): Connection timeout in seconds.

    Returns:
        paramiko.SSHClient: A connected SSH client object, or None if connection fails.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # 1. Attempt key-based authentication first
    if privateKeyPath:
        expanded_private_key_path = os.path.expanduser(privateKeyPath)
        if os.path.exists(expanded_private_key_path):
            try:
                log.debug(f"Attempting SSH connection to {unraidUser}@{unraidHostname} using private key: {expanded_private_key_path}...")
                # Paramiko automatically determines key type (RSA, DSA, ECDSA, Ed25519)
                private_key = paramiko.RSAKey.from_private_key_file(expanded_private_key_path) # Default to RSA for broader compatibility
                # Try specific key types if RSA fails, or use AutoAddPolicy
                # For Ed25519: private_key = paramiko.Ed25519Key.from_private_key_file(expanded_private_key_path)
                # For ECDSA: private_key = paramiko.ECDSAKey.from_private_key_file(expanded_private_key_path)
                # For DSA: private_key = paramiko.DSSKey.from_private_key_file(expanded_private_key_path)

                ssh.connect(
                    hostname=unraidHostname, username=unraidUser, pkey=private_key, timeout=timeout
                )
                log.info("SSH connection established successfully using key-based authentication.")
                return ssh
            except paramiko.AuthenticationException:
                log.warning(
                    f"Key-based SSH authentication failed for {unraidUser}@{unraidHostname} using key {expanded_private_key_path}. Trying password fallback if available."
                )
            except paramiko.SSHException as e:
                log.warning(f"SSH error during key-based connection attempt to {unraidHostname}: {e}. Trying password fallback if available.")
            except FileNotFoundError: # Should be caught by os.path.exists, but good for explicit logging
                log.warning(f"Private key file not found at {expanded_private_key_path}. Trying password fallback if available.")
            except Exception as e:
                log.warning(f"Unexpected error during key-based connection attempt to {unraidHostname}: {e}. Trying password fallback if available.")
        else:
            log.warning(f"Private key file not found at {expanded_private_key_path}. Trying password fallback if available.")


    # 2. Fallback to password-based authentication if key auth failed or no key path provided
    if unraidPass:
        try:
            log.debug(f"Attempting SSH connection to {unraidUser}@{unraidHostname} using password authentication...")
            ssh.connect(
                hostname=unraidHostname, username=unraidUser, password=unraidPass, timeout=timeout
            )
            log.info("SSH connection established successfully using password authentication.")
            return ssh
        except paramiko.AuthenticationException:
            log.error(
                f"SSH password authentication failed for {unraidUser}@{unraidHostname}. Check UNRAID_PASSWORD."
            )
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            log.error(
                f"SSH connection failed to {unraidHostname} (Is host reachable and SSH enabled?): {e}"
            )
        except paramiko.SSHException as e:
            log.error(f"An SSH error occurred during password connection attempt: {e}")
        except Exception as e:
            log.error(f"An unexpected error occurred during password connection attempt: {e}")
    else:
        log.error("No UNRAID_PRIVATE_KEY_PATH provided or key-based authentication failed, and no UNRAID_PASSWORD provided. Cannot authenticate via SSH.")

    return None


def sendSSHCommand(
    ssh_client: paramiko.SSHClient,
    command: str,
    waitForOutput: bool = True,
    timeout: int = 10,
) -> str:
    """
    Sends an SSH command using an existing, connected SSH client.

    Args:
        ssh_client (paramiko.SSHClient): An already connected Paramiko SSH client object.
        command (str): The command string to execute.
        waitForOutput (bool): If True, waits for and returns stdout.
        timeout (int): Command execution timeout in seconds. This timeout primarily
                       applies to establishing the command session and waiting for
                       initial output. Subsequent reads are handled by waiting for
                       the command to complete.

    Returns:
        str: The decoded stdout output if waitForOutput is True, otherwise an empty string.
             Returns empty string on any SSH error.
    """
    try:
        log.debug(f"Executing SSH command: '{command}'")

        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)

        # Get the underlying channel object
        channel = stdout.channel

        # Wait for the command to finish executing on the remote side.
        # This will block until the command provides its exit status.
        # It's crucial for commands that produce little or no stdout.
        exit_status = channel.recv_exit_status()
        log.debug(f"Command '{command}' completed with exit status: {exit_status}")

        # Now that the command has finished, read any output from stdout and stderr.
        # These reads should no longer time out as the streams are at EOF.
        output = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()

        if error_output:
            log.error(f"SSH command '{command}' produced stderr: {error_output}")

        if output:
            log.debug(f"SSH command '{command}' stdout: {output}")

        if waitForOutput:
            return output
        else:
            return ""

    except paramiko.SSHException as e:
        log.error(f'An SSH-specific error occurred during command "{command}": {e}')
        log.error(f"Traceback (SSHException): {traceback.format_exc()}")
    except Exception as e:
        log.error(
            f'An unexpected Python error occurred during SSH command "{command}": {e}'
        )
        log.error(f"Traceback (Unexpected Exception): {traceback.format_exc()}")
    return ""


def stopMover(ssh_client: paramiko.SSHClient) -> bool:
    """
    Attempts to stop the Unraid mover and records if it was interrupted.
    Performs a pre-check to see if the mover is actually running before attempting to stop.

    Args:
        ssh_client (paramiko.SSHClient): An already connected Paramiko SSH client object.

    Returns:
        bool: True if mover was running and stopped/interrupted, False otherwise.
    """
    log.debug("Checking if mover is currently running...")
    # Use pgrep to check if any process named 'mover' is running
    mover_check_output = sendSSHCommand(ssh_client, MOVER_RUNNING_CHECK_COMMAND)

    if mover_check_output: # If pgrep returns any output (i.e., a PID), mover is running
        log.info(f"Mover process detected (PID: {mover_check_output}). Attempting to stop mover...")
        mover_stop_output = sendSSHCommand(ssh_client, STOP_MOVER_COMMAND)
        
        # We assume if mover_stop_output contains MOVER_NOT_RUNNING_MESSAGE, it means it was already stopped
        # or the stop command completed and confirmed it's not running.
        # If it doesn't contain that, it implies it was running and was told to stop.
        if MOVER_NOT_RUNNING_MESSAGE not in mover_stop_output:
            # If mover was running and successfully told to stop, mark as interrupted
            if writeStatusFile(True):
                log.info("Mover was running and has been successfully stopped, marked as interrupted.")
                return True
            else:
                log.error("Failed to record mover interruption status after stopping.")
                return False
        else:
            # This case ideally means 'mover stop' command itself said it wasn't running,
            # which contradicts pgrep. This scenario should be rare if pgrep is reliable.
            log.warning("Mover appeared to be running but 'mover stop' command reported it was not.")
            return False
    else:
        log.info("Mover was not running (no process detected). No need to stop.")
        return False


def resumeMover(ssh_client: paramiko.SSHClient) -> bool:
    """
    Resumes the Unraid mover if it was previously interrupted.

    Args:
        ssh_client (paramiko.SSHClient): An already connected Paramiko SSH client object.

    Returns:
        bool: True if mover was resumed, False if it was not interrupted.
    """
    if readStatusFile():
        log.debug("Mover was previously interrupted, attempting to resume...")
        sendSSHCommand(
            ssh_client, START_MOVER_COMMAND, waitForOutput=False
        )  # Pass the existing client
        if writeStatusFile(False):  # Reset status file
            log.info("Mover resumed and interruption status cleared.")
            return True
        else:
            log.error("Failed to clear mover interruption status.")
            return False
    log.info("Mover was not marked as interrupted.")
    return False


def getActiveStreams(
    plexHost: str, plexToken: str
) -> tuple[int, int] | tuple[None, None]:
    """
    Fetches the number of active Plex streams, separating total and remote.

    Args:
        plexHost (str): The full URL for Plex sessions API (e.g., 'http://IP:PORT/status/sessions').
        plexToken (str): Your Plex API token.

    Returns:
        tuple[int, int]: (total_active_streams, remote_active_streams).
        tuple[None, None]: If there's an error fetching or parsing the streams.
    """
    headers = {"Accept": "application/xml", "X-Plex-Token": plexToken}
    try:
        resp = requests.get(plexHost, headers=headers, timeout=10)
        resp.raise_for_status()
        root = ET.fromstring(resp.text)

        total_count = 0
        remote_count = 0

        for video in root.findall(".//Video"):
            player = video.find(".//Player")
            if player is not None:
                total_count += 1  # Always count for total active streams

                # Check if the stream is remote (local="0" in Plex API)
                if player.attrib.get("local") == "0":
                    remote_count += 1

        return total_count, remote_count  # Return both counts
    except requests.exceptions.Timeout:
        log.error(f"Plex API request timed out after 10 seconds.")
        return None, None
    except requests.exceptions.HTTPError as e:
        log.error(
            f"Failed to fetch active streams (HTTP Error): {e} - Status: {resp.status_code}"
        )
        return None, None
    except requests.exceptions.ConnectionError as e:
        log.error(
            f"Plex API connection failed: {e}. Is Plex server running and reachable?"
        )
        return None, None
    except requests.exceptions.RequestException as e:
        log.error(f"An unexpected requests error occurred: {e}")
        return None, None
    except ET.ParseError as e:
        log.error(f"Failed to parse Plex XML response: {e}")
        return None, None


def getQbitSpeedLimitMode(qbitHost: str, qbitUser: str, qbitPass: str) -> int | None:
    """
    Queries the qBittorrent API to get the current speed limits mode.

    Args:
        qbitHost (str): qBittorrent host (e.g., 'IP:PORT').
        qbitUser (str): qBittorrent username.
        qbitPass (str): qBittorrent password.

    Returns:
        int | None: 1 if speed limits are enabled, 0 if disabled,
                    or None if there's an error querying the API.
    """
    qbit = qbitClient(host=qbitHost)
    try:
        qbit.auth_log_in(username=qbitUser, password=qbitPass)
        # The API returns 1 for enabled, 0 for disabled
        current_mode = qbit.transfer_speed_limits_mode()  # Corrected method name
        log.debug(f"qBittorrent API returned raw speedLimitsMode: {current_mode}")
        return int(current_mode)  # Ensure it's an int
    except APIConnectionError as e:
        log.error(
            f"qBittorrent connection failed during speed limit mode check: {e}. Check IP/Port and credentials."
        )
        return None
    except Exception as e:
        log.error(
            f"An unexpected error occurred while checking qBittorrent speed limit mode: {e}"
        )
        return None


def limitQbitSpeed(
    qbitHost: str, qbitUser: str, qbitPass: str, limitSpeed: bool = True
) -> bool:
    """
    Sets or restores qBittorrent speed limits mode, but only if it needs to be changed.

    Args:
        qbitHost (str): qBittorrent host (e.g., 'IP:PORT').
        qbitUser (str): qBittorrent username.
        qbitPass (str): qBittorrent password.
        limitSpeed (bool): True to enable speed limits, False to disable.

    Returns:
        bool: True if speed limit mode was successfully set (or already was), False otherwise.
    """
    current_speed_mode_int = getQbitSpeedLimitMode(qbitHost, qbitUser, qbitPass)
    desired_speed_mode_int = 1 if limitSpeed else 0  # Convert boolean to int (1 or 0)

    if current_speed_mode_int is None:
        log.warning(
            "Could not determine current qBittorrent speed limit mode. Attempting to set anyway."
        )
        qbit = qbitClient(host=qbitHost)
        try:
            qbit.auth_log_in(username=qbitUser, password=qbitPass)
            qbit.transfer_set_speed_limits_mode(limitSpeed)  # Corrected method name
            log.info(
                f'qBittorrent speed set to {"limited" if limitSpeed else "normal"} successfully.'
            )  # Moved inside
            return True
        except APIConnectionError as e:
            log.error(f"qBittorrent connection failed (fallback set speed): {e}.")
            return False
        except Exception as e:
            log.error(f"An unexpected error occurred (fallback set speed): {e}")
            return False

    if current_speed_mode_int == desired_speed_mode_int:
        log.info(
            f"qBittorrent speed already set to {'limited' if limitSpeed else 'normal'}. No change needed."
        )
        return True
    else:
        log.info(
            f"Changing qBittorrent speed from {'limited' if current_speed_mode_int == 1 else 'normal'} to {'limited' if limitSpeed else 'normal'}."
        )
        qbit = qbitClient(host=qbitHost)
        try:
            qbit.auth_log_in(username=qbitUser, password=qbitPass)
            qbit.transfer_set_speed_limits_mode(limitSpeed)  # Corrected method name
            log.info(
                f'qBittorrent speed set to {"limited" if limitSpeed else "normal"} successfully.'
            )
            return True
        except APIConnectionError as e:
            log.error(
                f"qBittorrent connection failed during speed limit change: {e}. Check IP/Port and credentials."
            )
            return False
        except Exception as e:
            log.error(
                f"An unexpected error occurred while setting qBittorrent speed: {e}"
            )
            return False


def parseParityStatus(status_output: str) -> ParityStatus:
    """
    Parses the output of the 'mdcmd status | egrep "mdResync="' command.

    Args:
        status_output (str): The raw output string from the mdResync status command (e.g., "mdResync=0").

    Returns:
        ParityStatus: An Enum representing the current parity status based on mdResync.
                      mdResync=1+ -> RUNNING
                      mdResync=0 -> NOT_RUNNING (covers both not running and paused states)
    """
    match = re.search(r'mdResync=(\d+)', status_output)
    if match:
        md_resync_value = int(match.group(1))
        if md_resync_value == 0:
            # As per user's description, 0 means not running or paused.
            log.debug(f'mdResync is {md_resync_value}, mapping to ParityStatus.NOT_RUNNING')
            return ParityStatus.NOT_RUNNING
        else: # Any non-zero value means it is running
            log.debug(f'mdResync is {md_resync_value} (non-zero), mapping to ParityStatus.RUNNING')
            return ParityStatus.RUNNING
    log.warning(f'Could not parse parity status from mdResync. Unexpected output: "{status_output}"')
    return ParityStatus.UNKNOWN # Ensure a return value for all paths


def checkAndCreateLock() -> None:
    """
    Checks for the existence of a lock file and creates it if not present.
    Exits the script if a lock file already exists.
    """
    if os.path.exists(LOCK_FILE):
        log.warning("Lock file exists. Exiting to avoid duplicate execution.")
        sys.exit(1)
    try:
        with open(LOCK_FILE, "w") as f:
            f.write("lock")
        log.info(f"Lock file '{LOCK_FILE}' created.")
    except IOError as e:
        log.critical(f"Failed to create lock file {LOCK_FILE}: {e}. Exiting.")
        sys.exit(1)


def removeLock() -> None:
    """
    Removes the script's lock file.
    """
    if os.path.exists(LOCK_FILE):
        try:
            os.remove(LOCK_FILE)
            log.info(f"Lock file '{LOCK_FILE}' removed.")
        except OSError as e:
            log.error(f"Failed to remove lock file {LOCK_FILE}: {e}")


def writeStreamCount(count: int) -> None:
    """
    Writes the current active stream count to a status file.

    Args:
        count (int): The number of active streams.
    """
    try:
        with open(STREAM_COUNT_FILE, "w") as f:
            f.write(str(count))
    except IOError as e:
        log.error(f"Failed to write stream count to {STREAM_COUNT_FILE}: {e}")


def readLastStreamCount() -> int:
    """
    Reads the last known active stream count from a status file.

    Returns:
        int: The last recorded stream count, or 0 if file not found or content is invalid.
    """
    try:
        with open(STREAM_COUNT_FILE, "r") as f:
            return int(f.read())
    except FileNotFoundError:
        return 0
    except ValueError:
        log.warning(
            f"Invalid content in stream count file {STREAM_COUNT_FILE}. Resetting to 0."
        )
        return 0
    except IOError as e:
        log.error(f"Failed to read stream count from {STREAM_COUNT_FILE}: {e}")
        return 0


# === Main Execution ===
if __name__ == "__main__":
    # No longer attempting to set log file ownership here.
    # The script should be run as the desired user (e.g., 'tautulli').

    checkAndCreateLock()  # This will create the lock file with the script's user/group ownership.

    ssh_client = None

    try:
        plexHost = f"http://{PLEX_IP}:{PLEX_PORT}/status/sessions"
        qbitHost = f"{QBIT_IP}:{QBIT_PORT}"

        # Get both total and remote active streams
        totalActiveStreams, remoteActiveStreams = getActiveStreams(plexHost, PLEX_TOKEN)
        if totalActiveStreams is None:  # Handle errors from getActiveStreams
            log.error(
                "Could not retrieve active streams from Plex. Script will exit without action."
            )
            sys.exit(0)

        # Read the last TOTAL stream count for comparison with current total streams
        lastTotalStreamCount = readLastStreamCount()

        log.info(
            f"Previous total streams: {lastTotalStreamCount} | Current total streams: {totalActiveStreams} (Remote: {remoteActiveStreams})"
        )

        # Determine if qBittorrent should be throttled based on the new rules:
        # THROTTLE if: (any remote stream is active) OR (any local stream is active AND we are NOT ignoring local streams)
        desiredQbitThrottleState = (remoteActiveStreams > 0) or (
            (totalActiveStreams - remoteActiveStreams) > 0 and not IGNORE_LOCAL_STREAMS
        )

        # Establish the SSH connection (if not already connected) before any SSH commands
        ssh_client = get_connected_ssh_client(
            UNRAID_IP, UNRAID_USERNAME, UNRAID_PASSWORD, UNRAID_PRIVATE_KEY_PATH # Pass the new argument
        )
        if ssh_client is None:
            log.critical(
                "Failed to establish SSH connection to Unraid. Cannot perform Unraid actions. Exiting."
            )
            sys.exit(1)

        # --- Main Logic Flow based on TOTAL active streams ---
        if totalActiveStreams > 0:  # If ANY stream (local or remote) is playing
            log.info('Active streams detected. Initiating performance optimization actions (limit qBittorrent, pause parity, stop mover)...')

            # qBittorrent handling: Apply throttling based on the calculated desired state
            if limitQbitSpeed(
                qbitHost,
                QBIT_USERNAME,
                QBIT_PASSWORD,
                limitSpeed=desiredQbitThrottleState,
            ):
                pass  # Log is now handled inside limitQbitSpeed
            else:
                log.warning("Failed to set qBittorrent speed.")

            # Parity handling: Check status before attempting to pause
            current_parity_status_output = sendSSHCommand(ssh_client, PARITY_STATUS_COMMAND)
            current_parity_status = parseParityStatus(current_parity_status_output)

            if current_parity_status == ParityStatus.RUNNING:
                log.info('Parity is running (mdResync!=0 detected), attempting to pause...')
                sendSSHCommand(ssh_client, PAUSE_PARITY_COMMAND, waitForOutput=False)
                time.sleep(1) # Give Unraid a moment to process the pause command
                # Re-check status to confirm pause
                after_pause_parity_status = parseParityStatus(sendSSHCommand(ssh_client, PARITY_STATUS_COMMAND))

                if after_pause_parity_status == ParityStatus.NOT_RUNNING:
                    log.info('Parity paused successfully (mdResync=0 detected after pause command).')
                elif after_pause_parity_status == ParityStatus.RUNNING:
                    log.warning(f'Failed to pause parity; mdResync is still running after pause attempt.')
                else:
                    log.warning(f'Failed to pause parity or parity is in an unexpected state after pause attempt: {after_pause_parity_status.value}.')
            elif current_parity_status == ParityStatus.NOT_RUNNING:
                log.info('Parity was not running (mdResync=0 detected). No need to pause.')
            else:
                log.warning(f'Could not determine initial parity status: {current_parity_status.value}. Skipping pause attempt.')


            # Mover handling: Check and stop if running
            if stopMover(ssh_client): # stopMover now handles its own pre-check and logging
                pass # Log messages are now handled internally by stopMover
            else:
                pass # Log messages are now handled internally by stopMover

        else:  # No active streams (totalActiveStreams == 0)
            log.info('No active streams detected. Restoring server performance (restore qBittorrent, resume parity, start mover if needed)...')

            # qBittorrent handling: Always restore to normal speed if no streams at all
            if limitQbitSpeed(qbitHost, QBIT_USERNAME, QBIT_PASSWORD, limitSpeed=False):
                pass  # Log is now handled inside limitQbitSpeed
            else:
                log.warning("Failed to restore qBittorrent speed.")

            # Parity handling: Always resume if no streams
            sendSSHCommand(ssh_client, RESUME_PARITY_COMMAND, waitForOutput=False)
            time.sleep(1)
            parityStatus = parseParityStatus(
                sendSSHCommand(ssh_client, PARITY_STATUS_COMMAND)
            )
            if parityStatus == ParityStatus.RUNNING:
                log.info("Parity resumed successfully.")
            elif parityStatus == ParityStatus.NOT_RUNNING:
                log.info("Parity was not running.")
            else:
                log.warning(
                    f"Failed to resume parity or parity is in an unexpected state: {parityStatus.value}."
                )

            # Mover handling: Resume only if previously interrupted
            if resumeMover(ssh_client):
                log.info("Mover resumed as it was previously interrupted.")
            else:
                log.info("Mover was not marked as interrupted or failed to resume.")

        # Always update the stream count file with the total active streams for the next run's comparison
        writeStreamCount(totalActiveStreams)
        log.info("Script execution complete.")

    finally:
        removeLock()
        if ssh_client:
            log.info("Closing SSH connection.")
            ssh_client.close()

        # If totalActiveStreams is 0 at the end of the script, remove the stream_count.status file
        if totalActiveStreams is not None and totalActiveStreams == 0:
            if os.path.exists(STREAM_COUNT_FILE):
                try:
                    os.remove(STREAM_COUNT_FILE)
                    log.info(
                        f"'{STREAM_COUNT_FILE}' removed as no active streams were detected."
                    )
                except OSError as e:
                    log.error(f"Failed to remove '{STREAM_COUNT_FILE}': {e}")

log.info(f"--- Script Execution Finished @ {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
