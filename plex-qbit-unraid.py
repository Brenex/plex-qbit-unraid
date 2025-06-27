# Standard library imports
import logging  # Logging infrastructure
import os  # OS-level operations
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
from qbittorrentapi.exceptions import APIConnectionError  # qBittorrent API connection error

# === Setup Logging ===
LOG_FILE = 'playback_actions.log'
logging.basicConfig(
    handlers=[RotatingFileHandler(LOG_FILE, maxBytes=1000000, backupCount=3)],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
log = logging.getLogger()

# Add this section for the log delimiter
log.info(f"--- Script Execution Started @ {time.strftime('%Y-%m-%d %H:%M:%S')} ---")

# === Load Environment Variables ===
load_dotenv()
# Basic check for essential environment variables
required_envs = ['UNRAID_IP', 'PLEX_IP', 'PLEX_TOKEN', 'PLEX_PORT', 'QBIT_IP', 'QBIT_PORT', 'QBIT_USERNAME', 'QBIT_PASSWORD', 'UNRAID_USERNAME', 'UNRAID_PASSWORD']
missing = [var for var in required_envs if not os.environ.get(var)]
if missing:
    log.critical(f"Missing environment variables: {', '.join(missing)}. Exiting.")
    sys.exit(1)

UNRAID_IP = os.environ.get('UNRAID_IP')
PLEX_IP = os.environ.get('PLEX_IP')
PLEX_TOKEN = os.environ.get('PLEX_TOKEN')
PLEX_PORT = os.environ.get('PLEX_PORT')
QBIT_IP = os.environ.get('QBIT_IP')
QBIT_PORT = os.environ.get('QBIT_PORT')
QBIT_USERNAME = os.environ.get('QBIT_USERNAME')
QBIT_PASSWORD = os.environ.get('QBIT_PASSWORD')
UNRAID_USERNAME = os.environ.get('UNRAID_USERNAME')
UNRAID_PASSWORD = os.environ.get('UNRAID_PASSWORD')

# === Constants and Configuration ===
# Define an Enum for parity status for clarity and robustness
class ParityStatus(Enum):
    """Represents the possible states of Unraid's parity check."""
    NOT_RUNNING = "no_operation"
    PAUSED = "paused"
    RUNNING = "running"
    UNKNOWN = "unknown"

# SSH Commands
PARITY_STATUS_COMMAND = 'parity.check status'
PAUSE_PARITY_COMMAND = 'parity.check pause'
RESUME_PARITY_COMMAND = 'parity.check resume'
START_MOVER_COMMAND = 'mover'
STOP_MOVER_COMMAND = 'mover stop'

# Expected SSH output snippets for parsing
MOVER_NOT_RUNNING_MESSAGE = 'mover: not running'
PARITY_NOT_RUNNING_MESSAGE = 'Status: No array operation currently in progress'
PARITY_PAUSED_MESSAGE = 'PAUSED'
# New constant for the specific parity sync/rebuild message
PARITY_SYNC_OR_REBUILD_MESSAGE = 'Parity Sync/Data Rebuild'
# Existing message for parity check/correction
PARITY_CORRECTING_MESSAGE = 'Correcting Parity-Check' # Covers both correct and check operations

DEFAULT_MOVER_FILE_NAME = 'mover.status'
STREAM_COUNT_FILE = 'stream_count.status'
LOCK_FILE = 'script.lock'

# Convert environment variable string to boolean
# Defaults to False if IGNORE_LOCAL_STREAMS is not set in the environment.
IGNORE_LOCAL_STREAMS = os.environ.get('IGNORE_LOCAL_STREAMS', 'False').lower() == 'true'

# === Utility Functions ===

def writeStatusFile(interrupted: bool, fileLocation: str = DEFAULT_MOVER_FILE_NAME) -> bool:
    """
    Writes the mover interruption status to a file.

    Args:
        interrupted (bool): True if mover was interrupted, False otherwise.
        fileLocation (str): Path to the status file.

    Returns:
        bool: True if write was successful, False otherwise.
    """
    try:
        with open(fileLocation, 'w') as f:
            f.write('1' if interrupted else '0')
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
        with open(fileLocation, 'r') as f:
            return int(f.read())
    except FileNotFoundError:
        return 0
    except ValueError:
        log.warning(f"Invalid content in status file {fileLocation}. Resetting to 0.")
        return 0
    except IOError as e:
        log.error(f"Failed to read status file {fileLocation}: {e}")
        return 0

def get_connected_ssh_client(unraidHostname: str, unraidUser: str, unraidPass: str, timeout: int = 10) -> paramiko.SSHClient | None:
    """
    Establishes and returns a connected Paramiko SSH client.

    Args:
        unraidHostname (str): IP address or hostname of Unraid.
        unraidUser (str): SSH username for Unraid.
        unraidPass (str): SSH password for Unraid.
        timeout (int): Connection timeout in seconds.

    Returns:
        paramiko.SSHClient: A connected SSH client object, or None if connection fails.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        log.info(f"Attempting SSH connection to {unraidUser}@{unraidHostname}...")
        ssh.connect(unraidHostname, username=unraidUser, password=unraidPass, timeout=timeout)
        log.info("SSH connection established successfully.")
        return ssh
    except paramiko.AuthenticationException:
        log.error(f'SSH authentication failed for {unraidUser}@{unraidHostname}. Check credentials.')
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        log.error(f'SSH connection failed to {unraidHostname} (Is host reachable and SSH enabled?): {e}')
    except paramiko.SSHException as e:
        log.error(f'An SSH error occurred during connection: {e}')
    except Exception as e:
        log.error(f'An unexpected error occurred during SSH connection: {e}')
    return None

def sendSSHCommand(ssh_client: paramiko.SSHClient, command: str, waitForOutput: bool = True, timeout: int = 10) -> str:
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

        # --- IMPORTANT CHANGE START ---
        # Get the underlying channel object
        channel = stdout.channel

        # Wait for the command to finish executing on the remote side.
        # This will block until the command provides its exit status.
        # It's crucial for commands that produce little or no stdout.
        exit_status = channel.recv_exit_status()
        log.debug(f"Command '{command}' completed with exit status: {exit_status}")
        # --- IMPORTANT CHANGE END ---

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
            return ''

    except paramiko.SSHException as e:
        log.error(f'An SSH-specific error occurred during command "{command}": {e}')
        log.error(f'Traceback (SSHException): {traceback.format_exc()}')
    except Exception as e:
        log.error(f'An unexpected Python error occurred during SSH command "{command}": {e}')
        log.error(f'Traceback (Unexpected Exception): {traceback.format_exc()}')
    return ''

def stopMover(ssh_client: paramiko.SSHClient) -> bool:
    """
    Attempts to stop the Unraid mover and records if it was interrupted.

    Args:
        ssh_client (paramiko.SSHClient): An already connected Paramiko SSH client object.

    Returns:
        bool: True if mover was running and stopped/interrupted, False otherwise.
    """
    log.info('Attempting to stop mover...')
    moverStatus = sendSSHCommand(ssh_client, STOP_MOVER_COMMAND) # Pass the existing client
    if MOVER_NOT_RUNNING_MESSAGE not in moverStatus:
        # If mover was running, it means we interrupted it.
        if writeStatusFile(True):
            log.info('Mover was running and has been marked as interrupted.')
            return True
        else:
            log.error('Failed to record mover interruption status.')
            return False
    log.info('Mover was not running.')
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
        log.info('Mover was previously interrupted, attempting to resume...')
        sendSSHCommand(ssh_client, START_MOVER_COMMAND, waitForOutput=False) # Pass the existing client
        if writeStatusFile(False): # Reset status file
            log.info('Mover resumed and interruption status cleared.')
            return True
        else:
            log.error('Failed to clear mover interruption status.')
            return False
    log.info('Mover was not marked as interrupted.')
    return False

def getActiveStreams(plexHost: str, plexToken: str) -> tuple[int, int] | tuple[None, None]:
    """
    Fetches the number of active Plex streams, separating total and remote.

    Args:
        plexHost (str): The full URL for Plex sessions API (e.g., 'http://IP:PORT/status/sessions').
        plexToken (str): Your Plex API token.

    Returns:
        tuple[int, int]: (total_active_streams, remote_active_streams).
        tuple[None, None]: If there's an error fetching or parsing the streams.
    """
    headers = {
        'Accept': 'application/xml',
        'X-Plex-Token': plexToken
    }
    try:
        resp = requests.get(plexHost, headers=headers, timeout=10)
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        
        total_count = 0
        remote_count = 0

        for video in root.findall('.//Video'):
            player = video.find('.//Player')
            if player is not None:
                total_count += 1 # Always count for total active streams

                # Check if the stream is remote (local="0" in Plex API)
                if player.attrib.get('local') == '0':
                    remote_count += 1
        
        return total_count, remote_count # Return both counts
    except requests.exceptions.Timeout:
        log.error(f'Plex API request timed out after 10 seconds.')
        return None, None
    except requests.exceptions.HTTPError as e:
        log.error(f'Failed to fetch active streams (HTTP Error): {e} - Status: {resp.status_code}')
        return None, None
    except requests.exceptions.ConnectionError as e:
        log.error(f'Plex API connection failed: {e}. Is Plex server running and reachable?')
        return None, None
    except requests.exceptions.RequestException as e:
        log.error(f'An unexpected requests error occurred: {e}')
        return None, None
    except ET.ParseError as e:
        log.error(f'Failed to parse Plex XML response: {e}')
        return None, None

def limitQbitSpeed(qbitHost: str, qbitUser: str, qbitPass: str, limitSpeed: bool = True) -> bool:
    """
    Sets or restores qBittorrent speed limits mode.

    Args:
        qbitHost (str): qBittorrent host (e.g., 'IP:PORT').
        qbitUser (str): qBittorrent username.
        qbitPass (str): qBittorrent password.
        limitSpeed (bool): True to enable speed limits, False to disable.

    Returns:
        bool: True if speed limit mode was successfully set, False otherwise.
    """
    qbit = qbitClient(host=qbitHost)
    try:
        qbit.auth_log_in(username=qbitUser, password=qbitPass)
        qbit.transfer_setSpeedLimitsMode(limitSpeed)
        return True
    except APIConnectionError as e:
        log.error(f'qBittorrent connection failed: {e}. Check IP/Port and credentials.')
        return False
    except Exception as e:
        log.error(f'An unexpected error occurred while setting qBittorrent speed: {e}')
        return False

def parseParityStatus(status_output: str) -> ParityStatus:
    """
    Parses the output of the 'parity.check status' command.

    Args:
        status_output (str): The raw output string from the parity status command.

    Returns:
        ParityStatus: An Enum representing the current parity status.
    """
    if PARITY_NOT_RUNNING_MESSAGE in status_output:
        return ParityStatus.NOT_RUNNING
    if PARITY_PAUSED_MESSAGE in status_output:
        return ParityStatus.PAUSED
    # Check for the new sync/rebuild message or the existing correcting message
    if PARITY_CORRECTING_MESSAGE in status_output or PARITY_SYNC_OR_REBUILD_MESSAGE in status_output:
        return ParityStatus.RUNNING
    log.warning(f'Could not parse parity status. Unexpected output: "{status_output}"')
    return ParityStatus.UNKNOWN

def checkAndCreateLock() -> None:
    """
    Checks for the existence of a lock file and creates it if not present.
    Exits the script if a lock file already exists.
    """
    if os.path.exists(LOCK_FILE):
        log.warning('Lock file exists. Exiting to avoid duplicate execution.')
        sys.exit(1)
    try:
        with open(LOCK_FILE, 'w') as f:
            f.write('lock')
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
        with open(STREAM_COUNT_FILE, 'w') as f:
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
        with open(STREAM_COUNT_FILE, 'r') as f:
            return int(f.read())
    except FileNotFoundError:
        return 0
    except ValueError:
        log.warning(f"Invalid content in stream count file {STREAM_COUNT_FILE}. Resetting to 0.")
        return 0
    except IOError as e:
        log.error(f"Failed to read stream count from {STREAM_COUNT_FILE}: {e}")
        return 0

# === Main Execution ===
if __name__ == '__main__':
    # No longer attempting to set log file ownership here.
    # The script should be run as the desired user (e.g., 'tautulli').

    checkAndCreateLock() # This will create the lock file with the script's user/group ownership.

    ssh_client = None

    try:
        plexHost = f'http://{PLEX_IP}:{PLEX_PORT}/status/sessions'
        qbitHost = f'{QBIT_IP}:{QBIT_PORT}'

        # Get both total and remote active streams
        totalActiveStreams, remoteActiveStreams = getActiveStreams(plexHost, PLEX_TOKEN)
        if totalActiveStreams is None: # Handle errors from getActiveStreams
            log.error("Could not retrieve active streams from Plex. Script will exit without action.")
            sys.exit(0)

        # Read the last TOTAL stream count for comparison with current total streams
        lastTotalStreamCount = readLastStreamCount()

        log.info(f'Previous total streams: {lastTotalStreamCount} | Current total streams: {totalActiveStreams} (Remote: {remoteActiveStreams})')

        # Determine if qBittorrent should be throttled based on the new rules:
        # THROTTLE if: (any remote stream is active) OR (any local stream is active AND we are NOT ignoring local streams)
        desiredQbitThrottleState = (remoteActiveStreams > 0) or \
                                   ((totalActiveStreams - remoteActiveStreams) > 0 and not IGNORE_LOCAL_STREAMS)

        # Establish the SSH connection (if not already connected) before any SSH commands
        ssh_client = get_connected_ssh_client(UNRAID_IP, UNRAID_USERNAME, UNRAID_PASSWORD)
        if ssh_client is None:
            log.critical("Failed to establish SSH connection to Unraid. Cannot perform Unraid actions. Exiting.")
            sys.exit(1)

        # --- Main Logic Flow based on TOTAL active streams ---
        if totalActiveStreams > 0: # If ANY stream (local or remote) is playing
            log.info('Active streams detected. Initiating performance optimization actions (limit qBittorrent, pause parity, stop mover)...')

            # qBittorrent handling: Apply throttling based on the calculated desired state
            if limitQbitSpeed(qbitHost, QBIT_USERNAME, QBIT_PASSWORD, limitSpeed=desiredQbitThrottleState):
                log.info(f'qBittorrent speed set to {"limited" if desiredQbitThrottleState else "normal"} successfully.')
            else:
                log.warning('Failed to set qBittorrent speed.')

            # Parity handling: Always pause if any stream
            sendSSHCommand(ssh_client, PAUSE_PARITY_COMMAND, waitForOutput=False)
            time.sleep(1)
            parityStatus = parseParityStatus(sendSSHCommand(ssh_client, PARITY_STATUS_COMMAND))
            if parityStatus == ParityStatus.PAUSED:
                log.info('Parity paused successfully.')
            elif parityStatus == ParityStatus.NOT_RUNNING:
                log.info('Parity was not running.')
            else:
                log.warning(f'Failed to pause parity or parity is in an unexpected state: {parityStatus.value}.')

            # Mover handling: Always stop if any stream
            if stopMover(ssh_client):
                log.info('Mover stopped and marked as interrupted.')
            else:
                log.info('Mover was not running or failed to stop.')

        else: # No active streams (totalActiveStreams == 0)
            log.info('No active streams detected. Restoring server performance (restore qBittorrent, resume parity, start mover if needed)...')

            # qBittorrent handling: Always restore to normal speed if no streams at all
            if limitQbitSpeed(qbitHost, QBIT_USERNAME, QBIT_PASSWORD, limitSpeed=False):
                log.info('qBittorrent speed restored successfully.')
            else:
                log.warning('Failed to restore qBittorrent speed.')

            # Parity handling: Always resume if no streams
            sendSSHCommand(ssh_client, RESUME_PARITY_COMMAND, waitForOutput=False)
            time.sleep(1)
            parityStatus = parseParityStatus(sendSSHCommand(ssh_client, PARITY_STATUS_COMMAND))
            if parityStatus == ParityStatus.RUNNING:
                log.info('Parity resumed successfully.')
            elif parityStatus == ParityStatus.NOT_RUNNING:
                log.info('Parity was not running.')
            else:
                log.warning(f'Failed to resume parity or parity is in an unexpected state: {parityStatus.value}.')

            # Mover handling: Resume only if previously interrupted
            if resumeMover(ssh_client):
                log.info('Mover resumed as it was previously interrupted.')
            else:
                log.info('Mover was not marked as interrupted or failed to resume.')
            
        # Always update the stream count file with the total active streams for the next run's comparison
        writeStreamCount(totalActiveStreams)
        log.info('Script execution complete.')

    finally:
        removeLock()
        if ssh_client:
            log.info("Closing SSH connection.")
            ssh_client.close()
