import sys
import os
import time
import logging
import configparser
import json
import requests
import threading
import queue
from logging.handlers import RotatingFileHandler
from pathlib import Path
from NetSDK.NetSDK import (
    NetClient,
    NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY,
    NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY,
    fDisConnect,
    fHaveReConnect,
    fMessCallBackEx1
)

# ==========================================================
# Detect if running as .exe (PyInstaller) or .py script
# ==========================================================
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
    script_path = os.path.dirname(sys.executable)
else:
    base_path = os.path.dirname(os.path.abspath(__file__))
    script_path = base_path

STATE_FILE = Path(script_path) / "state.json"  # File to save the last event timestamp

# ==========================================================
# Get the absolute path to config.ini
# ==========================================================
def get_config_path():
    return os.path.join(base_path, 'config', 'config.ini')

# ==========================================================
# Verify that NetSDK library is available
# ==========================================================
def verify_dependencies():
    try:
        import NetSDK.NetSDK
        logging.info("NetSDK found.")
        return True
    except ImportError as e:
        logging.error(f"Missing dependency: {e}")
        return False

# ==========================================================
# Main service class
# ==========================================================
class TCPTestService:

    # ==========================================================
    # Service initialization
    # ==========================================================
    def __init__(self):
        self.config_path = get_config_path()
        self.config = configparser.ConfigParser()
        self.config.read(self.config_path)

        # Basic configuration
        self.username = self.config.get('DEFAULT', 'username', fallback='admin')
        self.password = self.config.get('DEFAULT', 'password', fallback='admin')
        self.mode = self.config.get('DEFAULT', 'mode', fallback='permanent').lower()
        self.interval = int(self.config.get('DEFAULT', 'interval_seconds', fallback='1'))

        # Device IP:Port list
        self.ip_port_pairs = []
        pairs_str = self.config.get('DEFAULT', 'ip_port_pairs', fallback=None)
        if pairs_str:
            for pair in pairs_str.split(','):
                if ':' in pair:
                    ip, port = pair.split(':', 1)
                    try:
                        self.ip_port_pairs.append((ip.strip(), int(port.strip())))
                    except Exception:
                        pass

        # API configuration
        self.api_url = self.config.get('DEFAULT', 'api_url', fallback=None)
        self.api_key = self.config.get('DEFAULT', 'api_key', fallback=None)
        self.api_secret = self.config.get('DEFAULT', 'api_secret', fallback=None)
        self.api_max_retries = int(self.config.get('DEFAULT', 'api_max_retries', fallback='3'))

        # Logging setup
        log_dir = os.path.join(script_path, "logs")
        os.makedirs(log_dir, exist_ok=True)

        self.error_logger = self._build_logger("Errors", "errors.log", logging.ERROR, to_console=False)
        self.conn_error_logger = self._build_logger("ConnErrors", "connection_errors.log", logging.ERROR, to_console=False)
        self.info_logger = self._build_logger("Info", "info.log", logging.INFO, to_console=True)
        self.event_logger = self._build_logger("Events", "events.log", logging.INFO, fmt='%(asctime)s - %(message)s', to_console=True)

        # API queue and thread
        self.api_queue = queue.Queue()
        self.api_thread = threading.Thread(target=self._process_api_queue, daemon=True)
        self.api_thread.start()

        # Redirect stderr to logger
        class StderrToLogger:
            def __init__(self, logger): self.logger = logger
            def write(self, message):
                message = message.strip()
                if message: self.logger.error(message)
            def flush(self): pass
        sys.stderr = StderrToLogger(self.error_logger)

        self._running = True

    # ==========================================================
    # Create logger with rotation
    # ==========================================================
    def _build_logger(self, name, filename, level=logging.INFO, fmt=None, to_console=True):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.setLevel(level)

        # Lazy handler, creates file only when first log occurs
        class LazyFileHandler(logging.Handler):
            def __init__(self, filepath, level=logging.INFO):
                super().__init__(level)
                self.filepath = filepath
                self._handler = None
            def emit(self, record):
                if not self._handler:
                    os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
                    self._handler = RotatingFileHandler(
                        self.filepath,
                        maxBytes=5 * 1024 * 1024,
                        backupCount=10,
                        encoding='utf-8'
                    )
                    self._handler.setFormatter(logging.Formatter(fmt or '%(asctime)s - %(levelname)s - %(message)s'))
                self._handler.emit(record)

        file_handler = LazyFileHandler(os.path.join(script_path, "logs", filename), level)
        logger.addHandler(file_handler)

        if to_console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(logging.Formatter(fmt or '%(asctime)s - %(levelname)s - %(message)s'))
            logger.addHandler(console_handler)

        return logger

    # ==========================================================
    # Save last event timestamp
    # ==========================================================
    def save_state(self, last_event_time=None):
        state = {"last_event_time": last_event_time.isoformat() if last_event_time else None}
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(state, f)
        except Exception as e:
            self.error_logger.error(f"[State] Error saving state: {e}")

    # ==========================================================
    # Load last event timestamp
    # ==========================================================
    def load_state(self):
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    state = json.load(f)
                    last_event_time = state.get("last_event_time")
                    if last_event_time:
                        from datetime import datetime
                        return datetime.fromisoformat(last_event_time)
            except Exception as e:
                self.error_logger.error(f"[State] Error loading state: {e}")
        return None

    # ==========================================================
    # Process API queue in separate thread
    # ==========================================================
    def _process_api_queue(self):
        while self._running:
            try:
                data = self.api_queue.get(timeout=1)
            except queue.Empty:
                continue

            headers = {
                "Authorization": f"token {self.api_key}:{self.api_secret}",
                "Content-Type": "application/json"
            }

            attempt = 0
            while attempt < self.api_max_retries:
                try:
                    resp = requests.post(self.api_url, json=data, headers=headers, timeout=5, verify=True)
                    if resp.status_code == 200:
                        self.info_logger.info(f"[API] Event sent: {data}")
                        break
                    else:
                        self.error_logger.error(f"[API] Error ({resp.status_code}): {resp.text}")
                except requests.exceptions.SSLError as e:
                    self.error_logger.error(f"[SSL] Certificate error: {e}")
                except requests.exceptions.RequestException as e:
                    self.error_logger.error(f"[API] Exception sending event: {e}")

                attempt += 1
                time.sleep(5)  # Wait before retry

            else:
                self.error_logger.error(f"[API] Failed to send after {self.api_max_retries} attempts: {data}")

            self.api_queue.task_done()

    # ==========================================================
    # Enqueue event and save last timestamp
    # ==========================================================
    def enqueue_event(self, data):
        self.api_queue.put(data)
        # Save last event time if exists in event
        event_time_str = data.get("timestamp") or data.get("Time")  # Adjust key according to your events
        if event_time_str:
            try:
                from datetime import datetime
                event_time = datetime.fromisoformat(event_time_str)
                self.save_state(event_time)
            except Exception:
                pass

    # ==========================================================
    # Run service according to mode
    # ==========================================================
    def run(self):
        if self.mode == 'permanent' or self.interval == 0:
            self.info_logger.info("TCPTestService running in permanent mode (NetSDK)")
            self.netsdk_event_loop(once=False)
        else:
            self.info_logger.info(f"TCPTestService running in cycle mode every {self.interval}s (NetSDK)")
            while self._running:
                try:
                    self.netsdk_event_loop(once=True)
                    time.sleep(self.interval)
                except Exception as e:
                    self.error_logger.error(f"Monitoring error: {e}", exc_info=True)
                    time.sleep(2)

    # ==========================================================
    # NetSDK event loop
    # ==========================================================
    def netsdk_event_loop(self, once=False):
        # Callback for disconnect
        def on_disconnect(login_id, dvr_ip, dvr_port, user_data):
            self.conn_error_logger.error(f"[NetSDK] Disconnected from {dvr_ip.decode()}:{dvr_port}")

        # Callback for reconnect
        def on_reconnect(login_id, dvr_ip, dvr_port, user_data):
            self.conn_error_logger.error(f"[NetSDK] Reconnected to {dvr_ip.decode()}:{dvr_port}")

        # Callback for messages / events
        def on_message(command, login_id, pBuf, dwBufLen, pchDVRIP, nDVRPort, bAlarmAckFlag, nEventID, user_data):
            try:
                raw_msg = bytes(pBuf[:dwBufLen]).decode(errors='ignore')
                try:
                    data = json.loads(raw_msg)
                except json.JSONDecodeError:
                    data = None
                if data:
                    self.enqueue_event(data)  # Add to API queue
                    self.event_logger.info(f"[NetSDK] Event enqueued: {data}")
                else:
                    self.event_logger.info(f"[NetSDK] Event invalid JSON: {raw_msg}")
            except Exception as e:
                self.error_logger.error(f"Error parsing event: {e}", exc_info=True)

        client = NetClient()
        client.InitEx(fDisConnect(on_disconnect))
        client.SetAutoReconnect(fHaveReConnect(on_reconnect))
        client.SetDVRMessCallBackEx1(fMessCallBackEx1(on_message), 0)

        # Connect to all devices
        for ip, port in self.ip_port_pairs:
            try:
                in_param = NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY()
                in_param.dwSize = in_param.__sizeof__()
                in_param.szIP = ip.encode()[:63] + b'\0'
                in_param.nPort = port
                in_param.szUserName = self.username.encode()[:63] + b'\0'
                in_param.szPassword = self.password.encode()[:63] + b'\0'
                out_param = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY()
                out_param.dwSize = out_param.__sizeof__()

                login_id, device_info, err = client.LoginWithHighLevelSecurity(in_param, out_param)
                if not login_id:
                    self.conn_error_logger.error(f"[NetSDK] ❌ Login failed {ip}:{port}: {err}")
                    continue

                self.info_logger.info(f"[NetSDK] Login OK {ip}:{port}")
                client.StartListenEx(login_id)
                self.info_logger.info(f"[NetSDK] Listening events {ip}:{port}")

            except Exception as e:
                self.conn_error_logger.error(f"[NetSDK] ❌ Error {ip}:{port}: {e}")

        # Loop or single run
        if once:
            time.sleep(2)
            client.Cleanup()
        else:
            try:
                while self._running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("[NetSDK] Service stopped by user")
            finally:
                client.Cleanup()

# ==========================================================
# Entry point
# ==========================================================
if __name__ == "__main__":
    print("[INFO] Running TCPTestService in console mode")
    if not verify_dependencies():
        print("Error: Missing dependencies. Check logs.")
        sys.exit(1)
    service = TCPTestService()
    service.run()
