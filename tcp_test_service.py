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
from NetSDK.NetSDK import (
    NetClient,
    NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY,
    NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY,
    fDisConnect,
    fHaveReConnect,
    fMessCallBackEx1
)

# ==========================================================
# Detecta si se ejecuta como .exe (PyInstaller) o script .py
# ==========================================================
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
    script_path = os.path.dirname(sys.executable)
else:
    base_path = os.path.dirname(os.path.abspath(__file__))
    script_path = base_path

# ==========================================================
# Devuelve la ruta absoluta del archivo config.ini
# ==========================================================
def get_config_path():
    return os.path.join(base_path, 'config', 'config.ini')

# ==========================================================
# Verifica que la librería NetSDK esté disponible
# ==========================================================
def verify_dependencies():
    try:
        import NetSDK.NetSDK
        logging.info("Dependencia NetSDK encontrada.")
        return True
    except ImportError as e:
        logging.error(f"Dependencia faltante: {e}")
        return False

# ==========================================================
# Clase principal TCPTestService
# ==========================================================
class TCPTestService:
    """
    Servicio TCP para conectar con dispositivos Dahua y enviar eventos a la API de Frappe.
    - Lee configuración desde config.ini.
    - Soporta modo cíclico o permanente.
    - Maneja logs de errores, eventos e info.
    - Envía eventos a la API en un hilo separado mediante una cola.
    """

    def __init__(self):
        # ------------------------------
        # Leer configuración
        # ------------------------------
        self.config_path = get_config_path()
        self.config = configparser.ConfigParser()
        self.config.read(self.config_path)

        self.username = self.config.get('DEFAULT', 'username', fallback='admin')
        self.password = self.config.get('DEFAULT', 'password', fallback='admin')
        self.mode = self.config.get('DEFAULT', 'mode', fallback='permanente').lower()
        self.interval = int(self.config.get('DEFAULT', 'interval_seconds', fallback='1'))

        # Lista de pares IP:Puerto de dispositivos Dahua
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

        # ------------------------------
        # Configuración de API Frappe
        # ------------------------------
        self.api_url = self.config.get('DEFAULT', 'api_url', fallback=None)
        self.api_key = self.config.get('DEFAULT', 'api_key', fallback=None)
        self.api_secret = self.config.get('DEFAULT', 'api_secret', fallback=None)
        self.api_max_retries = int(self.config.get('DEFAULT', 'api_max_retries', fallback='3'))

        # ------------------------------
        # Configuración de logs
        # ------------------------------
        log_dir = os.path.join(script_path, "logs")
        os.makedirs(log_dir, exist_ok=True)

        self.error_logger = self._build_logger("Errors", "errors.log", logging.ERROR, to_console=False)
        self.conn_error_logger = self._build_logger("ConnErrors", "connection_errors.log", logging.ERROR, to_console=False)
        self.info_logger = self._build_logger("Info", "info.log", logging.INFO, to_console=True)
        self.event_logger = self._build_logger("Events", "events.log", logging.INFO, fmt='%(asctime)s - %(message)s', to_console=True)

        # ------------------------------
        # Cola para eventos API
        # ------------------------------
        self.api_queue = queue.Queue()  # Cola de eventos que serán enviados a Frappe
        self.api_thread = threading.Thread(target=self._process_api_queue, daemon=True)
        self.api_thread.start()  # Inicia el hilo de envío asíncrono

        # ------------------------------
        # Redirigir stderr a log
        # ------------------------------
        class StderrToLogger:
            def __init__(self, logger): self.logger = logger
            def write(self, message):
                message = message.strip()
                if message: self.logger.error(message)
            def flush(self): pass
        sys.stderr = StderrToLogger(self.error_logger)

        self._running = True

    # ==========================================================
    # Crea un logger con rotación de archivos
    # ==========================================================
    def _build_logger(self, name, filename, level=logging.INFO, fmt=None, to_console=True):
        """
        name: nombre del logger
        filename: archivo de log
        level: nivel de log
        fmt: formato del mensaje
        to_console: si se imprime por consola
        """
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.setLevel(level)

        # LazyFileHandler: solo crea archivo si hay información para escribir
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
    # Enviar eventos a la API (hilo asíncrono)
    # ==========================================================
    def _process_api_queue(self):
        """
        Función que corre en un hilo separado.
        Toma eventos de la cola y los envía a la API de Frappe con reintentos.
        No bloquea el flujo principal.
        """
        while self._running:
            try:
                data = self.api_queue.get(timeout=1)  # Espera un evento en la cola
            except queue.Empty:
                continue  # Si no hay eventos, sigue el loop

            headers = {
                "Authorization": f"token {self.api_key}:{self.api_secret}",
                "Content-Type": "application/json"
            }

            attempt = 0
            while attempt < self.api_max_retries:
                try:
                    resp = requests.post(self.api_url, json=data, headers=headers, timeout=5, verify=True)
                    if resp.status_code == 200:
                        self.info_logger.info(f"[API] Evento enviado: {data}")
                        break
                    else:
                        self.error_logger.error(f"[API] Error ({resp.status_code}): {resp.text}")
                except requests.exceptions.SSLError as e:
                    self.error_logger.error(f"[SSL] Error de certificado: {e}")
                except requests.exceptions.RequestException as e:
                    self.error_logger.error(f"[API] Excepción al enviar: {e}")

                attempt += 1
                time.sleep(5)  # Reintento después de 5s

            else:
                self.error_logger.error(f"[API] No se pudo enviar después de {self.api_max_retries} intentos: {data}")

            self.api_queue.task_done()

    # ==========================================================
    # Añade un evento a la cola de envío
    # ==========================================================
    def enqueue_event(self, data):
        """
        data: diccionario JSON del evento
        """
        self.api_queue.put(data)

    # ==========================================================
    # Ejecutar servicio según modo configurado
    # ==========================================================
    def run(self):
        if self.mode == 'permanente' or self.interval == 0:
            self.info_logger.info("TCPTestService ejecutando en modo permanente (NetSDK)")
            self.netsdk_event_loop(once=False)
        else:
            self.info_logger.info(f"TCPTestService ejecutando en modo cíclico cada {self.interval}s (NetSDK)")
            while self._running:
                try:
                    self.netsdk_event_loop(once=True)
                    time.sleep(self.interval)
                except Exception as e:
                    self.error_logger.error(f"Error en monitoreo: {e}", exc_info=True)
                    time.sleep(2)

    # ==========================================================
    # Bucle de eventos NetSDK
    # ==========================================================
    def netsdk_event_loop(self, once=False):
        """
        Inicializa NetSDK y callbacks de eventos, reconexión y desconexión.
        Envía eventos a la cola para que el hilo de API los procese.
        """
        def on_disconnect(login_id, dvr_ip, dvr_port, user_data):
            self.conn_error_logger.error(f"[NetSDK] Desconectado de {dvr_ip.decode()}:{dvr_port}")

        def on_reconnect(login_id, dvr_ip, dvr_port, user_data):
            self.conn_error_logger.error(f"[NetSDK] Reconectado a {dvr_ip.decode()}:{dvr_port}")

        def on_message(command, login_id, pBuf, dwBufLen, pchDVRIP, nDVRPort, bAlarmAckFlag, nEventID, user_data):
            """
            Callback de mensajes. Decodifica bytes a JSON y lo encola para la API.
            """
            try:
                raw_msg = bytes(pBuf[:dwBufLen]).decode(errors='ignore')
                try:
                    data = json.loads(raw_msg)
                except json.JSONDecodeError:
                    data = None
                if data:
                    self.enqueue_event(data)  # Se añade a la cola, no se envía directamente
                    self.event_logger.info(f"[NetSDK] Evento encolado: {data}")
                else:
                    self.event_logger.info(f"[NetSDK] Evento sin JSON válido: {raw_msg}")
            except Exception as e:
                self.error_logger.error(f"Error interpretando evento: {e}", exc_info=True)

        client = NetClient()
        client.InitEx(fDisConnect(on_disconnect))
        client.SetAutoReconnect(fHaveReConnect(on_reconnect))
        client.SetDVRMessCallBackEx1(fMessCallBackEx1(on_message), 0)

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
                    self.conn_error_logger.error(f"[NetSDK] ❌ Login fallido a {ip}:{port}: {err}")
                    continue

                self.info_logger.info(f"[NetSDK] Login OK a {ip}:{port}")
                client.StartListenEx(login_id)
                self.info_logger.info(f"[NetSDK] Escuchando eventos en {ip}:{port}")

            except Exception as e:
                self.conn_error_logger.error(f"[NetSDK] ❌ Error con {ip}:{port}: {e}")

        if once:
            time.sleep(2)
            client.Cleanup()
        else:
            try:
                while self._running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("[NetSDK] Servicio detenido por usuario")
            finally:
                client.Cleanup()

# ==========================================================
# Punto de entrada
# ==========================================================
if __name__ == "__main__":
    print("[INFO] Ejecutando TCPTestService en modo consola")
    if not verify_dependencies():
        print("Error: Dependencias faltantes. Verifique el log.")
        sys.exit(1)
    service = TCPTestService()
    service.run()
