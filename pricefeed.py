import datetime
import logging
from queue import Queue
import time
from kiteconnect import KiteTicker
import pytz
import requests
from config import Config
from instruments import underlying_instruments


logger = logging.getLogger(__name__)
last_heart_beat = time.time()
count = 0
all_connections: list[KiteTicker] = []
ltps = {}
historical_data = {}
price_queue = Queue()
tokens_to_subscribe = set()
running_connection = None

class PricePkt:
    def __init__(self, instrument_token: str, ltp: float):
        self.instrument_token = instrument_token
        self.ltp = ltp


def connect():
    global running_connection
    pricefeed_connection = KiteTicker(
        api_key=Config.PRICEFEED_CREDS["api_key"],
        access_token=Config.PRICEFEED_ACCESS_TOKEN,
        debug=False,
        root=None,
        reconnect=True,
        reconnect_max_tries=100,
        reconnect_max_delay=5,
        connect_timeout=10,
    )
    all_connections.append(pricefeed_connection)
    pricefeed_connection.on_connect = on_connect
    pricefeed_connection.on_ticks = on_ticks
    pricefeed_connection.on_close = on_close
    pricefeed_connection.on_error = or_error
    pricefeed_connection.on_reconnect = on_reconnect
    running_connection = pricefeed_connection
    pricefeed_connection.connect(threaded=True)


def on_connect(ws: KiteTicker, _):
    global last_heart_beat, tokens_to_subscribe
    logger.info("Feed connected successfully.")
    for und_inst in underlying_instruments.values():
        tokens_to_subscribe.add(int(und_inst.instrument_id))
    tkn_to_subscribe = list(tokens_to_subscribe)
    if len(tkn_to_subscribe) > 0:
        logger.info(tkn_to_subscribe)
        tkn_to_subscribe = tkn_to_subscribe[:4000]
        ws.subscribe(tkn_to_subscribe)
        ws.set_mode(
            ws.MODE_FULL, tkn_to_subscribe
        )
        logger.info(f"Succesfully subscribed {len(tkn_to_subscribe)} tokens.")
        last_heart_beat = time.time()
    logger.info(f"pricefeed connected, {ws}")


def on_ticks(_, ticks: dict):
    global last_heart_beat, count
    for pkt in ticks:
        if "depth" in pkt:
            ask_price = pkt['depth']['buy'][0]['price']
            bid_price = pkt['depth']['sell'][0]['price']
            volume_traded = pkt["volume_traded"]
        else:
            # for BANKNIFTY and NIFTY Index
            ask_price = 1
            bid_price = 1
            volume_traded = 1
        if (ask_price != 0) and (bid_price != 0) and (volume_traded != 0):
            instrument_token = str(pkt["instrument_token"])
            ltp = pkt["last_price"]
            # exchange_timestamp: datetime.datetime = pkt['exchange_timestamp']
            ltps[instrument_token] = ltp
            price_queue.put(PricePkt(instrument_token, ltp))
            count += 1


def on_close(_, code, reason):
    logger.debug(f"Closed feed with code={code}, reason={reason}")


def or_error(_, code, reason):
    logger.debug(f"{code}:: {reason}")


def on_reconnect(_, attempts_count):
    logger.debug(f"attempts: {attempts_count}")


def subscribe_token(token):
    global running_connection, tokens_to_subscribe
    tokens_to_subscribe.add(int(token))
    running_connection.subscribe([int(token)])
    logger.debug(f"Subsribed to {token}")


def get_quote_from_stream():
    return price_queue.get()


def heartbeat():
    global last_heart_beat, count
    while True:
        current_time = datetime.datetime.now(pytz.timezone("Asia/Kolkata")).replace(microsecond=0).time()
        if current_time <= datetime.time(9, 15):
            time.sleep(1)
            continue
        if time.time()-last_heart_beat>=20:
            if count == 0:
                logger.warning(f"Trying to reconnect pricefeed.")
                for conn in all_connections:
                    conn.close()
                all_connections.clear()
                connect()
            else:
                logger.debug(f"HEARTBEAT:: {count}")
                count = 0
            last_heart_beat = time.time()
        time.sleep(0.1)


def get_high_low_historical_data(instrument_token: str, timeframe: float, end_time: datetime.time):
    if instrument_token in historical_data:
        if end_time in historical_data[instrument_token]:
            return historical_data[instrument_token][end_time]["high"], historical_data[instrument_token][end_time]["low"]
    url = f"https://api.kite.trade/instruments/historical/{instrument_token}/minute"
    today = datetime.datetime.today().date()
    end_datetime = datetime.datetime.combine(today, end_time)
    start_datetime = end_datetime - datetime.timedelta(minutes=timeframe)
    params = {
        "from": start_datetime,
        "to": end_datetime
    }
    headers = {
        "Authorization" : f"token {Config.PRICEFEED_CREDS["api_key"]}:{Config.PRICEFEED_ACCESS_TOKEN}"
    }
    for count in range(3):
        resp = requests.get(url=url, params=params, headers=headers)
        if resp.status_code != 200:
            error_json_data = resp.json()
            if "message" in error_json_data:
                if error_json_data["message"] == "Too many requests":
                    logger.debug(f"Error: {resp.text} for going to retry, count: {count}")
                    time.sleep(1)
                    continue
            raise Exception(f"Error in getting hisotrical data::: {resp.text}")
        data = resp.json()["data"]
        flat_data = data["candles"]
        if not flat_data:
            return None, None
        high = max(row[2] for row in flat_data)
        low = min(row[3] for row in flat_data)
        if not instrument_token in historical_data:
            historical_data[instrument_token] = {}
        historical_data[instrument_token][end_time] = {
            "high": high,
            "low": low
        }
        return high, low
    
    raise Exception(f"Max retry attempts achieved for historical data.")


def get_ltp(instrument_token: str):
    return ltps.get(instrument_token)