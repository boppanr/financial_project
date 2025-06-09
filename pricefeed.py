import datetime
import logging
import time
from typing import List
from queue import Queue
from kiteconnect import KiteTicker
import requests
from config import Config
from instruments import instruments

ltps = {}
historical_data = {}

logger = logging.getLogger(__name__)

class PricePkt:
    def __init__(self, instrument_token: str, ltp: float):
        self.instrument_token = instrument_token
        self.ltp = ltp


class Pricefeed:
    def __init__(self, api_key: str, access_token: str, price_queue: Queue):
        self.price_queue = price_queue
        self.ws = KiteTicker(
            api_key=api_key,
            access_token=access_token,
            debug=False,
            root=None,
            reconnect=True,
            reconnect_max_tries=100,
            reconnect_max_delay=15,
            connect_timeout=10,
        )


    def connect(self):
        self.ws.on_connect = self.on_connect
        self.ws.on_ticks = self.on_ticks
        self.ws.on_close = self.on_close
        self.ws.connect(threaded=True)


    def on_connect(self, ws: KiteTicker, _):
        logger.info("Feed connected successfully.")
        tokens_to_subscribe = [
            int(instrument["pricefeed_token"]) for instrument in instruments.values()
        ]
        if len(tokens_to_subscribe) > 0:
            tokens_to_subscribe = tokens_to_subscribe[:4000]
            self.subscribe(tokens_to_subscribe)
        logger.info(f"pricefeed connected, {ws}")


    def on_ticks(self, _, ticks: dict):
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
                self.price_queue.put(PricePkt(instrument_token, ltp))


    def on_close(self, _, code, reason):
        logger.critical(f"Closed feed with code={code}, reason={reason}")


    def subscribe(self, tokens: List[str]):
        tokens = list(map(int, tokens))
        self.ws.subscribe(tokens)
        self.ws.set_mode(self.ws.MODE_FULL, tokens)
        logger.info(f"Succesfully subscribed {len(tokens)} tokens.")


    def unsubscribe(self, tokens: List[str]):
        tokens = list(map(int, tokens))
        self.ws.unsubscribe(tokens)


def get_high_low_historical_data(instrument_token: str, timeframe: float, end_time: datetime.time):
    if instrument_token in historical_data:
        if timeframe in historical_data[instrument_token]:
            return historical_data[instrument_token][timeframe]["high"], historical_data[instrument_token][timeframe]["low"]
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
        historical_data[instrument_token][timeframe] = {
            "high": high,
            "low": low
        }
        return high, low
    
    raise Exception(f"Max retry attempts achieved for historical data.")


def get_ltp(instrument_token: str):
    return ltps.get(instrument_token)