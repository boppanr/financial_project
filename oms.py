from copy import deepcopy
from queue import Queue
import threading
from typing import List
import uuid
import requests
import json
import hashlib
import pyotp
import logging
from requests.utils import urlparse
from kiteconnect import KiteConnect
from enums import ApiProvider, OrderStatus, OrderType, PositionStatus, Side
from constants import AVAILABLE_BROKERS
from config import Api, Config
from instruments import (
    get_exchnage_token, 
    get_fyers_tradingsymbol, 
    get_gopocket_tradingsymbol, 
    get_groww_tradingsymbol, 
    get_instrument, 
    get_zerodha_tradingsymbol
)
from models import Order, Position
import pricefeed
from fyers_apiv3 import fyersModel
import webbrowser

logger = logging.getLogger(__name__)

local_order_update_queue = Queue()

KITE_LOGIN_URL="https://kite.zerodha.com/api/login"
KITE_TWOFA_URL="https://kite.zerodha.com/api/twofa"

orders_with_us = {broker: {} for broker in AVAILABLE_BROKERS}
finvasia_tradingsymbol_mapping = {}


def slice_order(order: Order, lot_size: int, freeze_qty: int):
    complete_slices = int((order.qty / lot_size) // freeze_qty)
    reamining_qty = int((order.qty / lot_size) % freeze_qty)
    for i in range(complete_slices):
        child_order = deepcopy(order)
        child_order.id = i
        child_order.qty = lot_size * freeze_qty
        order.child_orders[child_order.id] = child_order

    if reamining_qty:
        child_order = deepcopy(order)
        child_order.id = complete_slices
        child_order.qty = reamining_qty * lot_size
        order.child_orders[child_order.id] = child_order


def zerodha_pricefeed_login(
    user_id: str, password: str, totp_secret: str, api_key: str, api_secret: str
):
    with requests.Session() as session:
        login_payload = {
            "user_id": user_id,
            "password": password,
        }
        login_response = session.post(
            KITE_LOGIN_URL, data=login_payload, timeout=10
        )
        if login_response.status_code != 200:
            raise Exception(
                f"Error while logging in to kite for user-{user_id}, Error: {login_response.text}"
            )
        req_id = login_response.json()["data"]["request_id"]

        twofa_payload = {
            "request_id": req_id,
            "user_id": user_id,
            "twofa_value": pyotp.TOTP(totp_secret).now(),
            "twofa_type": "totp",
        }
        twofa_response = session.post(
            KITE_TWOFA_URL, data=twofa_payload, timeout=10
        )
        if twofa_response.status_code != 200:
            raise Exception(
                f"Error while logging in to kite for user-{user_id}, Error: {twofa_response.text}"
            )

        api_login_response = session.get(
            f"https://kite.zerodha.com/connect/login?v=3&api_key={api_key}",
            timeout=10,
            allow_redirects=False,
        )
        if api_login_response.status_code != 302:
            raise Exception(
                f"Error while logging in to kite for user-{user_id}, Error: {api_login_response.text}"
            )

        finish_api_login_response = session.get(
            api_login_response.headers["Location"],
            timeout=10,
            allow_redirects=False,
        )
        if finish_api_login_response.status_code != 302:
            raise Exception(
                f"Error while logging in to kite for user-{user_id}, Error: {finish_api_login_response.text}"
            )

        location_url = finish_api_login_response.headers["Location"]
        query_string = urlparse(location_url).query
        query_dict = dict(param.split("=") for param in query_string.split("&"))
        if "request_token" in query_dict:
            req_token = query_dict["request_token"]
            kite = KiteConnect(api_key=api_key)
            token_res = kite.generate_session(
                req_token, api_secret=api_secret
            )
            Config.PRICEFEED_ACCESS_TOKEN = token_res["access_token"]
            return True

        raise None


def zerodha_login(
    api: Api
):
    user_id = api.creds["user_id"]
    api_key= api.creds["api_key"]
    password = api.creds["password"]
    totp_secret = api.creds["totp_secret"]
    api_secret = api.creds["api_secret"]

    with requests.Session() as session:
        login_payload = {
            "user_id": user_id,
            "password": password,
        }
        login_response = session.post(
            KITE_LOGIN_URL, data=login_payload, timeout=10
        )
        if login_response.status_code != 200:
            raise Exception(
                f"Error while logging in to kite for user-{user_id}, Error: {login_response.text}"
            )
        req_id = login_response.json()["data"]["request_id"]

        twofa_payload = {
            "request_id": req_id,
            "user_id": user_id,
            "twofa_value": pyotp.TOTP(totp_secret).now(),
            "twofa_type": "totp",
        }
        twofa_response = session.post(
            KITE_TWOFA_URL, data=twofa_payload, timeout=10
        )
        if twofa_response.status_code != 200:
            raise Exception(
                f"Error while logging in to kite for user-{user_id}, Error: {twofa_response.text}"
            )

        api_login_response = session.get(
            f"https://kite.zerodha.com/connect/login?v=3&api_key={api_key}",
            timeout=10,
            allow_redirects=False,
        )
        if api_login_response.status_code != 302:
            raise Exception(
                f"Error while logging in to kite for user-{user_id}, Error: {api_login_response.text}"
            )

        finish_api_login_response = session.get(
            api_login_response.headers["Location"],
            timeout=10,
            allow_redirects=False,
        )
        if finish_api_login_response.status_code != 302:
            raise Exception(
                f"Error while logging in to kite for user-{user_id}, Error: {finish_api_login_response.text}"
            )

        location_url = finish_api_login_response.headers["Location"]
        query_string = urlparse(location_url).query
        query_dict = dict(param.split("=") for param in query_string.split("&"))
        if "request_token" in query_dict:
            req_token = query_dict["request_token"]
            kite = KiteConnect(api_key=api_key)
            token_res = kite.generate_session(
                req_token, api_secret=api_secret
            )
            api.creds["access_token"] = token_res["access_token"]
            logger.info(f"Zerodha: {user_id} loggedin successfully.")
            return True

        raise None


def shoonya_login(api: Api):
    user_id = api.creds["user_id"]
    api_key = api.creds["api_key"]
    password = api.creds["password"]
    totp_secret = api.creds["totp_secret"]

    url = "https://api.shoonya.com/NorenWClientTP/QuickAuth"

    password_hash = hashlib.sha256(password.encode("ascii")).hexdigest()
    app_key = user_id + "|" + api_key
    app_key_hash = hashlib.sha256(app_key.encode("ascii")).hexdigest()

    totp = pyotp.TOTP(totp_secret).now()
    payload = {
        "apkversion": "1.0.0",
        "uid": user_id,
        "pwd": password_hash,
        "factor2": totp,
        "vc": f"{user_id}_U",
        "appkey": app_key_hash,
        "imei": "abc1234",
        "source": "API",
    }
    jData = f"jData={json.dumps(payload)}"
    logger.debug(f"Shoonya login payload: {jData}")
    response = requests.post(url, data=jData)
    logger.debug(f"Shoonya login response: {response.text}")
    if response.status_code == 200:
        api.creds["access_token"] = response.json()["susertoken"]
        logger.info(f"Shoonya: {user_id} loggedin successfully.")
    else:
        raise Exception("Not Ok")


def fyres_login(api: Api):
    app_id = api.creds["app_id"]
    app_secret = api.creds["app_secret"]
    auth_code = api.creds.get("auth_code")
    if not auth_code:
        response_type="code"
        grant_type="authorization_code"
        appSession = fyersModel.SessionModel(
            client_id=app_id,
            redirect_uri="https://trade.fyers.in/api-login/redirect-uri/index.html",
            response_type=response_type,
            grant_type=grant_type,
            state="state",scope="",nonce="")
        generateTokenUrl = appSession.generate_authcode()
        webbrowser.open(generateTokenUrl, new=1)
        logger.info(f"Please login to fyers and provide the auth code and paste it into config.json file.")
        exit()
    else:
        appSession = fyersModel.SessionModel(
            client_id=app_id,
            secret_key=app_secret,
            grant_type="authorization_code"
        )
        app_secret
        appSession.set_token(auth_code)
        access_token = appSession.generate_token()
        if "access_token" not in access_token:
            logger.error(f"Fyers login failed, {access_token}, generate new auth code in config.json") 
            api.creds["auth_code"] = None
            fyres_login(api)
        api.creds["access_token"] = access_token["access_token"]
        logger.info(f"Fyers: {app_id} loggedin successfully.")


def groww_login(api: Api):
    groww_get_orderbook(api)
    logger.info(f"Groww: {api.creds['user_id']} loggedin successfully.")


def gopocket_login(api: Api):
    user_id = api.creds["user_id"]
    password = api.creds["password"]
    totp_secret = api.creds["totp_secret"]
    user_phone = api.creds["user_phone"]
    app_code = api.creds["app_code"]
    with requests.Session() as session:
        payload = {
            "userId": str(user_phone)
        }
        user_id_response = session.post(
            "https://web.gopocket.in/am/access/client/verify",
            json=payload
        )
        if user_id_response.status_code == 200 and user_id_response.json()["status"] == "Ok":
            user_id = user_id_response.json()["result"][0]["ucc"]
            api.creds["user_id"] = user_id
        else:
            raise Exception(user_id_response.text)
        payload = {
            "userId": user_id,
            "source": "API",
            "password": password
        }
        login_response = session.post(
            "https://web.gopocket.in/am/access/pwd/validate", 
            json=payload, 
            timeout=10
        )
        if login_response.status_code == 200 and login_response.json()["status"] == "Ok":
            token = login_response.json()["result"][0]['token']
        else:
            raise Exception(login_response.text)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {user_id} API {token}"
        }
        payload = {
            "userId": user_id,
            "source": "API",
            "totp": pyotp.TOTP(totp_secret).now(),
            "vendor": app_code
        }
        twofa_resp = session.post(
            "https://web.gopocket.in/am/access/topt/verify",
            json=payload,
            timeout=10,
            headers=headers,
            allow_redirects=False
        )
        if twofa_resp.status_code == 200 and twofa_resp.json()["status"] == "Ok":
            access_token = twofa_resp.json()["result"][0]["accessToken"]
            api.creds["access_token"] = access_token
            logger.info(f"Gopocket: {api.creds['user_id']} loggedin successfully.")
        else:
            raise Exception(twofa_resp.text)


def fyers_place_order(order: Order, api: Api):
    trading_symbol = get_fyers_tradingsymbol(order.instrument_id)
    url = "https://api-t1.fyers.in/api/v3/orders/sync"
    headers = {
        "Authorization": f"{api.creds['app_id']}:{api.creds['access_token']}"
    }
    logger.debug(f"headers: {headers}")
    payload = {
        "symbol": trading_symbol,
        "qty": order.qty,
        "type": 2 if order.order_type== OrderType.MARKET else None,
        "side": 1 if order.side == Side.BUY else -1,
        "productType": "INTRADAY",
        "limitPrice": 0,
        "stopPrice": 0,
        "validity": "DAY",
        "disclosedQty": 0,
        "offlineOrder": False,
        "stopLoss": 0,
        "takeProfit": 0,
        "orderTag": "OnlyBroker"
    }
    logger.debug(f"Payload: {payload}")
    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=10)
        logger.debug(f"Response: {response.text}")
        if response.status_code == 200 and response.json()["s"] == "ok":
            broker_order_id = response.json()["id"]
            order.broker_order_id = str(broker_order_id)
            order_data = {
                "Broker": api.provider,
                "Order": order
            }
            local_order_update_queue.put(order_data)
            # orders_with_us["FYERS"][order.broker_order_id] = order
            logger.debug(f"Order places with broker id, {broker_order_id}")
        else:
            error_message = response.json()["message"]
            raise Exception(error_message)
    except Exception as ex:
        raise ex


def get_token_symbol(exchange_token: str, exchange_type: str, api: Api):
    if exchange_token in finvasia_tradingsymbol_mapping:
        return finvasia_tradingsymbol_mapping[exchange_token]
    url = "https://api.shoonya.com/NorenWClientTP/GetSecurityInfo"
    payload = {"uid":api.creds["user_id"], "token": exchange_token, "exch": exchange_type}
    jData = f"jData={json.dumps(payload)}"
    jKey = f"jKey={api.creds["access_token"]}"
    data = f"{jData}&{jKey}"
    logger.debug(data)
    response = requests.post(url, data=data)
    logger.debug(f"tysm: {response.text}")
    if response.status_code == 200 and response.json()["stat"] == "Ok":
        finvasia_tradingsymbol_mapping[exchange_token] = response.json()["tsym"]
        return response.json()["tsym"]


def finvasia_place_order(order: Order, api: Api):
    finvasia_instrument = get_instrument(ApiProvider.SHOONYA.name, order.instrument_id)
    exchange_token = get_exchnage_token(order.instrument_id)
    exchange_type = "NFO" if finvasia_instrument.exchange == "NSE" else "BFO"
    tsym = get_token_symbol(exchange_token, exchange_type, api)
    url = "https://api.shoonya.com/NorenWClientTP/PlaceOrder"
    jKey = f"jKey={api.creds["access_token"]}"
    payload = {
        "uid": api.creds["user_id"],
        "actid": api.creds["user_id"],
        "exch": exchange_type,
        "tsym": tsym,
        "qty": str(order.qty),
        "prc": str(0),
        "dscqty": str(0),
        "prd": "M",
        "trantype": "B" if order.side == Side.BUY else "S",
        "prctyp": "MKT",
        "validity": "GTT",
        "ret": "DAY"
    }
    jData = f"jData= {json.dumps(payload)}"
    data = f"{jData}&{jKey}"
    logger.debug(f"Payload: {payload}")
    try:
        response = requests.post(url, data=data, timeout=10)
        logger.debug(response.text)
        if response.status_code == 200 and response.json()["stat"] == "Ok":
            broker_order_id = response.json()["norenordno"]
            order.broker_order_id = broker_order_id
            logger.debug(f"Order places with broker id, {broker_order_id}")
            order_data = {
                "Broker": api.provider,
                "Order": order
            }
            local_order_update_queue.put(order_data)
            # orders_with_us["SHOONYA"][order.broker_order_id] = order
        else:
            error_message = response.json()["emsg"]
            raise Exception(error_message)
    except Exception as ex:
        raise ex


def fyers_get_orderbook(api: Api):
    url = "https://api-t1.fyers.in/api/v3/orders"
    headers = {
        "Authorization": f"{api.creds['app_id']}:{api.creds['access_token']}"
    }
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code == 200 and response.json()["s"] == "ok":
        response_json = response.json()
        broker_orders = response_json["orderBook"]
        for broker_order in broker_orders:
            broker_order_id = broker_order["id"]
            if broker_order_id not in orders_with_us["FYERS"]:
                continue
            order_with_us: Order = orders_with_us["FYERS"][broker_order_id]
            if order_with_us.status in [
                OrderStatus.FILLED,
                OrderStatus.REJECTED,
                OrderStatus.CANCELLED
            ]:
                continue
            order_status = broker_order["status"]
            if order_status == 2:
                order_with_us.status = OrderStatus.FILLED
            if order_status in [1, 5]:
                order_with_us.status = OrderStatus.REJECTED
                order_with_us.error_code = 9017
                order_with_us.error_message = broker_order["message"]
            order_with_us.traded_qty = int(broker_order["filledQty"])
            order_with_us.average_trade_price = float(broker_order["tradedPrice"])
            if order_with_us.status == OrderStatus.FILLED:
                logger.info(f"{order_with_us.status.name} ::: {order_with_us.trading_symbol}@{order_with_us.average_trade_price}, side:{order_with_us.side.name}, qty:{order_with_us.traded_qty}")
                logger.debug(f"{order_with_us.status.name} ::: {order_with_us}")
    else:
        error_message = response.text
        raise Exception(error_message)


def finvasia_get_orderbook(api: Api):
    url = "https://api.shoonya.com/NorenWClientTP/OrderBook"
    jKey = f"jKey={api.creds["access_token"]}"
    payload = {"uid": api.creds["user_id"]}
    jData = f"jData= {json.dumps(payload)}"
    data = f"{jData}&{jKey}"
    logger.debug(f"Payload: {data}")
    response = requests.post(
        url, data=data, timeout=10
    )
    if response.status_code == 200:
        response_json = response.json()
        broker_orders = response_json
        for broker_order in broker_orders:
            if not "norenordno" in broker_order:
                continue
            broker_order_id = str(broker_order["norenordno"])
            if broker_order_id not in orders_with_us["SHOONYA"]:
                continue
            order_with_us: Order = orders_with_us["SHOONYA"][broker_order_id]
            if order_with_us.status in [
                OrderStatus.FILLED,
                OrderStatus.REJECTED,
                OrderStatus.CANCELLED
            ]:
                continue
            order_status = broker_order["status"]
            if order_status == "COMPLETE":
                order_with_us.status = OrderStatus.FILLED
            elif order_status == "REJECTED":
                order_with_us.status = OrderStatus.REJECTED
                order_with_us.error_code = 9017
                order_with_us.error_message = broker_order["rejreason"]
            elif order_status == "CANCELLED":
                order_with_us.status = OrderStatus.CANCELLED
                order_with_us.error_code = 9017
                order_with_us.error_message = broker_order["rejreason"]
            order_type = broker_order["prctyp"]
            if order_type == "MKT":
                order_with_us.order_type = OrderType.MARKET
            if "avgprc" in broker_order:
                order_with_us.average_trade_price = float(broker_order["avgprc"])
            if "fillshares" in broker_order:
                order_with_us.traded_qty = int(broker_order["fillshares"])
            if order_with_us.status == OrderStatus.FILLED:
                logger.info(f"{order_with_us.status.name} ::: {order_with_us.trading_symbol}@{order_with_us.average_trade_price}, side:{order_with_us.side.name}, qty:{order_with_us.traded_qty}")
                logger.debug(f"{order_with_us.status.name} ::: {order_with_us}")
    else:
        error_message = response.json()["emsg"]
        raise Exception(error_message)


def zerodha_place_order(order: Order, api: Api):
    api_key = api.creds["api_key"]
    zerodha_access_token = api.creds["access_token"]
    logger.info(zerodha_access_token)
    url = "https://api.kite.trade/orders/regular"
    headers = {
        "X-Kite-Version": "3",
        "Authorization": f"token {api_key}:{zerodha_access_token}",
    }
    trading_symbol = get_zerodha_tradingsymbol(order.instrument_id)
    zerodha_instrument = get_instrument(ApiProvider.ZERODHA.name, order.instrument_id)
    payload = {
        "tradingsymbol": trading_symbol,
        "exchange": zerodha_instrument.exchange,
        "transaction_type": order.side.name,
        "order_type": order.order_type.name,
        "quantity": order.qty,
        "price": 0,
        "trigger_price": 0,
        "product": "NRML",
        "validity": "DAY",
    }
    logger.debug(f"Place Order: {payload}")
    try:
        response = requests.post(
            url, headers=headers, data=payload, timeout=10
        )
        logger.debug(f"Response: {response.text}")
        if response.status_code == 200 and response.json()["status"] == "success":
            broker_order_id = str(response.json()["data"]["order_id"])
            order.broker_order_id = broker_order_id
            order_data = {
                "Broker": api.provider,
                "Order": order
            }
            local_order_update_queue.put(order_data)
            # orders_with_us["ZERODHA"][order.broker_order_id] = order
            logger.debug(f"Order places with broker id, {broker_order_id}")
        else:
            error_message = response.json()["message"]
            raise Exception(error_message)
    except Exception as ex:
        raise ex


def zerodha_get_orderbook(api: Api):
    api_key = api.creds["api_key"]
    zerodha_access_token = api.creds["access_token"]
    url = "https://api.kite.trade/orders"
    headers = {
        "X-Kite-Version": "3",
        "Authorization": f"token {api_key}:{zerodha_access_token}",
    }
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code == 200 and response.json()["status"] == "success":
        response_json = response.json()
        broker_orders = response_json["data"]
        for broker_order in broker_orders:
            broker_order_id = broker_order["order_id"]
            if broker_order_id not in orders_with_us["ZERODHA"]:
                continue
            order_with_us: Order = orders_with_us["ZERODHA"][broker_order_id]
            order_status = broker_order["status"]
            if order_with_us.status in [OrderStatus.FILLED, OrderStatus.CANCELLED, OrderStatus.REJECTED]:
                continue 
            if order_status == "COMPLETE":
                order_with_us.status = OrderStatus.FILLED
            elif order_status == "REJECTED":
                order_with_us.status = OrderStatus.REJECTED
                order_with_us.error_code = 9017
                order_with_us.error_message = broker_order["status_message_raw"]
            elif order_status == "CANCELLED":
                order_with_us.status = OrderStatus.CANCELLED
                order_with_us.error_code = 9017
                order_with_us.error_message = broker_order["status_message_raw"]
            if "average_price" in broker_order:
                order_with_us.average_trade_price = float(broker_order["average_price"])
            if "filled_quantity" in broker_order:
                order_with_us.traded_qty = int(broker_order["filled_quantity"])
            if order_with_us.status == OrderStatus.FILLED:
                logger.info(f"{order_with_us.status.name} ::: {order_with_us.trading_symbol}@{order_with_us.average_trade_price}, side:{order_with_us.side.name}, qty:{order_with_us.traded_qty}")
                logger.debug(f"{order_with_us.status.name} ::: {order_with_us}")
    else:
        error_message = response.json()["message"]
        raise Exception(error_message)


def groww_place_order(order: Order, api: Api):
    api_key = api.creds["api_key"]
    url = "https://api.groww.in/v1/order/create"
    groww_instrument = get_instrument(ApiProvider.GROWW.name, order.instrument_id)
    groww_tradingsymbol = get_groww_tradingsymbol(order.instrument_id)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    payload = {
        "trading_symbol": groww_tradingsymbol,
        "quantity": order.qty,
        "validity": "DAY",
        "exchange": groww_instrument.exchange,
        "segment": "FNO",
        "product": "NRML",
        "order_type": order.order_type.name,
        "transaction_type": order.side.name,
        "order_reference_id": uuid.uuid4().hex[:20]
    }
    logger.debug(f"Groww Place Order: {payload}")
    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=10)
        logger.debug(f"Groww Response: {response.text}")
        if response.status_code == 200 and response.json()["status"] == "SUCCESS":
            broker_order_id = str(response.json()["payload"]["groww_order_id"])
            order.broker_order_id = broker_order_id
            order_data = {
                "Broker": api.provider,
                "Order": order
            }
            local_order_update_queue.put(order_data)
            # orders_with_us["GROWW"][order.broker_order_id] = order
        else:
            error_message = response.text
            raise Exception(error_message)
    except Exception as ex:
        raise ex


def groww_get_orderbook(api: Api):
    api_key = api.creds["api_key"]
    url = "https://api.groww.in/v1/order/list"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code == 200 and response.json()["status"] == "SUCCESS":
        response_json = response.json()
        broker_orders = response_json["payload"]["order_list"]
        for broker_order in broker_orders:
            broker_order_id = str(broker_order["groww_order_id"])
            if broker_order_id not in orders_with_us["GROWW"]:
                continue
            order_with_us: Order = orders_with_us["GROWW"][broker_order_id]
            if order_with_us.status in [OrderStatus.FILLED, OrderStatus.CANCELLED, OrderStatus.REJECTED]:
                continue
            order_status = broker_order["order_status"]
            if order_status in ["COMPLETE", "EXECUTED"]:
                order_with_us.status = OrderStatus.FILLED
            if order_status in ["REJECTED", "CANCELLED", "FAILED"]:
                order_with_us.status = OrderStatus.REJECTED
                order_with_us.error_code = 9017
                order_with_us.error_message = str(broker_order["remark"]).replace("₹", "Rs.")
            if "filled_quantity" in broker_order:
                order_with_us.traded_qty = int(broker_order["filled_quantity"])
            if "average_fill_price" in broker_order:
                order_with_us.average_trade_price = float(broker_order["average_fill_price"])
            if order_with_us.status == OrderStatus.FILLED:
                logger.info(f"{order_with_us.status.name} ::: {order_with_us.trading_symbol}@{order_with_us.average_trade_price}, side:{order_with_us.side.name}, qty:{order_with_us.traded_qty}")
                logger.debug(f"{order_with_us.status.name} ::: {order_with_us}")
    else:
        error_message = response.text
        # logger.warning(f"fetch order book warning: {error_message}")
        raise Exception(error_message)


def gopocket_place_order(order: Order, api: Api):
    base_url = "https://web.gopocket.in/"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + api.creds["access_token"]
    }
    instrument = get_instrument(ApiProvider.ZERODHA.name, order.instrument_id)
    gopocket_tradingsymbol = get_gopocket_tradingsymbol(order.instrument_id)
    payload = [{
        "exchange": instrument.exchange,
        "tradingSymbol": gopocket_tradingsymbol,
        "qty": str(order.qty),
        "price": "0",
        "product": "NRML",
        "transType": "B" if order.side == Side.BUY else "S",
        "priceType": "MKt",
        "orderType": "Regular",
        "ret": "DAY",
        "source":"API"
    }]
    response = requests.post(base_url + "od-rest/orders/execute", headers=headers, data=json.dumps(payload))
    if response.status_code == 200 and response.json()[0]["status"] == "Ok":
        broker_order_id = response.json()[0]["result"][0]["orderNo"]
        order.broker_order_id = str(broker_order_id)
        order_data = {
            "Broker": api.provider,
            "Order": order
        }
        local_order_update_queue.put(order_data)
        # orders_with_us["GOPOCKET"][order.broker_order_id] = order
    else:
        error_message = response.text
        raise Exception(error_message)


def gopocket_get_orderbook(api: Api):
    base_url = "https://web.gopocket.in/"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + api.creds["access_token"]
    }
    response = requests.get(base_url + "od-rest/info/orderbook", headers=headers)
    if response.status_code == 200 and response.json()["status"] == "Ok":
        response_json = response.json()
        broker_orders = response_json["result"]
        for broker_order in broker_orders:
            broker_order_id = str(broker_order["orderNo"])
            if broker_order_id not in orders_with_us["GOPOCKET"]:
                continue
            order_with_us: Order = orders_with_us["GOPOCKET"][broker_order_id]
            if order_with_us.status in [OrderStatus.FILLED, OrderStatus.CANCELLED, OrderStatus.REJECTED]:
                continue
            order_status = broker_order["orderStatus"]
            if order_status in ["REJECTED", "CANCELLED"]:
                order_with_us.status = OrderStatus.REJECTED
                order_with_us.error_code = 9017
                order_with_us.error_message = broker_order["rejectedReason"]
            if order_status in ["COMPLETE", "EXECUTED"]:
                order_with_us.status = OrderStatus.FILLED
            if "fillShares" in broker_order:
                order_with_us.traded_qty = int(broker_order["fillShares"])
            if "avgTradePrice" in broker_order:
                if broker_order["avgTradePrice"]:
                    order_with_us.average_trade_price = float(broker_order["avgTradePrice"])
            if order_with_us.status == OrderStatus.FILLED:
                logger.info(f"{order_with_us.status.name} ::: {order_with_us.trading_symbol}@{order_with_us.average_trade_price}, side:{order_with_us.side.name}, qty:{order_with_us.traded_qty}")
                logger.debug(f"{order_with_us.status.name} ::: {order_with_us}")
    else:
        error_message = response.text
        raise Exception(error_message)


def dummy_place_order(order: Order):
    order.broker_order_id = uuid.uuid4().hex
    order.status = OrderStatus.WORKING
    order_data = {
        "Broker": ApiProvider.DUMMY,
        "Order": order
    }
    local_order_update_queue.put(order_data)
    # orders_with_us["DUMMY"][order.broker_order_id] = order


def dummy_get_orderbook():
    for order in orders_with_us["DUMMY"].values():
        order: Order
        if order.status in [OrderStatus.CANCELLED, OrderStatus.FILLED]:
            continue
        ltp = pricefeed.get_ltp(order.instrument_id)
        order.average_trade_price = ltp
        order.traded_qty = order.qty
        order.status = OrderStatus.FILLED
        logger.info(f"{order.status.name}: {order.trading_symbol}@{order.average_trade_price} qty:{order.traded_qty}")


def sync_local_orders():
    while True:
        if local_order_update_queue.empty():
            return
        order_data = local_order_update_queue.get(block=False)
        api_provider: ApiProvider = order_data["Broker"]
        order: Order = order_data["Order"]
        orders_with_us[api_provider.name][order.broker_order_id] = order


def sync_position(position: Position, api: Api):
    net_buy_qty = 0
    net_sell_qty = 0
    buy_prices = []
    buy_quantities = []
    sell_pricess = []
    sell_quantities = []
    orders = [position.entry_order, position.exit_order]
    borker_name = api.provider.name
    for order in orders:
        if not order:
            continue
        for child_order in order.child_orders.values():
            if child_order.broker_order_id in orders_with_us[borker_name]:
                broker_order: Order = orders_with_us[borker_name][child_order.broker_order_id]
                child_order.traded_qty = broker_order.traded_qty
                child_order.average_trade_price = broker_order.average_trade_price
                child_order.broker_order_id = broker_order.broker_order_id
                child_order.status = broker_order.status
                child_order.trigger_price = broker_order.trigger_price
                if child_order.side == Side.BUY:
                    net_buy_qty += child_order.traded_qty
                    buy_quantities.append(child_order.traded_qty)
                    buy_prices.append(child_order.average_trade_price)
                else:
                    net_sell_qty += child_order.traded_qty
                    sell_quantities.append(child_order.traded_qty)
                    sell_pricess.append(child_order.average_trade_price)
                child_order.status = broker_order.status
                if child_order.status in [OrderStatus.REJECTED]:
                    logger.debug(f"{child_order.status} :: {order}")
                    position.status = PositionStatus.ERROR
                    child_order.error_code = broker_order.error_code
                    child_order.error_message = broker_order.error_message
                    raise Exception(
                        f"Order {child_order.broker_order_id} rejected with {child_order.error_message}"
                    )
        if order.child_orders and all(
            child_order.status in [OrderStatus.FILLED]
            for child_order in order.child_orders.values()
        ):
            order.status = OrderStatus.FILLED
        if order.child_orders and all(
            child_order.status in [OrderStatus.CANCELLED]
            for child_order in order.child_orders.values()
        ):
            order.status = OrderStatus.CANCELLED

    if (
        net_buy_qty == position.net_buy_quantity
        and net_sell_qty == position.net_sell_quantity
    ):
        if buy_prices:
            position.buy_average_price = sum([buy_prices[i]*buy_quantities[i] for i in range(len(buy_prices))])/sum(buy_quantities)
        if sell_pricess:
            position.sell_average_price = sum([sell_pricess[i]*sell_quantities[i] for i in range(len(sell_pricess))])/sum(sell_quantities)
        position.buy_value = position.buy_average_price * position.net_buy_quantity
        position.sell_value = position.sell_average_price * position.net_sell_quantity
        position.net_quantity = net_buy_qty - net_sell_qty
        position.status = PositionStatus.COMPLETE


def place_order(order: Order, lot_size: int, freeze_qty: int, api: Api):
    try:
        logger.info(f"Placing Order for {order.trading_symbol} id: {order.id}")
        logger.debug(f"Placing Order: {order}")
        slice_order(order, lot_size, freeze_qty)
        placed_child_orders: List[Order] = []
        for child_order in order.child_orders.values(): 
            if api.provider == ApiProvider.SHOONYA:
                finvasia_place_order(child_order, api)
                placed_child_orders.append(child_order)
            elif api.provider == ApiProvider.ZERODHA:
                zerodha_place_order(child_order, api)
                placed_child_orders.append(child_order)
            elif api.provider == ApiProvider.FYERS:
                fyers_place_order(child_order, api)
                placed_child_orders.append(child_order)
            elif api.provider == ApiProvider.GROWW:
                groww_place_order(child_order, api)
                placed_child_orders.append(child_order)
            elif api.provider == ApiProvider.GOPOCKET:
                gopocket_place_order(child_order, api)
                placed_child_orders.append(child_order)
            elif api.provider == ApiProvider.DUMMY:
                dummy_place_order(child_order)
                placed_child_orders.append(child_order)
            else:
                raise Exception(f"{api.provider} is not supported")
        order.child_orders.clear()
        for placed_child_order in placed_child_orders:
            order.child_orders[placed_child_order.broker_order_id] = placed_child_order
    except Exception as ex:
        logger.debug(f"Error in placing order", exc_info=True)
        raise ex


def place_order_on_thread(order: Order, lot_size: int, freeze_qty: int, api: Api):
    thread = threading.Thread(target=place_order, args=(order, lot_size, freeze_qty, api))
    thread.start()
    return thread


def get_broker_orderbook(api: Api, broker_user_id: str):
    try:
        sync_local_orders()
        if api.provider == ApiProvider.SHOONYA:
            try:
                finvasia_get_orderbook(api)
            except Exception as ex:
                if isinstance(ex, KeyboardInterrupt):
                    raise ex
                logger.warning(f"user_id: {broker_user_id} - Error in getting pending orderbook.")
                logger.debug(f"user_id: {broker_user_id} - Error in getting pending orderbook.", exc_info=True)
        elif api.provider == ApiProvider.ZERODHA:
            try:
                zerodha_get_orderbook(api)
            except Exception as ex:
                if isinstance(ex, KeyboardInterrupt):
                    raise ex
                logger.warning(f"user_id: {broker_user_id} - Error in getting pending orderbook.")
                logger.debug(f"user_id: {broker_user_id} - Error in getting pending orderbook.", exc_info=True)
        elif api.provider == ApiProvider.FYERS:
            try:
                fyers_get_orderbook(api)
            except Exception as ex:
                if isinstance(ex, KeyboardInterrupt):
                    raise ex
                logger.warning(f"user_id: {broker_user_id} - Error in getting pending orderbook.")
                logger.debug(f"user_id: {broker_user_id} - Error in getting pending orderbook.", exc_info=True)
        elif api.provider == ApiProvider.GROWW:
            try:
                groww_get_orderbook(api)
            except Exception as ex:
                if isinstance(ex, KeyboardInterrupt):
                    raise ex
                logger.warning(f"user_id: {broker_user_id} - Error in getting pending orderbook.", exc_info=True)
                logger.debug(f"user_id: {broker_user_id} - Error in getting pending orderbook.", exc_info=True)
        elif api.provider == ApiProvider.GOPOCKET:
            try:
                gopocket_get_orderbook(api)
            except Exception as ex:
                if isinstance(ex, KeyboardInterrupt):
                    raise ex
                logger.warning(f"user_id: {broker_user_id} - Error in getting pending orderbook.")
                logger.debug(f"user_id: {broker_user_id} - Error in getting pending orderbook.", exc_info=True)
        elif api.provider == ApiProvider.DUMMY:
            dummy_get_orderbook()
        else:
            raise Exception(f"{api.provider} is not supported")
    except Exception as ex:
        logger.debug(f"user_id: {broker_user_id} - Error in getting orderbook", exc_info=True)
        raise ex
