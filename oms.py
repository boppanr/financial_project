from copy import deepcopy
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
from config import Config
from instruments import get_exchnage_token, get_instrument
from models import Order, Position
import pricefeed


logger = logging.getLogger(__name__)

KITE_LOGIN_URL="https://kite.zerodha.com/api/login"
KITE_TWOFA_URL="https://kite.zerodha.com/api/twofa"

creds = {broker: {} for broker in AVAILABLE_BROKERS}
orders_with_us = {broker: {} for broker in AVAILABLE_BROKERS}


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


def zerodha_login(
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


def fyers_login(): ...


def fyers_place_gtt_order(order: Order):
    url = "https://api-t1.fyers.in/api/v3/gtt/orders/sync"
    headers = {"Content-Type": "application/json", "Authorization": Config.ACCESS_TOKEN}
    side = 1 if order.side == Side.BUY else -1
    instrument = get_instrument(ApiProvider.FYERS.name, order.instrument_id)
    payload = {
        "side": side,  # 1,
        "symbol": instrument.instrument_id,  # "NSE:SBIN-EQ",
        "productType": "CNC",
        "orderInfo": {
            "leg1": {
                "price": order.limit_price,
                "triggerPrice": order.trigger_price,
                "qty": order.qty,
            }
        },
    }
    response = requests.post(url, headers=headers, json=payload, timeout=10)
    ## TODO handle response


def shoonya_login(user_id: str, api_key: str, password: str, totp_secret: str):
    creds[ApiProvider.SHOONYA.name]["user_id"] = user_id
    creds[ApiProvider.SHOONYA.name]["api_key"] = api_key
    creds[ApiProvider.SHOONYA.name]["password"] = password
    creds[ApiProvider.SHOONYA.name]["totp_secret"] = totp_secret

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

    try:
        response = requests.post(url, data=jData)
        if response.status_code == 200:
            creds[ApiProvider.SHOONYA.name]["access_token"] = response.json()["susertoken"]
            logger.info(f"Shoonya loggedin successfully.")
        else:
            raise Exception("Not Ok")
    except Exception as ex:
        logger.exception(f"Shoonya login failed, {ex}")


def get_token_symbol(exchange_token: str, exchange_type: str):
    url = "https://api.shoonya.com/NorenWClientTP/GetSecurityInfo"
    payload = {"uid":creds[ApiProvider.SHOONYA.name]["user_id"], "token": exchange_token, "exch": exchange_type}
    jData = f"jData={json.dumps(payload)}"
    jKey = f"jKey={creds[ApiProvider.SHOONYA.name]['access_token']}"
    data = f"{jData}&{jKey}"
    logger.debug(data)
    response = requests.post(url, data=data)
    logger.debug(f"tysm: {response.text}")
    if response.status_code == 200 and response.json()["stat"] == "Ok":
        return response.json()["tsym"]


def finvasia_place_order(order: Order):
    finvasia_instrument = get_instrument(ApiProvider.SHOONYA.name, order.instrument_id)
    exchange_token = get_exchnage_token(order.instrument_id)
    exchange_type = "NFO" if finvasia_instrument.exchange == "NSE" else "BFO"
    tsym = get_token_symbol(exchange_token, exchange_type)
    url = "https://api.shoonya.com/NorenWClientTP/PlaceOrder"
    jKey = f"jKey={creds[ApiProvider.SHOONYA.name]['access_token']}"
    payload = {
        "uid": creds[ApiProvider.SHOONYA.name]["user_id"],
        "actid": creds[ApiProvider.SHOONYA.name]["user_id"],
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
            orders_with_us["SHOONYA"][order.broker_order_id] = order
        else:
            error_message = response.json()["emsg"]
            raise Exception(error_message)
    except Exception as ex:
        raise ex


def finvasia_get_orderbook():
    url = "https://api.shoonya.com/NorenWClientTP/OrderBook"
    jKey = f"jKey={creds[ApiProvider.SHOONYA.name]['access_token']}"
    payload = {"uid": creds[ApiProvider.SHOONYA.name]["user_id"]}
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
        logger.warning(f"fetch order book warning: {error_message}")


def dummy_place_order(order: Order):
    order.broker_order_id = uuid.uuid4().hex
    order.status = OrderStatus.WORKING
    orders_with_us["DUMMY"][order.broker_order_id] = order


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


def sync_position(position: Position):
    net_buy_qty = 0
    net_sell_qty = 0
    buy_prices = []
    buy_quantities = []
    sell_pricess = []
    sell_quantities = []
    orders = [position.entry_order, position.exit_order]
    borker_name = Config.API.provider.name
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
        logger.debug(f"{position.instrument_id}::Buy prices={buy_prices}, Buy quantities={buy_quantities}, Sell prices={sell_pricess}, Sell quantities={sell_quantities}")
        position.buy_value = position.buy_average_price * position.net_buy_quantity
        position.sell_value = position.sell_average_price * position.net_sell_quantity
        position.net_quantity = net_buy_qty - net_sell_qty
        position.status = PositionStatus.COMPLETE
    else:
        logger.debug(f"instrument_id={position.trading_symbol}, position_net_buy_qty={position.net_buy_quantity}, net_buy_qty={net_buy_qty}, position_net_sell_qty={position.net_sell_quantity}, net_sell_qty={net_sell_qty}")


def place_order(order: Order, lot_size: int, freeze_qty: int):
    try:
        logger.info(f"Placing Order for {order.trading_symbol} id: {order.id}")
        logger.debug(f"Placing Order: {order}")
        slice_order(order, lot_size, freeze_qty)
        placed_child_orders: List[Order] = []
        for child_order in order.child_orders.values(): 
            if Config.API.provider == ApiProvider.SHOONYA:
                finvasia_place_order(child_order)
                placed_child_orders.append(child_order)
            elif Config.API.provider == ApiProvider.DUMMY:
                dummy_place_order(child_order)
                placed_child_orders.append(child_order)
            else:
                raise Exception(f"{Config.API.provider} is not supported")
        order.child_orders.clear()
        for placed_child_order in placed_child_orders:
            order.child_orders[placed_child_order.broker_order_id] = placed_child_order
    except Exception as ex:
        logger.debug(f"Error in placing order", exc_info=True)
        raise ex


def get_broker_orderbook():
    try:
        if Config.API.provider == ApiProvider.SHOONYA:
            try:
                finvasia_get_orderbook()
            except:
                logger.warning(f"Error in getting pending orderbook.")
                logger.debug(f"Error in getting pending orderbook.", exc_info=True)
        elif Config.API.provider == ApiProvider.DUMMY:
            dummy_get_orderbook()
        else:
            raise Exception(f"{Config.API.provider} is not supported")
    except Exception as ex:
        logger.debug(f"Error in getting orderbook", exc_info=True)
        raise ex
