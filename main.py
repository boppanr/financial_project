import watchtower
import os
from queue import Queue
import logging
import logging.config
import uuid
import pytz
import datetime 
import time
from constants import FREEZE_QTY, LOT_SIZE, INDEXS, STRIKE_DIFF
from enums import ApiProvider, OrderStatus, OrderType, Side, StrategyStatus
from config import Config, Strategy
from instruments import generate_trading_symbol, get_expiry, get_instruent_token_from_name, load_instruments, underlying_instruments
from oms import (
    fyers_login,
    #groww_login,
    place_order,
    get_broker_orderbook,
    sync_position, 
    zerodha_login, 
    shoonya_login
    #zerodha_pricefeed_login
)
from models import Order, Position
from pricefeed import PricePkt, Pricefeed, get_high_low_historical_data, get_ltp
from utils import get_alloted_fund, get_time_frame_stamps
from copy import deepcopy
from config import Config


logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(watchtower.CloudWatchLogHandler(log_group="financial_project_logs"))

class MyFilter(logging.Filter):
    def __init__(self, filter_msg):
        super(MyFilter, self).__init__()

        self.filter_msg = filter_msg

    def filter(self, record):
        """
        :param record: LogRecord Object
        :return True to accept record, False to drop record
        """

        # if record.levelname == 'INFO':
        #     return False
        # else:
        #     record.msg += self.filter_msg
        return True

pricefeed_queue = Queue()

def mround(value, round_to):
    return round_to * round(value / round_to)


def round_to(n, precision):
    correction = 0.5 if n >= 0 else -0.5
    return int(n / (precision) + correction) * precision


def get_strike(ltp: float, strike_diff: int):
    return int(round_to(ltp, strike_diff))


def get_buffer_price(price: float, buffer_price_percentage: float):
    raw_buffer_price = (price*buffer_price_percentage)/100
    return mround(raw_buffer_price, 0.05)


def calculate_entry_price(high: float):
    if high >= 250:
        return round(mround(high + (high * 7 / 100), 0.05), 4)
    else:
        return round(mround(high + (high * 12 / 100), 0.05), 4)


def calculate_stoploss_price(entry, stop_loss: float):
    return round(mround(entry - (entry * stop_loss / 100), 0.05), 4)


def calculate_target_price(entry, profit_target: float):
    return round(mround(entry + (entry * profit_target / 100), 0.05), 4)


def all_position_completed(strategy: Strategy):
    for position in strategy.running_positions+strategy.archived_positons:
        for order in [position.entry_order, position.exit_order]:
            if order and order.status in [
                OrderStatus.TRIGGER_PENDING,
                OrderStatus.WORKING, 
                OrderStatus.OPEN
            ]:
                logger.debug(f"user_id: {strategy.broker_user_id} - {order.id} :: {order.trading_symbol} :: {order.status.name}")
                return False
    return True


def sq_off_all(strategy: Strategy):
    archived_positions = []
    for position in strategy.running_positions:
        entry_order = position.entry_order
        exit_order = position.exit_order
        if entry_order.status == OrderStatus.TRIGGER_PENDING:
            entry_order.status = OrderStatus.CANCELLED
            logger.info(f"user_id: {strategy.broker_user_id} - {entry_order.trading_symbol} {entry_order.id} is {entry_order.status.name}")
            position.net_buy_quantity -= entry_order.qty
        if (
            entry_order.status == OrderStatus.FILLED and 
            not exit_order
        ):
            exit_order = Order(
                uuid.uuid4().hex,
                position.instrument_id,
                position.trading_symbol,
                position.net_buy_quantity,
                Side.SELL,
                OrderType.MARKET,
                0
            )
            position.exit_order = exit_order
            place_order(position.exit_order, position.lot_size, position.freeze_qty, strategy.api)
            position.net_sell_quantity += position.exit_order.qty
        archived_positions.append(position)
    
    for archived_position in archived_positions:
        strategy.running_positions.remove(archived_position)
        strategy.archived_positons.append(archived_position)

    strategy.status = StrategyStatus.SQUARING_OFF


def main(config_data=None):
    # Use the config_data passed from the service, or load from local if not provided
    if config_data:
        Config.config_json = config_data
        print("=== MAIN FUNCTION STARTED ===")
        print("Received config from service:")
        print(config_data)
        print("=== CONFIG LOADED FROM SERVICE ===")
    else:
        # Fallback to local config loading if no config_data is passed
        print("=== MAIN FUNCTION STARTED ===")
        print("No config data passed, using local configuration")
        print("=== USING LOCAL CONFIG ===")
    
    load_instruments()

    zerodha_pricefeed_login(
        Config.PRICEFEED_CREDS["user_id"],
        Config.PRICEFEED_CREDS["password"],
        Config.PRICEFEED_CREDS["totp_secret"],
        Config.PRICEFEED_CREDS["api_key"],
        Config.PRICEFEED_CREDS["api_secret"],
    )
    pricefeed = Pricefeed(
        api_key=Config.PRICEFEED_CREDS["api_key"], 
        access_token=Config.PRICEFEED_ACCESS_TOKEN,
        price_queue=pricefeed_queue
    )
    pricefeed.connect()
    for strategy in Config.STRATEGY_LIST:
        try:
            if strategy.api.provider == ApiProvider.ZERODHA:
                zerodha_login(strategy.api)
                strategy.broker_user_id = strategy.api.creds["user_id"]
            elif strategy.api.provider == ApiProvider.SHOONYA:
                shoonya_login(strategy.api)
                strategy.broker_user_id = strategy.api.creds["user_id"]
            elif strategy.api.provider == ApiProvider.FYERS:
                fyres_login(strategy.api)
                strategy.broker_user_id = strategy.api.creds["app_id"]
            elif strategy.api.provider == ApiProvider.GROWW:
                groww_login(strategy.api)
                strategy.broker_user_id = strategy.api.creds["user_id"]
            elif strategy.api.provider == ApiProvider.DUMMY:
                strategy.broker_user_id = strategy.api.creds["user_id"]
            strategy.status = StrategyStatus.RUNNING
        except Exception as ex:
            logger.critical(f"Error while login in {strategy.api.provider.name}, config: {strategy.api.creds}")
            logger.debug(f"Error while login in {strategy.api.provider.name}", exc_info=True)
            strategy.status = StrategyStatus.ERROR
            return
        timeframe_stamps = get_time_frame_stamps(interval=strategy.check_candle)
        strategy.timeframe_stamps = timeframe_stamps
    logger.info(f"========= Next check-time: {timeframe_stamps[0].strftime("%H:%M:%S")} =========")
    while True:
        try:
            tick: PricePkt = pricefeed_queue.get()
            if not tick:
                time.sleep(0.5)
                continue
            for strategy in Config.STRATEGY_LIST:
                try:
                    if strategy.status not in [
                        StrategyStatus.SQUARED_OFF,
                        StrategyStatus.ERROR,
                        StrategyStatus.SQUARING_OFF,
                    ]:
                        current_time = datetime.datetime.now(pytz.timezone("Asia/Kolkata")).replace(
                            microsecond=0
                        ).time()
                        if current_time >= strategy.strategy_end_time:
                            logger.info("Strategy time is over")
                            sq_off_all(strategy)
                            continue
                        if current_time >= strategy.timeframe_stamps[0]:
                            check_time = strategy.timeframe_stamps.pop(0)
                            logger.info(f"==============================================")
                            for position in strategy.running_positions + strategy.archived_positons:
                                if position:
                                    sync_position(position, strategy.api)
                            for underlying_token, underlying_instrument in underlying_instruments.items():
                                take_call_entry = True
                                take_put_entry = True
                                if INDEXS[underlying_instrument.trading_symbol].lower() not in strategy.fund_allocations:
                                    continue
                                if strategy.running_positions:
                                    if not [position.entry_order for position in strategy.running_positions
                                        if position.underlying_token == underlying_token]:
                                        logger.debug(f"No entry orders for {underlying_instrument.trading_symbol}")
                                    elif any(
                                        position.entry_order.status in [OrderStatus.TRIGGER_PENDING]
                                        for position in strategy.running_positions
                                        if position.underlying_token == underlying_token
                                    ):
                                        archived_positions = []
                                        for position in strategy.running_positions:
                                            if position.underlying_token == underlying_token:
                                                order = position.entry_order
                                                if order.status == OrderStatus.TRIGGER_PENDING:
                                                    order.status = OrderStatus.CANCELLED
                                                    logger.info(f"{order.trading_symbol} {order.id} is {order.status.name}")
                                                    position.net_buy_quantity -= order.qty
                                                    archived_positions.append(position)
                                                elif order.status == OrderStatus.FILLED:
                                                    if "CE" in position.trading_symbol:
                                                        take_call_entry = False
                                                        logger.info(f"user_id: {strategy.broker_user_id} - Running Call Position for {underlying_instrument.trading_symbol} not taking new entry.")
                                                    if "PE" in position.trading_symbol:
                                                        take_put_entry = False
                                                        logger.info(f"user_id: {strategy.broker_user_id} - Running Put Position for {underlying_instrument.trading_symbol} not taking new entry.")
                                                    continue
                                        for archive_position in archived_positions:
                                            strategy.running_positions.remove(archive_position)
                                            strategy.archived_positons.append(archive_position)
                                    else:
                                        logger.info(f"user_id: {strategy.broker_user_id} - Running Call and Put positions for {underlying_instrument.trading_symbol} not taking new entry.")
                                        continue
                                underlying_name = INDEXS[underlying_instrument.trading_symbol]
                                lot_size = LOT_SIZE[underlying_name]
                                index_high, index_low = get_high_low_historical_data(underlying_token, strategy.check_candle, check_time)
                                if not index_high or not index_low:
                                    logger.warning(f"user_id: {strategy.broker_user_id} - No high low found for: {underlying_name}")
                                    continue
                                high_spot = index_high + (strategy.strike_buffer_precentage*index_high)/100
                                strike_diff = STRIKE_DIFF[underlying_name]
                                high_strike = get_strike(high_spot, strike_diff)
                                low_spot = index_low - (strategy.strike_buffer_precentage*index_low)/100
                                low_strike = get_strike(low_spot, strike_diff)
                                alloted_fund = get_alloted_fund(underlying_instrument.trading_symbol, strategy)
                                quantity = alloted_fund // lot_size
                                if quantity <= 0:
                                    logger.warning(f"user_id: {strategy.broker_user_id} - Insufficient alloted fund for: {underlying_name}. skipping")
                                    continue
                                expiry = get_expiry(underlying_name, "WEEKLY")
                                freeze_qty = FREEZE_QTY[underlying_name]["WEEKLY"]
                                exchange = "NFO"
                                if underlying_name in ["SENSEX", "BANKEX"]:
                                    exchange = "BFO"
                                call_symbol = generate_trading_symbol(
                                    exchange,
                                    underlying_name,
                                    "OPTIDX",
                                    expiry,
                                    high_strike,
                                    "CE",
                                )
                                call_token = get_instruent_token_from_name(call_symbol)
                                put_symbol = generate_trading_symbol(
                                    exchange,
                                    underlying_name,
                                    "OPTIDX",
                                    expiry,
                                    low_strike,
                                    "PE",
                                )
                                put_token = get_instruent_token_from_name(put_symbol)
                                option_high_ce, _ = get_high_low_historical_data(call_token, strategy.check_candle, check_time)
                                option_high_pe, _ = get_high_low_historical_data(put_token, strategy.check_candle, check_time)

                                if not option_high_ce and take_call_entry:
                                    logger.warning(f"user_id: {strategy.broker_user_id} - High not found for: {call_symbol}")
                                    continue
                                
                                if not option_high_pe and take_put_entry:
                                    logger.warning(f"user_id: {strategy.broker_user_id} - High not found for: {put_symbol}")
                                    continue

                                call_entry_price = calculate_entry_price(option_high_ce)
                                put_entry_price = calculate_entry_price(option_high_pe)

                                call_quantity = lot_size*int(alloted_fund // (call_entry_price*lot_size))
                                put_quantity = lot_size*int(alloted_fund // (put_entry_price*lot_size))
                                if call_quantity <= 0 and take_call_entry:
                                    logger.warning(f"user_id: {strategy.broker_user_id} - {call_symbol} qty is: {call_quantity}, skiping entry")
                                    continue
                                if put_quantity <= 0 and take_put_entry:
                                    logger.warning(f"user_id: {strategy.broker_user_id} - {put_symbol} qty is: {put_quantity}, skiping entry")
                                    continue
                                
                                if take_call_entry:
                                    logger.info(f"user_id: {strategy.broker_user_id} - {underlying_name}: CE({call_symbol}): High={option_high_ce}, Entry={call_entry_price}, Qty={call_quantity}")
                                    call_order = Order(
                                        uuid.uuid4().hex,
                                        call_token,
                                        call_symbol,
                                        call_quantity,
                                        Side.BUY,
                                        OrderType.MARKET,
                                        call_entry_price
                                    )
                                    call_positon = Position(
                                        call_order.id, 
                                        call_order.instrument_id, 
                                        call_order.trading_symbol, 
                                        underlying_token,
                                        strategy.profit_target, 
                                        strategy.stop_loss, 
                                        deepcopy(strategy.trailings),
                                        lot_size,
                                        freeze_qty
                                    )
                                    call_order.status = OrderStatus.TRIGGER_PENDING
                                    call_positon.entry_order = call_order
                                    call_positon.net_buy_quantity += call_order.qty
                                    strategy.running_positions.append(call_positon)
                                    logger.info(f"user_id: {strategy.broker_user_id} - Trigger order placed for: {call_positon.trading_symbol}, Side:{call_order.side.name}, Qty: {call_order.qty}")

                                if take_put_entry:
                                    logger.info(f"user_id: {strategy.broker_user_id} - {underlying_name}: PE({put_symbol}): High={option_high_pe}, Entry={put_entry_price}, Qty={put_quantity}")
                                    put_order = Order(
                                        uuid.uuid4().hex,
                                        put_token,
                                        put_symbol,
                                        put_quantity,
                                        Side.BUY,
                                        OrderType.MARKET,
                                        put_entry_price
                                    )
                                    put_positon = Position(
                                        put_order.id, 
                                        put_order.instrument_id, 
                                        put_order.trading_symbol, 
                                        underlying_token,
                                        strategy.profit_target, 
                                        strategy.stop_loss, 
                                        deepcopy(strategy.trailings),
                                        lot_size,
                                        freeze_qty
                                    )
                                    put_order.status = OrderStatus.TRIGGER_PENDING
                                    put_positon.entry_order = put_order
                                    put_positon.net_buy_quantity += put_order.qty
                                    strategy.running_positions.append(put_positon)
                                    logger.info(f"user_id: {strategy.broker_user_id} - Trigger order placed for: {put_positon.trading_symbol}, Side:{put_order.side.name}, Qty: {put_order.qty}")
                            logger.info(f"========= Next check-time: {strategy.timeframe_stamps[0].strftime("%H:%M:%S")} =========")
                        positions_to_archive = []
                        for position in strategy.running_positions:
                            if position.entry_order.status == OrderStatus.TRIGGER_PENDING:
                                if tick.instrument_token == position.instrument_id:
                                    order = position.entry_order
                                    if order.side == Side.BUY:
                                        if tick.ltp >= order.trigger_price:
                                            logger.info(f"user_id: {strategy.broker_user_id} - {order.trading_symbol} Order Triggered ::: ltp: {tick.ltp} >= trigger_price: {order.trigger_price}")
                                            order.status = OrderStatus.WORKING
                                            place_order(order, position.lot_size, position.freeze_qty, strategy.api)    
                                    else:
                                        if tick.ltp <= order.trigger_price:
                                            logger.info(f"user_id: {strategy.broker_user_id} - {order.trading_symbol} Order Triggered ::: ltp: {tick.ltp} <= trigger_price: {order.trigger_price}")
                                            order.status = OrderStatus.WORKING
                                            place_order(order, position.lot_size, position.freeze_qty, strategy.api)
                            if position.exit_order and position.exit_order.status in [OrderStatus.FILLED]:
                                positions_to_archive.append(position)
                                continue
                            if position.entry_order.status == OrderStatus.FILLED and not position.exit_order:
                                if not position.stoploss_price and not position.target_price:
                                    position.stoploss_price = calculate_stoploss_price(position.buy_average_price, position.stop_loss)
                                    position.target_price = calculate_target_price(position.buy_average_price, position.take_profit)
                                    logger.info(f"user_id: {strategy.broker_user_id} - {position.trading_symbol}, Avg Buy Price: {position.buy_average_price}, StopLoss Price: {position.stoploss_price}, ProfitTarget Price: {position.target_price}")
                                if tick.instrument_token == position.instrument_id:
                                    if tick.ltp <= position.stoploss_price:
                                        logger.info(f"user_id: {strategy.broker_user_id} - {position.trading_symbol}, StopLoss Hit ::: Ltp:{tick.ltp} <= StopLoss Price: {position.stoploss_price}")
                                        exit_order = Order(
                                            uuid.uuid4().hex,
                                            position.instrument_id,
                                            position.trading_symbol,
                                            position.net_buy_quantity,
                                            Side.SELL,
                                            OrderType.MARKET,
                                            0
                                        )
                                        position.exit_order = exit_order
                                        place_order(position.exit_order, position.lot_size, position.freeze_qty, strategy.api)
                                        position.net_sell_quantity += position.exit_order.qty
                                        continue
                                    if tick.ltp >= position.target_price:
                                        logger.info(f"user_id: {strategy.broker_user_id} - {position.trading_symbol}, Target Hit ::: Ltp:{tick.ltp} >= TakeProfit Price: {position.target_price}")
                                        exit_order = Order(
                                            uuid.uuid4().hex,
                                            position.instrument_id,
                                            position.trading_symbol,
                                            position.net_buy_quantity,
                                            Side.SELL,
                                            OrderType.MARKET,
                                            0
                                        )
                                        position.exit_order = exit_order
                                        place_order(position.exit_order, position.lot_size, position.freeze_qty, strategy.api)
                                        position.net_sell_quantity += position.exit_order.qty
                                        continue
                                    if position.trailings:
                                        profit_move = position.trailings[0]["profit_move"]
                                        stop_loss_move = position.trailings[0]["stop_loss_move"]
                                        pnl_percentage = (tick.ltp-position.buy_average_price)*100/position.buy_average_price
                                        if pnl_percentage >= profit_move:
                                            new_stop_loss_price = position.buy_average_price*stop_loss_move
                                            new_stop_loss_price = mround(new_stop_loss_price, 0.05)
                                            position.stoploss_price = new_stop_loss_price
                                            logger.info(f"user_id: {strategy.broker_user_id} - {position.trading_symbol} Trailing Stoploss ::: running_profit_percentage:{pnl_percentage} > profit_move:{profit_move}, Updated StopLoss Price: {new_stop_loss_price}")
                                            position.trailings.pop(0)

                        for position in positions_to_archive:
                            strategy.running_positions.remove(position)
                            strategy.archived_positons.append(position)

                    if strategy.status not in [
                        StrategyStatus.SQUARED_OFF,
                        StrategyStatus.ERROR
                    ]:
                        if time.time()-strategy.last_sync_time >= 1:
                            get_broker_orderbook(strategy.api, strategy.broker_user_id)
                            for position in strategy.running_positions + strategy.archived_positons:
                                if position:
                                    sync_position(position, strategy.api)
                            strategy.last_sync_time = time.time()
                        if strategy.status == StrategyStatus.SQUARING_OFF and all_position_completed(strategy):
                            logger.info(f"user_id: {strategy.broker_user_id} - Strategy completed")
                            strategy.status = StrategyStatus.SQUARED_OFF
                except Exception as ex:
                    if isinstance(ex, KeyboardInterrupt):
                        raise ex
                    try:
                        sq_off_all(strategy)
                    except Exception as ex:
                        logger.warning(f"user_id: {strategy.broker_user_id} - Check your positions in broker account.")
                        logger.debug(f"user_id: {strategy.broker_user_id} - Error while sq off", exc_info=True)
                    logger.error(f"user_id: {strategy.broker_user_id} - Runtime Error {ex}")
                    logger.debug(f"user_id: {strategy.broker_user_id} - Runtime Error", exc_info=True)
                    strategy.status = StrategyStatus.ERROR

            if all(
                strategy.status == StrategyStatus.SQUARED_OFF or 
                strategy.status == StrategyStatus.ERROR
                for strategy in Config.STRATEGY_LIST
            ):
                logger.info("All strategies are completed")
                return
        except KeyboardInterrupt:
            logger.warning("Keyboard Interrupt")
            for strategy in Config.STRATEGY_LIST:
                sq_off_all(strategy)
            return

def create_user(username, password, role):
    if get_user(username):
        return False, 'User already exists.'

    try:
        table.put_item(
            Item={
                'username': username,
                'password': hash_password(password),
                'role': role
            }
        )
        return True, 'User created successfully.'
    except ClientError as e:
        return False, str(e)


def create_user(username, password, role):
    if get_user(username):
        return False, 'User already exists.'

    try:
        table.put_item(
            Item={
                'username': username,
                'password': hash_password(password),
                'role': role
            }
        )
        return True, 'User created successfully.'
    except ClientError as e:
        return False, str(e)

import boto3
from botocore.exceptions import ClientError
import hashlib

dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
table = dynamodb.Table('users')

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_user(username):
    try:
        response = table.get_item(Key={'username': username})
        return response.get('Item')
    except ClientError as e:
        print(e.response['Error']['Message'])
        return None

def verify_user(username, password):
    user = get_user(username)
    if not user:
        return False, None
    return user['password'] == hash_password(password), user['role']


if __name__ == "__main__":
    load_instruments()
    main()
