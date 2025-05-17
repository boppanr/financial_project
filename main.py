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
    place_order,
    get_broker_orderbook,
    sync_position, 
    zerodha_login, 
    shoonya_login
)
from models import Order, Position
from pricefeed import PricePkt, Pricefeed, get_high_low_historical_data, get_ltp
from utils import get_alloted_fund, get_time_frame_stamps
from copy import deepcopy

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

dict_config = {
    'version': 1,
    'disable_existing_loggers': False, # default True
    'filters': {
        'my_filter': {
            '()': MyFilter,
            'filter_msg': 'show how to use filter'
        }
    },
    'formatters': {
        'user_info': {
            'datefmt': '%H:%M:%S',
            'format': '%(levelname)-8s - %(asctime)s - %(message)s'
        },
        'brief': {
            'datefmt': '%H:%M:%S',
            'format': '%(levelname)-8s - %(name)s - %(message)s'
        },
        'single-line': {
            'datefmt': '%H:%M:%S',
            'format': '%(levelname)-8s - %(asctime)s - %(name)s - %(module)s - %(funcName)s - line no. %(lineno)d: %(message)s'
        },
        'multi-process': {
            'datefmt': '%H:%M:%S',
            'format': '%(levelname)-8s - [%(process)d] - %(name)s - %(module)s:%(funcName)s - %(lineno)d: %(message)s'
        },
        'multi-thread': {
            'datefmt': '%H:%M:%S',
            'format': '%(levelname)-8s - %(threadName)s - %(name)s - %(module)s:%(funcName)s - %(lineno)d: %(message)s'
        },
        'verbose': {
            'format': '%(asctime)s - %(levelname)-8s - [%(process)d] - %(threadName)s - %(name)s - %(module)s:%(funcName)s - %(lineno)d'
                    ': %(message)s'
        },
        'multiline': {
            'format': 'Level: %(levelname)s\nTime: %(asctime)s\nProcess: %(process)d\nThread: %(threadName)s\nLogger'
                    ': %(name)s\nPath: %(module)s:%(lineno)d\nFunction :%(funcName)s\nMessage: %(message)s\n'
        }
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'single-line',
            'filters': ['my_filter'],
            # 'stream': 'ext://sys.stdout'
        },
        'file_handler': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'formatter': 'verbose',
        },
        'null_handler': {
            'level': 'DEBUG',
            'class': 'logging.NullHandler',
        },
    },
    'loggers': {
        'root': {  # this is root logger
            'level': 'DEBUG',
            'handlers': ['console', 'file_handler'],
        },
        'parent': {
            'level': 'DEBUG',
            'handlers': ['console', 'file_handler'],
        },
        'parent.child': {  # This is child logger of `parent` handler, propagate will up to `parent` handler
            'level': 'DEBUG',
            'handlers': ['console', 'file_handler'],
        },
    }
}

logging.config.dictConfig(dict_config)
logger = logging.getLogger("root")

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
                logger.info(f"{order.id} :: {order.trading_symbol} :: {order.status.name}")
                return False
    return True


def sq_off_all(strategy: Strategy):
    archived_positions = []
    for position in strategy.running_positions:
        entry_order = position.entry_order
        exit_order = position.exit_order
        if entry_order.status == OrderStatus.TRIGGER_PENDING:
            entry_order.status = OrderStatus.CANCELLED
            logger.info(f"{entry_order.trading_symbol} {entry_order.id} is {entry_order.status.name}")
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
            place_order(position.exit_order, position.lot_size, position.freeze_qty)
            position.net_sell_quantity += position.exit_order.qty
        archived_positions.append(position)
    
    for archived_position in archived_positions:
        strategy.running_positions.remove(archived_position)
        strategy.archived_positons.append(archived_position)

    strategy.status = StrategyStatus.SQUARING_OFF


def main():
    logger.debug(Config.config_json)
    zerodha_login(
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
    if Config.API.provider == ApiProvider.ZERODHA:
        Config.API.creds["access_token"] = Config.PRICEFEED_CREDS["access_token"]
    elif Config.API.provider == ApiProvider.SHOONYA:
        shoonya_login(
            Config.API.creds["user_id"],
            Config.API.creds["api_key"],
            Config.API.creds["password"],
            Config.API.creds["totp_secret"],
        )
    timeframe_stamps = get_time_frame_stamps(interval=Config.STRATEGY.check_candle)
    logger.info(f"========= Next check-time: {timeframe_stamps[0].strftime('%H:%M:%S')} =========")
    strategy = Config.STRATEGY
    strategy.status = StrategyStatus.RUNNING
    last_sync_time = time.time()
    while True:
        try:
            tick: PricePkt = pricefeed_queue.get()
            if not tick:
                time.sleep(0.5)
                continue
            if strategy.status not in [
                StrategyStatus.SQUARED_OFF,
                StrategyStatus.ERROR,
                StrategyStatus.SQUARING_OFF,
            ]:
                if tick.instrument_token not in [str(und_token) for und_token in underlying_instruments.keys()]:
                    continue
                current_time = datetime.datetime.now(pytz.timezone("Asia/Kolkata")).replace(
                    microsecond=0
                ).time()
                if current_time >= strategy.strategy_end_time:
                    logger.info("Strategy time is over")
                    sq_off_all(strategy)
                    continue
                if current_time >= timeframe_stamps[0]:
                    check_time = timeframe_stamps.pop(0)
                    logger.info(f"==============================================")
                    for position in strategy.running_positions + strategy.archived_positons:
                        if position:
                            sync_position(position)
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
                                                logger.info(f"Running Call Position for {underlying_instrument.trading_symbol} not taking new entry.")
                                            if "PE" in position.trading_symbol:
                                                take_put_entry = False
                                                logger.info(f"Running Put Position for {underlying_instrument.trading_symbol} not taking new entry.")
                                            continue
                                for archive_position in archived_positions:
                                    strategy.running_positions.remove(archive_position)
                                    strategy.archived_positons.append(archive_position)
                            else:
                                logger.info(f"Running Call and Put positions for {underlying_instrument.trading_symbol} not taking new entry.")
                                continue
                        underlying_name = INDEXS[underlying_instrument.trading_symbol]
                        lot_size = LOT_SIZE[underlying_name]
                        index_high, index_low = get_high_low_historical_data(underlying_token, Config.STRATEGY.check_candle, check_time)
                        if not index_high or not index_low:
                            logger.warning(f"No high low found for: {underlying_name}")
                            continue
                        high_spot = index_high + (strategy.strike_buffer_precentage*index_high)/100
                        strike_diff = STRIKE_DIFF[underlying_name]
                        high_strike = get_strike(high_spot, strike_diff)
                        low_spot = index_low - (strategy.strike_buffer_precentage*index_low)/100
                        low_strike = get_strike(low_spot, strike_diff)
                        alloted_fund = get_alloted_fund(underlying_instrument.trading_symbol)
                        quantity = alloted_fund // lot_size
                        if quantity <= 0:
                            logger.warning(f"Insufficient alloted fund for: {underlying_name}. skipping")
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
                        option_high_ce, _ = get_high_low_historical_data(call_token, Config.STRATEGY.check_candle, check_time)
                        option_high_pe, _ = get_high_low_historical_data(put_token, Config.STRATEGY.check_candle, check_time)

                        if not option_high_ce and take_call_entry:
                            logger.warning(f"High not found for: {call_symbol}")
                            continue
                        
                        if not option_high_pe and take_put_entry:
                            logger.warning(f"High not found for: {put_symbol}")
                            continue

                        call_entry_price = calculate_entry_price(option_high_ce)
                        put_entry_price = calculate_entry_price(option_high_pe)

                        call_quantity = lot_size*int(alloted_fund // (call_entry_price*lot_size))
                        put_quantity = lot_size*int(alloted_fund // (put_entry_price*lot_size))
                        if call_quantity <= 0 and take_call_entry:
                            logger.warning(f"Call qty is: {call_quantity}, skiping entry")
                            continue
                        if put_quantity <= 0 and take_put_entry:
                            logger.warning(f"Put qty is: {put_quantity}, skiping entry")
                            continue
                        
                        if take_call_entry:
                            logger.info(f"{underlying_name}: CE({call_symbol}): High={option_high_ce}, Entry={call_entry_price}, Qty={call_quantity}")
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
                            logger.info(f"Trigger order placed for: {call_positon.trading_symbol}, Side:{call_order.side.name}, Qty: {call_order.qty}")

                        if take_put_entry:
                            logger.info(f"{underlying_name}: PE({put_symbol}): High={option_high_pe}, Entry={put_entry_price}, Qty={put_quantity}")
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
                            logger.info(f"Trigger order placed for: {put_positon.trading_symbol}, Side:{call_order.side.name}, Qty: {put_order.qty}")
                    logger.info(f"========= Next check-time: {timeframe_stamps[0].strftime('%H:%M:%S')} =========")
                positions_to_archive = []
                for position in strategy.running_positions:
                    ltp = get_ltp(position.instrument_id)
                    if position.entry_order.status == OrderStatus.TRIGGER_PENDING:
                        order = position.entry_order
                        if order.side == Side.BUY:
                            if ltp >= order.trigger_price:
                                logger.info(f"{order.trading_symbol} Order Triggered ::: ltp: {ltp} >= trigger_price: {order.trigger_price}")
                                order.status = OrderStatus.WORKING
                                place_order(order, position.lot_size, position.freeze_qty)
                        else:
                            if ltp <= order.trigger_price:
                                logger.info(f"{order.trading_symbol} Order Triggered ::: ltp: {ltp} <= trigger_price: {order.trigger_price}")
                                order.status = OrderStatus.WORKING
                                place_order(order, position.lot_size, position.freeze_qty)
                    if position.exit_order and position.exit_order.status in [OrderStatus.FILLED]:
                        positions_to_archive.append(position)
                        continue
                    if position.entry_order.status == OrderStatus.FILLED and not position.exit_order:
                        if not position.stoploss_price and not position.target_price:
                            position.stoploss_price = calculate_stoploss_price(position.buy_average_price, position.stop_loss)
                            position.target_price = calculate_target_price(position.buy_average_price, position.take_profit)
                            logger.info(f"{position.trading_symbol}, Avg Buy Price: {position.buy_average_price}, StopLoss Price: {position.stoploss_price}, ProfitTarget Price: {position.target_price}")
                        if ltp <= position.stoploss_price:
                            logger.info(f"{position.trading_symbol}, StopLoss Hit ::: Ltp:{ltp} <= StopLoss Price: {position.stoploss_price}")
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
                            place_order(position.exit_order, position.lot_size, position.freeze_qty)
                            position.net_sell_quantity += position.exit_order.qty
                            continue
                        if ltp >= position.target_price:
                            logger.info(f"{position.trading_symbol}, Target Hit ::: Ltp:{ltp} >= TakeProfit Price: {position.stoploss_price}")
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
                            place_order(position.exit_order, position.lot_size, position.freeze_qty)
                            position.net_sell_quantity += position.exit_order.qty
                            continue
                        if position.trailings:
                            profit_move = position.trailings[0]["profit_move"]
                            stop_loss_move = position.trailings[0]["stop_loss_move"]
                            if (ltp-position.buy_average_price)*100/position.buy_average_price >= profit_move:
                                new_stop_loss_price = position.buy_average_price*stop_loss_move
                                new_stop_loss_price = mround(new_stop_loss_price, 0.05)
                                position.stoploss_price = new_stop_loss_price
                                logger.info(f"{position.trading_symbol} Tariling ::: running_profit_percentage:{(ltp-position.buy_average_price)*100/position.buy_average_price} > profit_move:{profit_move}, Updated StopLoss Price: {new_stop_loss_price}")
                                position.trailings.pop(0)

                for position in positions_to_archive:
                    strategy.running_positions.remove(position)
                    strategy.archived_positons.append(position)

            if strategy.status not in [
                StrategyStatus.SQUARED_OFF,
                StrategyStatus.ERROR
            ]:
                if time.time()-last_sync_time >= 1:
                    get_broker_orderbook()
                    for position in strategy.running_positions + strategy.archived_positons:
                        if position:
                            sync_position(position)
                    last_sync_time = time.time()
                if strategy.status == StrategyStatus.SQUARING_OFF and all_position_completed(strategy):
                    logger.info(f"Stratgy completed")
                    return

        except:
            try:
                sq_off_all(strategy)
            except:
                logger.warning(f"Check your positions in broker account.")
                logger.debug(f"Error while sq off", exc_info=True)
            logger.critical(f"Runtime Error", exc_info=True)
            strategy.status = StrategyStatus.ERROR
            return


if __name__ == "__main__":
    load_instruments()
    main()
