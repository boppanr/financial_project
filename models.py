
from typing import Dict
from enums import OrderStatus, OrderType, PositionStatus, Side


class Order:
    def __init__(
        self,
        id: str,
        instrument_id: str,
        trading_symbol: str,
        qty: int,
        side: Side,
        order_type: OrderType,
        trigger_price: float
    ):
        self.id = id
        self.instrument_id = instrument_id
        self.trading_symbol = trading_symbol
        self.qty = qty
        self.side = side
        self.order_type = order_type
        self.trigger_price = round(trigger_price, 4)

        self.broker_order_id = None
        self.average_trade_price = 0
        self.traded_qty = 0
        self.error_code = None
        self.error_message = None
        self.status: OrderStatus = OrderStatus.CREATED
        self.child_orders: Dict[str, Order] = {}

    def __str__(self):
        return (
            f"Order(id={self.id}, instrument_id={self.instrument_id}, trading_symbol={self.trading_symbol}, "
            f"qty={self.qty}, side={self.side.name}, order_type={self.order_type}, "
            f"trigger_price={self.trigger_price}, broker_order_id={self.broker_order_id}, "
            f"average_trade_price={self.average_trade_price}, traded_qty={self.traded_qty}, "
            f"error_code={self.error_code}, error_message={self.error_message}, status={self.status}"
        )

    def __repr__(self):
        return (
            f"Order(id={self.id}, instrument_id={self.instrument_id}, trading_symbol={self.trading_symbol}, "
            f"qty={self.qty}, side={self.side.name}, order_type={self.order_type}, "
            f"trigger_price={self.trigger_price}, broker_order_id={self.broker_order_id}, "
            f"average_trade_price={self.average_trade_price}, traded_qty={self.traded_qty}, "
            f"error_code={self.error_code}, error_message={self.error_message}, status={self.status})"
        )


class Position:
    def __init__(
        self, 
        initial_order_id: str, 
        instrument_id: str, 
        trading_symbol: str, 
        underlying_token: str,
        trigger_price: float,
        take_profit: float, 
        stop_loss: float, 
        trailings: list,
        lot_size: int,
        freeze_qty: int
    ):
        self.initial_order_id = initial_order_id
        self.instrument_id = instrument_id
        self.trading_symbol = trading_symbol
        self.underlying_token = underlying_token
        self.trigger_price = trigger_price
        self.take_profit = take_profit
        self.stop_loss = stop_loss
        self.trailings = trailings 
        self.lot_size = lot_size
        self.freeze_qty = freeze_qty
        self.target_price = None
        self.stoploss_price = None
        self.net_buy_quantity = 0
        self.buy_average_price = 0
        self.buy_value = 0
        self.net_sell_quantity = 0
        self.sell_average_price = 0
        self.sell_value = 0
        self.net_quantity = 0
        
        self.status = PositionStatus.PENDING
        self.ltp = None
        self.entry_order: Order = None
        self.exit_order: Order = None
