from enum import Enum

class ApiProvider(Enum):
    ZERODHA = "ZERODHA"
    SHOONYA = "SHOONYA"
    FYERS = "FYERS"
    GROWW = "GROWW"
    GOPOCKET = "GOPOCKET"
    DUMMY = "DUMMY"
    
class Side(Enum):
    BUY = "BUY"
    SELL = "SELL"

class OrderType(Enum):
    LIMIT = "LIMIT"
    MARKET = "MARKET"
    STOPLIMIT = "STOPLIMIT"
    
class OrderStatus(Enum):
    CREATED = "CREATED"
    WORKING = "WORKING"
    FILLED = "FILLED"
    CANCELLED = "CANCELLED"
    REJECTED = "RJECTED"
    
class ExpiryType(Enum):
    WEEKLY = "WEEKLY"
    MONTHLY = "MONTHLY"

class PositionStatus(Enum):
    PENDING = "PENDING"
    COMPLETE = "COMPLETE"
    ERROR = "ERROR"

class OrderStatus(Enum):
    CREATED = "CREATED"
    SENT = "SENT"
    WORKING = "WORKING"
    TRIGGER_PENDING = "TRIGGER_PENDING"
    OPEN = "OPEN"
    FILLED = "FILLED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"

class StrategyStatus(Enum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    SQUARING_OFF = "SQUARING_OFF"
    SQUARED_OFF = "SQUARED_OFF"
    ERROR = "ERROR"
