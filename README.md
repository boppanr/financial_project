# 🔐 Broker API Configuration

This project provides a simple and secure way to configure API credentials for three major Indian stock brokers: **Zerodha**, **Shoonya**, and **Fyers**.

## 📋 Supported Brokers

- ✅ Zerodha
- ✅ Shoonya
- ✅ Fyers

---

## 📄 Sample `config.json`

```json
{
  "pricefeed_creds": {
    "user_id": "",
    "password": "",
    "totp_secret": "",
    "api_key": "",
    "api_secret": ""
  },
  "api": [
    {
      "provider": "zerodha",
      "fund_allocations": {
        "nifty": 15000,
        "sensex": 20000
      },
      "creds": {
        "user_id": "",
        "api_key": "",
        "password": "",
        "totp_secret": "",
        "api_secret": ""
      }
    },
    {
      "provider": "shoonya",
      "fund_allocations": {
        "banknifty": 15000,
        "bankex": 20000
      },
      "creds": {
        "user_id": "",
        "api_key": "",
        "password": "",
        "totp_secret": ""
      }
    },
    {
      "provider": "fyers",
      "fund_allocations": {
        "midcpnifty": 15000,
        "finnifty": 20000
      },
      "creds": {
        "auth_code": "",
        "app_id": "",
        "app_secret": ""
      }
    },
    {
      "provider": "groww",
      "fund_allocations": {
        "banknifty": 15000,
        "bankex": 20000
      },
      "creds": {
        "user_id": "",
        "api_key": ""
      }
    }
  ],
  "strategy": {
    "strategy_end_time": "14:00:00",
    "check_candle": 38,
    "buffer_price_percentage": 5,
    "strike_buffer_precentage": 0.15,
    "stop_loss": 40,
    "profit_target": 60,
    "trailings": [
      { "profit_move": 25, "stop_loss_move": 1 },
      { "profit_move": 40, "stop_loss_move": 1.25 },
      { "profit_move": 60, "stop_loss_move": 1.4 }
    ]
  }
}

```

## ⚙️ Required Parameters

### 🪙 Zerodha

```json
{
  "user_id": "",
  "api_key": "",
  "password": "",
  "totp_secret": "",
  "api_secret": ""
}
```

| Parameter     | Description                                     |
|---------------|-------------------------------------------------|
| `user_id`     | Your Zerodha client ID                          |
| `api_key`     | API key from Zerodha Developer Console          |
| `password`    | Your account password                           |
| `totp_secret` | TOTP secret for 2FA (Time-based OTP)            |
| `api_secret`  | Secret key associated with your API key         |

---

### 🪙 Shoonya

```json
{
  "user_id": "",
  "api_key": "",
  "password": "",
  "totp_secret": ""
}
```

| Parameter     | Description                                     |
|---------------|-------------------------------------------------|
| `user_id`     | Your Shoonya client ID                          |
| `api_key`     | API key from Shoonya                            |
| `password`    | Your account password                           |
| `totp_secret` | TOTP secret for 2FA                             |

---

### 🪙 Groww

```json
{
  "user_id": "",
  "api_key": ""
}
```

| Parameter     | Description                                     |
|---------------|-------------------------------------------------|
| `user_id`     | Your Groww User name                            |
| `api_key`     | API key from Groww get from groww api page      |

---

### 🪙 Fyers

```json
{
  "auth_code": "",
  "app_id": "",
  "app_secret": ""
}
```

| Parameter     | Description                                         |
|---------------|-----------------------------------------------------|
| `auth_code`   | Authorization code obtained from Fyers login flow  |
| `app_id`      | Application ID (API key) from Fyers Developer Portal |
| `app_secret`  | Secret key associated with the App ID               |

---