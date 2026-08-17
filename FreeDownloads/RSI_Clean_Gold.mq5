//+------------------------------------------------------------------+
//|                    RSI Auto Lot & Close (GOLD v1.0)              |
//|        نسخه اختصاصی طلا — فیلتر روند H4 + گرید بدون مارتینگیل     |
//| مبنا: RSI_Clean v3.2 + تنظیمات بهینه طلا (گام 12$، هدف 10$)      |
//| v1.0: فیلتر روند H4 (EMA) — ورود فقط در جهت روند؛               |
//|       بدون مارتینگیل، بدون بازیابی خودکار (برای طلا امن‌تر)      |
//| v1.1: فیلتر H4 تست شد (50/100/200) — ضرر داد؛ پیش‌فرض خاموش = برنده +14.4% |
//+------------------------------------------------------------------+
#property copyright   "K.m@2025"
#property version     "1.10"
#property description "RSI + H4 trend filter + grid (gold optimized)"

//==================== ورودی‌ها ====================
input string InpHeadSignal    = "===== RSI Signal =====";
input int    InpRSIPeriod     = 14;
input int    InpRSIOversold   = 30;
input int    InpRSIOverbought = 70;

input string InpHeadTrend     = "===== H4 Trend Filter =====";
input bool   InpH4TrendUse    = false;         // فیلتر روند H4 — تست شد و بهینه نیست؛ پیش‌فرض خاموش
input int    InpH4EMA         = 50;            // دوره EMA روند H4

input string InpHeadLot       = "===== Lot Management =====";
input bool   InpSteppedLot    = true;          // لات پلکانی بر اساس موجودی
input double InpStartMoney    = 1000.0;        // موجودی پایه هر پله
input double InpBaseLot       = 0.01;          // لات پایه

input string InpHeadGrid      = "===== Grid =====";
input int    InpNearbyPips    = 600;           // فاصله مجاز از معامله/سفارش نزدیک (×۲) — طلا: 6$
input int    InpGridMax       = 7;             // حداکثر سطوح گرید
input double InpGridStep      = -1200;         // فاصله سطوح (پیپ، 1200 = 12$) — بهینه طلا
input double InpGridStepMult  = 1.12;          // رشد فاصله سطوح
input double InpGridLotMult   = 1.0;           // بدون مارتینگیل (مهم برای طلا)
input int    InpClosePips     = 1000;          // سود کل سبد برای بستن (پیپ، 1000 = 10$)
input int    InpPendingHours  = 24;            // انقضای سفارش‌های پندینگ (۰=نامحدود)

input string InpHeadRisk      = "===== Risk =====";
input int    InpSL            = 6000;          // حد ضرر هر معامله (پیپ، 6000 = 60$)
input int    InpTP            = 0;             // حد سود هر معامله (پیپ)
input double InpMaxDD         = 20.0;          // سقف افت حساب (٪)
input bool   InpDDTrackPeak   = false;         // DD از اوج اکویتی (پیش‌فرض خاموش)
input double InpMaxDailyLossPct = 10.0;        // سقف ضرر روزانه (٪، ۰=خاموش)
input bool   InpAutoResumeDD  = false;         // بازیابی خودکار DD — برای طلا همیشه خاموش!
input int    InpMaxSpread     = 60;            // حداکثر اسپرد مجاز (پیپ) — طلا اسپرد بالاتر دارد
input bool   InpAntiHedge     = true;          // جلوگیری از دو جهت هم‌زمان

input string InpHeadOther     = "===== Other =====";
input int    InpMagic         = 7122;
input ulong  InpSlippage      = 30;

//==================== متغیرهای سراسری ====================
int      rsiHandle   = INVALID_HANDLE;
int      h4EmaHandle = INVALID_HANDLE;
datetime lastBar     = 0;
bool     tradingOff  = false;

// آمار و محافظ‌های ریسک
double   gStartBalance = 0;
double   gPeakEquity   = 0;
double   gMaxDD        = 0;
datetime dayKey        = 0;
double   dayStartEq    = 0;

//==================== توابع کمکی ====================
double PipSize()
{
   double point = SymbolInfoDouble(_Symbol, SYMBOL_POINT);
   int    d     = (int)SymbolInfoInteger(_Symbol, SYMBOL_DIGITS);
   if (d == 3 || d == 5) point *= 10;
   return point;
}
double PipsToPrice(double pips) { return pips * PipSize(); }

ENUM_ORDER_TYPE_FILLING GetFilling()
{
   long f = SymbolInfoInteger(_Symbol, SYMBOL_FILLING_MODE);
   if ((f & SYMBOL_FILLING_FOK) == SYMBOL_FILLING_FOK) return ORDER_FILLING_FOK;
   if ((f & SYMBOL_FILLING_IOC) == SYMBOL_FILLING_IOC) return ORDER_FILLING_IOC;
   return ORDER_FILLING_RETURN;
}

bool MarketOpen()
{
   double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);
   double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);
   if (ask <= 0 || bid <= 0) return false;
   if ((ask - bid) / PipSize() > 500.0) return false;
   return true;
}

double AlignLot(double lot)
{
   double step = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_STEP);
   double minL = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_MIN);
   double maxL = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_MAX);
   lot = MathFloor(lot / step) * step;
   if (lot < minL) lot = minL;
   if (lot > maxL) lot = maxL;
   double margin = 0;
   if (OrderCalcMargin(ORDER_TYPE_BUY, _Symbol, lot,
                       SymbolInfoDouble(_Symbol, SYMBOL_ASK), margin) && margin > 0)
   {
      double maxByMargin = AccountInfoDouble(ACCOUNT_MARGIN_FREE) / margin * lot;
      if (maxByMargin < lot)
      {
         lot = MathFloor(maxByMargin / step) * step;
         if (lot < minL) lot = 0;
      }
   }
   return NormalizeDouble(lot, 2);
}

double CalcBaseLot()
{
   double lot = InpBaseLot;
   if (InpSteppedLot)
   {
      double sm = (InpStartMoney > 0) ? InpStartMoney : 1.0;
      int level = (int)MathFloor(AccountInfoDouble(ACCOUNT_BALANCE) / sm);
      if (level < 1) level = 1;
      lot = InpBaseLot * level;
   }
   return AlignLot(lot);
}

// فیلتر روند H4: 1=صعودی، -1=نزولی، 0=نامشخص
int H4Trend()
{
   if (h4EmaHandle == INVALID_HANDLE) return 0;
   double ema[1], cl[1];
   if (CopyBuffer(h4EmaHandle, 0, 1, 1, ema) < 1) return 0;
   if (CopyClose(_Symbol, PERIOD_H4, 1, 1, cl) < 1) return 0;
   if (cl[0] > ema[0]) return 1;
   if (cl[0] < ema[0]) return -1;
   return 0;
}

int CountPositions(int type)
{
   int cnt = 0;
   for (int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong tk = PositionGetTicket(i);
      if (tk == 0) continue;
      if (PositionGetString(POSITION_SYMBOL) != _Symbol) continue;
      if ((long)PositionGetInteger(POSITION_MAGIC) != InpMagic) continue;
      if (type != -1 && (int)PositionGetInteger(POSITION_TYPE) != type) continue;
      cnt++;
   }
   return cnt;
}

int CountPending(int type)
{
   int cnt = 0;
   for (int i = OrdersTotal() - 1; i >= 0; i--)
   {
      ulong tk = OrderGetTicket(i);
      if (tk == 0) continue;
      if (OrderGetString(ORDER_SYMBOL) != _Symbol) continue;
      if ((long)OrderGetInteger(ORDER_MAGIC) != InpMagic) continue;
      ENUM_ORDER_TYPE ot = (ENUM_ORDER_TYPE)OrderGetInteger(ORDER_TYPE);
      if (type == 0 && (ot == ORDER_TYPE_BUY_LIMIT || ot == ORDER_TYPE_BUY_STOP || ot == ORDER_TYPE_BUY_STOP_LIMIT)) cnt++;
      else if (type == 1 && (ot == ORDER_TYPE_SELL_LIMIT || ot == ORDER_TYPE_SELL_STOP || ot == ORDER_TYPE_SELL_STOP_LIMIT)) cnt++;
      else if (type == -1 && ot >= ORDER_TYPE_BUY_LIMIT) cnt++;
   }
   return cnt;
}

bool NearPosition(int type, double price, double rangePips)
{
   double range = PipsToPrice(rangePips);
   for (int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong tk = PositionGetTicket(i);
      if (tk == 0) continue;
      if (PositionGetString(POSITION_SYMBOL) != _Symbol) continue;
      if ((long)PositionGetInteger(POSITION_MAGIC) != InpMagic) continue;
      if ((int)PositionGetInteger(POSITION_TYPE) != type) continue;
      if (MathAbs(PositionGetDouble(POSITION_PRICE_OPEN) - price) <= range) return true;
   }
   return false;
}

bool NearPending(int type, double price, double rangePips)
{
   double range = PipsToPrice(rangePips);
   for (int i = OrdersTotal() - 1; i >= 0; i--)
   {
      ulong tk = OrderGetTicket(i);
      if (tk == 0) continue;
      if (OrderGetString(ORDER_SYMBOL) != _Symbol) continue;
      if ((long)OrderGetInteger(ORDER_MAGIC) != InpMagic) continue;
      ENUM_ORDER_TYPE ot = (ENUM_ORDER_TYPE)OrderGetInteger(ORDER_TYPE);
      bool isBuy  = (ot == ORDER_TYPE_BUY_LIMIT || ot == ORDER_TYPE_BUY_STOP);
      bool isSell = (ot == ORDER_TYPE_SELL_LIMIT || ot == ORDER_TYPE_SELL_STOP);
      if (type == 0 && !isBuy) continue;
      if (type == 1 && !isSell) continue;
      if (MathAbs(OrderGetDouble(ORDER_PRICE_OPEN) - price) <= range) return true;
   }
   return false;
}

double BasketPips()
{
   double sum = 0, lots = 0;
   for (int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong tk = PositionGetTicket(i);
      if (tk == 0) continue;
      if (PositionGetString(POSITION_SYMBOL) != _Symbol) continue;
      if ((long)PositionGetInteger(POSITION_MAGIC) != InpMagic) continue;
      double vol = PositionGetDouble(POSITION_VOLUME);
      double op  = PositionGetDouble(POSITION_PRICE_OPEN);
      if ((int)PositionGetInteger(POSITION_TYPE) == POSITION_TYPE_BUY)
      { sum += (SymbolInfoDouble(_Symbol, SYMBOL_BID) - op) * vol; lots += vol; }
      else
      { sum += (op - SymbolInfoDouble(_Symbol, SYMBOL_ASK)) * vol; lots += vol; }
   }
   return (lots > 0) ? (sum / lots / PipSize()) : 0;
}

void DeleteAllPendings()
{
   for (int i = OrdersTotal() - 1; i >= 0; i--)
   {
      ulong tk = OrderGetTicket(i);
      if (tk == 0) continue;
      if (OrderGetString(ORDER_SYMBOL) != _Symbol) continue;
      if ((long)OrderGetInteger(ORDER_MAGIC) != InpMagic) continue;
      MqlTradeRequest req = {};
      MqlTradeResult  res = {};
      req.action = TRADE_ACTION_REMOVE;
      req.order  = tk;
      if (!OrderSend(req, res))
         Print("DeletePending err ", res.retcode, " ", res.comment);
   }
}

void CloseAllBasket()
{
   for (int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong tk = PositionGetTicket(i);
      if (tk == 0) continue;
      if (PositionGetString(POSITION_SYMBOL) != _Symbol) continue;
      if ((long)PositionGetInteger(POSITION_MAGIC) != InpMagic) continue;
      MqlTradeRequest req = {};
      MqlTradeResult  res = {};
      req.action    = TRADE_ACTION_DEAL;
      req.symbol    = _Symbol;
      req.position  = tk;
      req.volume    = PositionGetDouble(POSITION_VOLUME);
      req.type      = ((ENUM_POSITION_TYPE)PositionGetInteger(POSITION_TYPE) == POSITION_TYPE_BUY)
                      ? ORDER_TYPE_SELL : ORDER_TYPE_BUY;
      req.price     = (req.type == ORDER_TYPE_SELL)
                      ? SymbolInfoDouble(_Symbol, SYMBOL_BID)
                      : SymbolInfoDouble(_Symbol, SYMBOL_ASK);
      req.deviation = InpSlippage;
      req.magic     = InpMagic;
      req.type_filling = GetFilling();
      if (!OrderSend(req, res))
      {
         if (res.retcode != TRADE_RETCODE_MARKET_CLOSED)
            Print("CloseAll err ", res.retcode, " ", res.comment);
      }
   }
   DeleteAllPendings();
}

//==================== معاملات ====================
bool OpenMarket(int type, double lot, double slPrice, double tpPrice)
{
   MqlTradeRequest req = {};
   MqlTradeResult  res = {};
   req.action    = TRADE_ACTION_DEAL;
   req.symbol    = _Symbol;
   req.volume    = lot;
   req.type      = (type == 0) ? ORDER_TYPE_BUY : ORDER_TYPE_SELL;
   req.price     = (type == 0) ? SymbolInfoDouble(_Symbol, SYMBOL_ASK)
                               : SymbolInfoDouble(_Symbol, SYMBOL_BID);
   req.sl        = NormalizeDouble(slPrice, (int)SymbolInfoInteger(_Symbol, SYMBOL_DIGITS));
   req.tp        = NormalizeDouble(tpPrice, (int)SymbolInfoInteger(_Symbol, SYMBOL_DIGITS));
   req.deviation = InpSlippage;
   req.magic     = InpMagic;
   req.type_filling = GetFilling();
   req.comment   = "RSI";
   if (!OrderSend(req, res))
   {
      if (res.retcode != TRADE_RETCODE_MARKET_CLOSED)
         Print("OpenMarket err ", res.retcode, " ", res.comment);
      return false;
   }
   return true;
}

bool OpenPending(int type, double lot, double price, double slPrice, double tpPrice, datetime exp)
{
   MqlTradeRequest req = {};
   MqlTradeResult  res = {};
   req.action   = TRADE_ACTION_PENDING;
   req.symbol   = _Symbol;
   req.volume   = lot;
   req.type     = (type == 0) ? ORDER_TYPE_BUY_LIMIT : ORDER_TYPE_SELL_LIMIT;
   req.price    = NormalizeDouble(price, (int)SymbolInfoInteger(_Symbol, SYMBOL_DIGITS));
   req.sl       = NormalizeDouble(slPrice, (int)SymbolInfoInteger(_Symbol, SYMBOL_DIGITS));
   req.tp       = NormalizeDouble(tpPrice, (int)SymbolInfoInteger(_Symbol, SYMBOL_DIGITS));
   req.magic    = InpMagic;
   req.comment  = "Grid";
   if (exp > 0 &&
       (SymbolInfoInteger(_Symbol, SYMBOL_EXPIRATION_MODE) & SYMBOL_EXPIRATION_SPECIFIED) != 0)
   {
      req.type_time  = ORDER_TIME_SPECIFIED;
      req.expiration = exp;
   }
   else req.type_time = ORDER_TIME_GTC;
   if (!OrderSend(req, res))
   {
      if (res.retcode != TRADE_RETCODE_MARKET_CLOSED)
         Print("OpenPending err ", res.retcode, " ", res.comment);
      return false;
   }
   return true;
}

//==================== ورود گرید ====================
void TryOpenGrid(int direction)
{
   double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);
   double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);
   if ((ask - bid) / PipSize() > InpMaxSpread) return;

   double baseLot = CalcBaseLot();
   if (baseLot <= 0) return;

   double ref     = (direction == 0) ? ask : bid;
   int    signSL  = (direction == 0) ? -1 : 1;
   double sl = 0, tp = 0;
   if (InpSL > 0) sl = ref + signSL * PipsToPrice(InpSL);
   if (InpTP > 0) tp = ref - signSL * PipsToPrice(InpTP);

   if (!OpenMarket(direction, baseLot, sl, tp)) return;

   double step   = MathAbs(InpGridStep);
   double lot    = baseLot;
   double price  = ref;
   int    signG  = (direction == 0) ? -1 : 1;
   datetime exp  = (InpPendingHours > 0) ? TimeCurrent() + InpPendingHours * 3600 : 0;

   for (int n = 1; n <= InpGridMax; n++)
   {
      price = ref + signG * PipsToPrice(step * MathPow(InpGridStepMult, n - 1));
      if (n > 1) lot = baseLot * MathPow(InpGridLotMult, n - 1);
      lot = AlignLot(lot);
      if (lot <= 0) break;

      double gsl = 0, gtp = 0;
      if (InpSL > 0) gsl = price + signSL * PipsToPrice(InpSL);
      if (InpTP > 0) gtp = price - signSL * PipsToPrice(InpTP);
      long stopsLvl = SymbolInfoInteger(_Symbol, SYMBOL_TRADE_STOPS_LEVEL);
      if (stopsLvl < 0) stopsLvl = 0;
      double minGap = MathMax(PipsToPrice(1.0), (double)stopsLvl * _Point);
      if (direction == 0 && price >= bid - minGap) continue;
      if (direction == 1 && price <= ask + minGap) continue;
      if (!OpenPending(direction, lot, price, gsl, gtp, exp)) break;
   }
}

//==================== رویدادها ====================
int OnInit()
{
   rsiHandle = iRSI(_Symbol, _Period, InpRSIPeriod, PRICE_CLOSE);
   if (rsiHandle == INVALID_HANDLE)
   {
      Print("RSI handle error: ", GetLastError());
      return INIT_FAILED;
   }
   h4EmaHandle = iMA(_Symbol, PERIOD_H4, InpH4EMA, 0, MODE_EMA, PRICE_CLOSE);
   if (h4EmaHandle == INVALID_HANDLE)
   {
      Print("H4 EMA handle error: ", GetLastError());
      return INIT_FAILED;
   }
   gStartBalance = AccountInfoDouble(ACCOUNT_BALANCE);
   gPeakEquity   = AccountInfoDouble(ACCOUNT_EQUITY);
   dayKey        = 0;
   dayStartEq    = 0;
   Print("RSI Clean GOLD v1.0 started. Magic=", InpMagic, " Symbol=", _Symbol,
         " step=", InpGridStep, " close=", InpClosePips, " H4EMA=", InpH4EMA);
   return INIT_SUCCEEDED;
}

void OnDeinit(const int reason)
{
   if (rsiHandle != INVALID_HANDLE) IndicatorRelease(rsiHandle);
   if (h4EmaHandle != INVALID_HANDLE) IndicatorRelease(h4EmaHandle);
   Comment("");
}

void OnTick()
{
   if (tradingOff)
   {
      double eqR = AccountInfoDouble(ACCOUNT_EQUITY);
      double blR = AccountInfoDouble(ACCOUNT_BALANCE);
      if (InpAutoResumeDD && blR > 0 && eqR >= blR * (1.0 - InpMaxDD / 200.0))
      {
         tradingOff = false;
         Print("DD protection released, trading resumed");
      }
      else return;
   }

   double eq = AccountInfoDouble(ACCOUNT_EQUITY);
   double bl = AccountInfoDouble(ACCOUNT_BALANCE);
   if (eq > gPeakEquity) gPeakEquity = eq;
   if (gPeakEquity > 0)
   {
      double ddNow = (gPeakEquity - eq) / gPeakEquity;
      if (ddNow > gMaxDD) gMaxDD = ddNow;
   }

   double ddBase = InpDDTrackPeak ? gPeakEquity : bl;
   if (ddBase > 0 && eq <= ddBase * (1.0 - InpMaxDD / 100.0))
   {
      CloseAllBasket();
      tradingOff = true;
      Alert("Equity stop hit at ", DoubleToString(eq, 2), " - trading disabled");
      return;
   }

   if (CountPositions(-1) > 0 && BasketPips() >= InpClosePips)
   {
      CloseAllBasket();
      return;
   }

   datetime today = iTime(_Symbol, PERIOD_D1, 0);
   if (today != dayKey)
   {
      dayKey     = today;
      dayStartEq = AccountInfoDouble(ACCOUNT_EQUITY);
   }
   if (InpMaxDailyLossPct > 0 && dayStartEq > 0)
   {
      double dayDD = (dayStartEq - AccountInfoDouble(ACCOUNT_EQUITY)) / dayStartEq * 100.0;
      if (dayDD >= InpMaxDailyLossPct) return;
   }

   datetime bar = iTime(_Symbol, _Period, 0);
   if (bar == lastBar) return;
   lastBar = bar;

   if (!MarketOpen()) return;

   double rsi = -1;
   double buf[1];
   if (CopyBuffer(rsiHandle, 0, 1, 1, buf) >= 1) rsi = buf[0];
   if (rsi < 0) return;

   int trend = H4Trend();

   bool hasBuy  = (CountPositions(0) + CountPending(0)) > 0;
   bool hasSell = (CountPositions(1) + CountPending(1)) > 0;

   // خرید: RSI اشباع فروش + روند H4 صعودی (در صورت فعال بودن فیلتر)
   if (rsi < InpRSIOversold && (!InpH4TrendUse || trend == 1) &&
       !hasBuy && (!InpAntiHedge || !hasSell))
   {
      double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);
      if (!NearPosition(0, ask, InpNearbyPips * 2) &&
          !NearPending(0, ask, InpNearbyPips * 2))
         TryOpenGrid(0);
   }
   // فروش: RSI اشباع خرید + روند H4 نزولی (در صورت فعال بودن فیلتر)
   else if (rsi > InpRSIOverbought && (!InpH4TrendUse || trend == -1) &&
            !hasSell && (!InpAntiHedge || !hasBuy))
   {
      double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);
      if (!NearPosition(1, bid, InpNearbyPips * 2) &&
          !NearPending(1, bid, InpNearbyPips * 2))
         TryOpenGrid(1);
   }

   Comment("RSI(1): ", DoubleToString(rsi, 2),
           " | H4 trend: ", (trend == 1 ? "UP" : (trend == -1 ? "DOWN" : "?")),
           "\nPositions: ", CountPositions(-1),
           " | Pending: ", CountPending(-1),
           " | Basket pips: ", DoubleToString(BasketPips(), 1),
           "\nPeakEq: ", DoubleToString(gPeakEquity, 2),
           " | MaxDD: ", DoubleToString(gMaxDD * 100.0, 2), "%");
}

//==================== گزارش بکتست ====================
double OnTester()
{
   double gProfit = 0, gLoss = 0;
   int    closed  = 0;
   if (HistorySelect(0, TimeCurrent()))
   {
      int total = HistoryDealsTotal();
      for (int i = 0; i < total; i++)
      {
         ulong tk = HistoryDealGetTicket(i);
         if (tk == 0) continue;
         if (HistoryDealGetString(tk, DEAL_SYMBOL) != _Symbol) continue;
         if ((long)HistoryDealGetInteger(tk, DEAL_MAGIC) != InpMagic) continue;
         if (HistoryDealGetInteger(tk, DEAL_ENTRY) != DEAL_ENTRY_OUT) continue;
         double p = HistoryDealGetDouble(tk, DEAL_PROFIT)
                  + HistoryDealGetDouble(tk, DEAL_SWAP)
                  + HistoryDealGetDouble(tk, DEAL_COMMISSION);
         if (p >= 0) gProfit += p; else gLoss += -p;
         closed++;
      }
   }
   double bal    = AccountInfoDouble(ACCOUNT_BALANCE);
   double profit = bal - gStartBalance;
   double pf     = (gLoss > 0) ? gProfit / gLoss : (gProfit > 0 ? 100.0 : 0.0);
   Print("OnTester: profit=", DoubleToString(profit, 2),
         " PF=", DoubleToString(pf, 2),
         " DD=", DoubleToString(gMaxDD * 100.0, 2), "%",
         " trades=", closed,
         " balance=", DoubleToString(bal, 2));
   return profit;
}
