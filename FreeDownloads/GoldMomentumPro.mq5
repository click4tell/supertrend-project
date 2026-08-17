#property copyright   "GoldMomentumPro v3.00 - XAUUSD M1 momentum breakout"
#property version     "3.00"
#property description "Broker-aware: commission, swap, stops/freeze levels, margin & stop-out are read from the broker and used in lot sizing and trailing. REAL-TICKS VERDICT (2026 H1, XAUUSDb M1): negative expectancy; best config tested still loses -11%. NOT for live use without logic redesign."
#property strict

//====================================================================
//  INPUTS
//====================================================================
input group "=== Session Filter ==="
input bool  UseTimeFilter     = true;   // Use time filter
input int   TimeStartTrade    = 3;      // Start hour (server time)
input int   TimeEndTrade      = 22;     // End hour (server time)

input group "=== Trading Days ==="
input bool  Sunday            = false;
input bool  Monday            = true;
input bool  Tuesday           = true;
input bool  Wednesday         = true;
input bool  Thursday          = true;
input bool  Friday            = true;
input bool  Saturday          = false;

input group "=== Momentum Signal ==="
input int   Signal_2          = 60;     // Velocity threshold (points) [tuned on real ticks]
input int   Signal_2_Period   = 300;    // Velocity reference (points) [tuned on real ticks]
input int   VelocityTime      = 10;     // Velocity window (seconds)
input int   TradeDelta        = 100;    // Pending order distance (points)
input int   DeleteRatio       = 60;     // Pending delete ratio (%)

input group "=== Risk / Money Management ==="
input double FixedLot         = 0.0;    // Fixed lot (0 = use AutoMM)
input double AutoMM           = 1.0;    // Risk per trade (% of balance) [tuned on real ticks]
input int    StopLoss         = 100;    // Initial stop loss (points)
input int    TrailingLoss     = 100;    // Max loss cap before trail (points)
input int    TrailingStop     = 50;     // Trailing lock (points)
input int    MaxTradesPerDay  = 8;      // Max new trades per day
input int    MinSecondsBetweenEntries = 180; // Min seconds between entries

input group "=== Filters / Limits ==="
input int    Max_Spread       = 30;     // Max spread (points)
input int    TradeDeviation   = 3;      // Max concurrent trades (positions+pending)
input int    TickSample       = 100;    // Spread averaging sample
input int    Magic            = 56343;  // Magic number

//====================================================================
//  GLOBALS
//====================================================================
int      g_digits;
double   g_point       = 0.0;
double   g_tickValue   = 0.0;
double   g_tickSize    = 0.0;
double   g_moneyPerPointPerLot = 0.0;   // USD per point per 1.0 lot
double   g_stopsLevel  = 0.0;
double   g_freezeLevel = 0.0;
double   g_volMin      = 0.01;
double   g_volMax      = 100.0;
double   g_volStep     = 0.01;
double   g_swapLong    = 0.0;
double   g_swapShort   = 0.0;
int      g_swapMode    = 0;
double   g_commLong    = 0.0;           // commission per lot (buy)
double   g_commShort   = 0.0;           // commission per lot (sell)
double   g_marginCall  = 100.0;         // margin call level %
double   g_marginSO    = 50.0;          // stop-out level %
double   g_bid         = 0.0;
double   g_ask         = 0.0;
double   g_avgSpread   = 0.0;
double   g_maxSpread   = 0.0;
double   g_deleteRatio = 0.6;
int      g_TD          = 1;
int      g_TS          = 5;
int      g_lastBuyOrder  = 0;
int      g_lastSellOrder = 0;
datetime g_lastEntryTime = 0;
datetime g_dayStartStamp = 0;
int      g_tradesToday   = 0;
ulong    g_lastSeenPosTicket = 0;

#define  RING_MAX 512
double   g_tickBuf[RING_MAX];
int      g_tickTimeBuf[RING_MAX];
int      g_tickHead = 0, g_tickCount = 0;
double   g_spreadBuf[RING_MAX];
int      g_spreadHead = 0, g_spreadCount = 0;
double   g_rateChange = 0.0;

//====================================================================
//  HELPERS
//====================================================================
bool IsTest()
{
   return (bool)(MQLInfoInteger(MQL_TESTER) || MQLInfoInteger(MQL_OPTIMIZATION) ||
                 MQLInfoInteger(MQL_VISUAL_MODE) || AccountInfoInteger(ACCOUNT_TRADE_MODE) == ACCOUNT_TRADE_MODE_DEMO);
}

double NormalizeLots(double lots)
{
   if(g_volStep > 0.0) lots = MathFloor(lots / g_volStep + 0.0000001) * g_volStep;
   if(lots < g_volMin) lots = g_volMin;
   if(lots > g_volMax) lots = g_volMax;
   return NormalizeDouble(lots, 8);
}

// Broker data refresh (called on init and on first ticks)
void FetchBrokerData()
{
   g_digits       = (int)SymbolInfoInteger(_Symbol, SYMBOL_DIGITS);
   g_point        = SymbolInfoDouble(_Symbol, SYMBOL_POINT);
   g_tickValue    = SymbolInfoDouble(_Symbol, SYMBOL_TRADE_TICK_VALUE);
   g_tickSize     = SymbolInfoDouble(_Symbol, SYMBOL_TRADE_TICK_SIZE);
   g_stopsLevel   = (double)SymbolInfoInteger(_Symbol, SYMBOL_TRADE_STOPS_LEVEL);
   g_freezeLevel  = (double)SymbolInfoInteger(_Symbol, SYMBOL_TRADE_FREEZE_LEVEL);
   g_volMin       = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_MIN);
   g_volMax       = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_MAX);
   g_volStep      = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_STEP);
   g_swapLong     = SymbolInfoDouble(_Symbol, SYMBOL_SWAP_LONG);
   g_swapShort    = SymbolInfoDouble(_Symbol, SYMBOL_SWAP_SHORT);
   g_swapMode     = (int)SymbolInfoInteger(_Symbol, SYMBOL_SWAP_MODE);

   // Commission: this build has no SYMBOL_COMMISSION_* constants -> estimate from closed deals
   g_commLong  = 0.0;
   g_commShort = 0.0;
   if(HistorySelect(0, TimeCurrent()))
   {
      int start = MathMax(0, HistoryDealsTotal() - 200);
      for(int i = HistoryDealsTotal() - 1; i >= start; i--)
      {
         ulong d = HistoryDealGetTicket(i);
         if(d == 0) continue;
         if(HistoryDealGetString(d, DEAL_SYMBOL) != _Symbol) continue;
         double vol  = HistoryDealGetDouble(d, DEAL_VOLUME);
         double comm = HistoryDealGetDouble(d, DEAL_COMMISSION);
         if(vol > 0.0)
         {
            double perLot = MathAbs(comm / vol);
            if(HistoryDealGetInteger(d, DEAL_ENTRY) == DEAL_ENTRY_IN)
            {
               long dType = HistoryDealGetInteger(d, DEAL_TYPE);
               if(dType == DEAL_TYPE_BUY && perLot > 0.0)  g_commLong  = perLot;
               if(dType == DEAL_TYPE_SELL && perLot > 0.0) g_commShort = perLot;
            }
            if(g_commLong > 0.0 && g_commShort > 0.0) break;
         }
      }
   }

   if(g_volMin <= 0.0)     g_volMin     = 0.01;
   if(g_volStep <= 0.0)    g_volStep    = g_volMin;

   if(g_tickSize > 0.0 && g_tickValue > 0.0)
      g_moneyPerPointPerLot = g_tickValue * g_point / g_tickSize;
   else
      g_moneyPerPointPerLot = g_tickValue;   // fallback: broker reports per-point value
   if(g_moneyPerPointPerLot <= 0.0)
      g_moneyPerPointPerLot = 1.0;           // last-resort fallback

   g_marginCall = AccountInfoDouble(ACCOUNT_MARGIN_SO_CALL);
   g_marginSO   = AccountInfoDouble(ACCOUNT_MARGIN_SO_SO);
   if(g_marginCall <= 0.0) g_marginCall = 100.0;
   if(g_marginSO   <= 0.0) g_marginSO   = 50.0;

   g_maxSpread   = (double)Max_Spread * g_point;
   g_deleteRatio = (double)DeleteRatio / 100.0;
   g_TD          = MathMax(TradeDelta, (int)g_stopsLevel);
   g_TS          = MathMax(TrailingStop, (int)g_stopsLevel);
}

void PrintBrokerSummary()
{
   PrintFormat("GoldMomentumPro v3.00 | %s | digits=%d point=%.5f",
               _Symbol, g_digits, g_point);
   PrintFormat("  tickValue=%.4f  tickSize=%.5f  ->  %.4f USD per point per lot",
               g_tickValue, g_tickSize, g_moneyPerPointPerLot);
   PrintFormat("  stopsLevel=%d  freezeLevel=%d  volMin=%.2f  volMax=%.2f  step=%.2f",
               (int)g_stopsLevel, (int)g_freezeLevel, g_volMin, g_volMax, g_volStep);
   PrintFormat("  swapMode=%d  swapLong=%.2f  swapShort=%.2f  commLong=%.4f  commShort=%.4f",
               g_swapMode, g_swapLong, g_swapShort, g_commLong, g_commShort);
   PrintFormat("  marginCall=%.1f%%  stopOut=%.1f%%  leverage=%d",
               g_marginCall, g_marginSO, (int)AccountInfoInteger(ACCOUNT_LEVERAGE));
}

double SafePendingPrice(ENUM_ORDER_TYPE type, double price)
{
   double minGap = MathMax(g_point * 3.0, g_stopsLevel * g_point + g_point);
   if(type == ORDER_TYPE_BUY_STOP || type == ORDER_TYPE_BUY_LIMIT || type == ORDER_TYPE_BUY_STOP_LIMIT)
   {
      if(price < g_ask + minGap) price = g_ask + minGap;
   }
   else
   {
      if(price > g_bid - minGap) price = g_bid - minGap;
   }
   return NormalizeDouble(price, g_digits);
}

double SafeStopLoss(ENUM_ORDER_TYPE type, double price, double sl)
{
   double minGap = MathMax(g_point * 3.0, g_stopsLevel * g_point + g_point);
   if(type == ORDER_TYPE_BUY_STOP || type == ORDER_TYPE_BUY_LIMIT || type == ORDER_TYPE_BUY_STOP_LIMIT)
   {
      if(sl > g_bid - minGap) sl = g_bid - minGap;
      if(sl > price - minGap) sl = price - minGap;
   }
   else
   {
      if(sl < g_ask + minGap) sl = g_ask + minGap;
      if(sl < price + minGap) sl = price + minGap;
   }
   return NormalizeDouble(sl, g_digits);
}

bool ModifySL(ulong posTicket, double sl, double tp)
{
   MqlTradeRequest req = {};
   MqlTradeResult  res = {};
   req.action   = TRADE_ACTION_SLTP;
   req.symbol   = _Symbol;
   req.position = posTicket;
   req.sl       = NormalizeDouble(sl, g_digits);
   req.tp       = NormalizeDouble(tp, g_digits);
   return OrderSend(req, res);
}

ulong PlacePending(ENUM_ORDER_TYPE type, double lot, double price, double sl)
{
   MqlTradeRequest req = {};
   MqlTradeResult  res = {};
   req.action    = TRADE_ACTION_PENDING;
   req.symbol    = _Symbol;
   req.volume    = lot;
   req.type      = type;
   req.price     = SafePendingPrice(type, price);
   req.sl        = (sl > 0.0) ? SafeStopLoss(type, req.price, sl) : 0.0;
   req.tp        = 0.0;
   req.deviation = 0;
   req.magic     = Magic;
   req.comment   = "GoldMomentumPro";
   req.type_time = ORDER_TIME_GTC;
   for(int attempt = 0; attempt < 3; attempt++)
   {
      if(OrderSend(req, res)) return res.order;
      req.price = SafePendingPrice(type, req.price);
      req.sl    = (sl > 0.0) ? SafeStopLoss(type, req.price, sl) : 0.0;
   }
   return 0;
}

bool DeletePending(ulong ticket)
{
   MqlTradeRequest req = {};
   MqlTradeResult  res = {};
   req.action = TRADE_ACTION_REMOVE;
   req.order  = ticket;
   return OrderSend(req, res);
}

datetime DayStart(datetime t)
{
   MqlDateTime d;
   TimeToStruct(t, d);
   d.hour = 0; d.min = 0; d.sec = 0;
   return StructToTime(d);
}

int CountTradesToday()
{
   datetime from = DayStart(TimeCurrent());
   datetime to   = TimeCurrent() + 1;
   if(from >= to) return 0;
   if(!HistorySelect(from, to)) return 0;
   ulong ids[1024];
   int n = 0;
   int total = HistoryDealsTotal();
   for(int i = 0; i < total; i++)
   {
      ulong t = HistoryDealGetTicket(i);
      if(t == 0) continue;
      if(HistoryDealGetString(t, DEAL_SYMBOL) != _Symbol) continue;
      if((long)HistoryDealGetInteger(t, DEAL_MAGIC) != Magic) continue;
      if(HistoryDealGetInteger(t, DEAL_ENTRY) != DEAL_ENTRY_IN) continue;
      ulong pid = (ulong)HistoryDealGetInteger(t, DEAL_POSITION_ID);
      if(pid == 0) pid = t;
      bool found = false;
      for(int j = 0; j < n; j++)
         if(ids[j] == pid) { found = true; break; }
      if(!found && n < 1024) ids[n++] = pid;
   }
   return n;
}

//====================================================================
//  INIT
//====================================================================
int OnInit()
{
   FetchBrokerData();
   PrintBrokerSummary();
   g_dayStartStamp = DayStart(TimeCurrent());
   g_tradesToday   = CountTradesToday();

   g_lastSeenPosTicket = 0;
   for(int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong tk = PositionGetTicket(i);
      if(tk > g_lastSeenPosTicket) g_lastSeenPosTicket = tk;
   }
   return INIT_SUCCEEDED;
}

void OnDeinit(const int reason) { }

//====================================================================
//  SPREAD (weighted ring buffer)
//====================================================================
void UpdateSpread()
{
   if(!IsTest()) return;
   double s = g_ask - g_bid;
   g_spreadBuf[g_spreadHead] = s;
   g_spreadHead = (g_spreadHead + 1) % RING_MAX;
   if(g_spreadCount < RING_MAX) g_spreadCount++;

   int n = MathMin(g_spreadCount, TickSample);
   if(n <= 0) { g_avgSpread = s; return; }
   int idx = (g_spreadHead - n + RING_MAX) % RING_MAX;
   double sum = 0.0, wsum = 0.0, w = (double)n;
   for(int i = 0; i < n; i++)
   {
      sum  += g_spreadBuf[idx] * w;
      wsum += w;
      w    -= 1.0;
      idx   = (idx + 1) % RING_MAX;
   }
   g_avgSpread = (wsum > 0.0) ? sum / wsum : s;
}

//====================================================================
//  VELOCITY (ring buffer)
//====================================================================
void UpdateVelocity()
{
   int now = (int)TimeCurrent();
   g_tickBuf[g_tickHead]     = g_bid;
   g_tickTimeBuf[g_tickHead] = now;
   g_tickHead = (g_tickHead + 1) % RING_MAX;
   if(g_tickCount < RING_MAX) g_tickCount++;

   double priceThen = g_bid;
   for(int i = 0; i < g_tickCount; i++)
   {
      int idx = (g_tickHead - 1 - i + RING_MAX) % RING_MAX;
      if(now - g_tickTimeBuf[idx] > VelocityTime)
      {
         priceThen = g_tickBuf[idx];
         break;
      }
   }
   g_rateChange = g_bid - priceThen;
   if(g_rateChange / g_point > 5000.0) g_rateChange = 0.0;
}

//====================================================================
//  LOT SIZING - broker-aware (risk %, SL distance, commission, swap, margin, stop-out)
//====================================================================
double CalcLot()
{
   double riskPoints = MathMax((double)StopLoss, g_stopsLevel);
   if(riskPoints <= 0.0) riskPoints = 100.0;

   // round-trip costs per lot: entry+exit commission + worst-case one-night swap
   double roundTripCost = (g_commLong + g_commShort) + MathMax(MathAbs(g_swapLong), MathAbs(g_swapShort));
   double riskPerLot    = riskPoints * g_moneyPerPointPerLot + roundTripCost;
   if(riskPerLot <= 0.0) riskPerLot = 1.0;

   double lot = g_volMin;
   if(FixedLot > 0.0)
   {
      lot = NormalizeLots(FixedLot);
   }
   else
   {
      double riskMoney = AccountInfoDouble(ACCOUNT_BALANCE) * AutoMM / 100.0;
      lot = NormalizeLots(riskMoney / riskPerLot);
   }

   // ---- margin & stop-out safety ----
   double marginPerLot = 0.0;
   if(OrderCalcMargin(ORDER_TYPE_BUY, _Symbol, 1.0, g_ask, marginPerLot) && marginPerLot > 0.0)
   {
      double equity = AccountInfoDouble(ACCOUNT_EQUITY);
      double riskMoney2 = (FixedLot > 0.0) ? lot * riskPerLot : AccountInfoDouble(ACCOUNT_BALANCE) * AutoMM / 100.0;
      // keep margin level above stop-out even after the worst loss
      double capBySO = (equity - MathMax(riskMoney2, 0.0)) * (100.0 / g_marginSO) / marginPerLot;
      double capByFree = AccountInfoDouble(ACCOUNT_MARGIN_FREE) / marginPerLot;
      double cap = MathMin(capByFree, capBySO);
      if(cap > 0.0 && lot > cap) lot = NormalizeLots(cap);
   }

   if(lot < g_volMin) lot = g_volMin;
   if(lot > g_volMax) lot = g_volMax;
   return NormalizeLots(lot);
}

// Estimated money costs for an open position (commission + swap so far)
double PositionCosts(ENUM_POSITION_TYPE type, double lot, datetime posTime)
{
   double nights = (double)(TimeCurrent() - posTime) / 86400.0;
   if(nights < 0.0) nights = 0.0;
   double swapRate = (type == POSITION_TYPE_BUY) ? g_swapLong : g_swapShort;
   double swapMoney = swapRate * lot * nights;
   double commPerLot = (type == POSITION_TYPE_BUY) ? g_commLong : g_commShort;
   double commMoney = commPerLot * lot * 2.0;      // entry + exit estimate
   return swapMoney + commMoney;
}

//====================================================================
//  ON TICK
//====================================================================
void OnTick()
{
   MqlTick tick;
   if(!SymbolInfoTick(_Symbol, tick)) return;
   g_bid = tick.bid;
   g_ask = tick.ask;
   if(g_bid <= 0.0 || g_ask <= 0.0) return;

   // lazy broker-data refresh (tick value may be 0 until first ticks in tester)
   if(g_tickValue <= 0.0 || g_tickSize <= 0.0)
   {
      FetchBrokerData();
      PrintBrokerSummary();
   }

   MqlDateTime dt;
   TimeToStruct(TimeCurrent(), dt);
   if(!AllowedDay(dt.day_of_week)) return;

   bool timeOk = true;
   if(UseTimeFilter)
      timeOk = (dt.hour >= TimeStartTrade && dt.hour <= TimeEndTrade);

   datetime ds = DayStart(TimeCurrent());
   if(ds != g_dayStartStamp) { g_dayStartStamp = ds; g_tradesToday = CountTradesToday(); }

   UpdateSpread();
   UpdateVelocity();

   int totalTrades = 0;
   int totalBuyStop = 0, totalSellStop = 0;
   bool hasBuyPos = false, hasSellPos = false;

   // ---- pending orders ----
   for(int i = OrdersTotal() - 1; i >= 0; i--)
   {
      ulong tk = OrderGetTicket(i);
      if(tk == 0) continue;
      if(OrderGetString(ORDER_SYMBOL) != _Symbol) continue;
      if((long)OrderGetInteger(ORDER_MAGIC) != Magic) continue;
      totalTrades++;
      ENUM_ORDER_TYPE ot = (ENUM_ORDER_TYPE)OrderGetInteger(ORDER_TYPE);
      if(ot == ORDER_TYPE_BUY_STOP)
      {
         if((int)TimeCurrent() - g_lastBuyOrder > VelocityTime &&
            g_rateChange < Signal_2_Period * g_point * g_deleteRatio)
            DeletePending(tk);
         totalBuyStop++;
      }
      else if(ot == ORDER_TYPE_SELL_STOP)
      {
         if((int)TimeCurrent() - g_lastSellOrder > VelocityTime &&
            g_rateChange > -Signal_2_Period * g_point * g_deleteRatio)
            DeletePending(tk);
         totalSellStop++;
      }
   }

   // ---- positions ----
   for(int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong tk = PositionGetTicket(i);
      if(tk == 0) continue;
      if(PositionGetString(POSITION_SYMBOL) != _Symbol) continue;
      if((long)PositionGetInteger(POSITION_MAGIC) != Magic) continue;
      totalTrades++;

      if(tk > g_lastSeenPosTicket)
      {
         g_lastSeenPosTicket = tk;
         g_tradesToday++;
      }

      double openP  = PositionGetDouble(POSITION_PRICE_OPEN);
      double sl     = PositionGetDouble(POSITION_SL);
      double tp     = PositionGetDouble(POSITION_TP);
      double lot    = PositionGetDouble(POSITION_VOLUME);
      datetime posTime = (datetime)PositionGetInteger(POSITION_TIME);
      ENUM_POSITION_TYPE ptype = (ENUM_POSITION_TYPE)PositionGetInteger(POSITION_TYPE);

      // raw floating result in points
      double rawPoints = (ptype == POSITION_TYPE_BUY) ? (g_bid - openP) / g_point
                                                      : (openP - g_ask) / g_point;
      // costs in points (commission + swap so far)
      double costsMoney = PositionCosts(ptype, lot, posTime);
      double costPoints = (g_moneyPerPointPerLot * lot > 0.0) ? costsMoney / (g_moneyPerPointPerLot * lot) : 0.0;
      double netPoints  = rawPoints - costPoints;

      if(ptype == POSITION_TYPE_BUY)
      {
         hasBuyPos = true;
         if(netPoints > g_TS)
         {
            double newSL = g_bid - (g_TS + costPoints) * g_point;
            if(newSL > openP && (sl == 0.0 || newSL > sl) && newSL < g_bid - g_stopsLevel * g_point)
               ModifySL(tk, newSL, tp);
         }
         else if(rawPoints < -TrailingLoss)
         {
            double newSL = openP - TrailingLoss * g_point;
            if(newSL > g_bid - g_stopsLevel * g_point) newSL = g_bid - g_stopsLevel * g_point;
            if(sl == 0.0 || newSL > sl)
               ModifySL(tk, newSL, tp);
         }
      }
      else
      {
         hasSellPos = true;
         if(netPoints > g_TS)
         {
            double newSL = g_ask + (g_TS + costPoints) * g_point;
            if(newSL < openP && (sl == 0.0 || newSL < sl) && newSL > g_ask + g_stopsLevel * g_point)
               ModifySL(tk, newSL, tp);
         }
         else if(rawPoints < -TrailingLoss)
         {
            double newSL = openP + TrailingLoss * g_point;
            if(newSL < g_ask + g_stopsLevel * g_point) newSL = g_ask + g_stopsLevel * g_point;
            if(sl == 0.0 || newSL < sl)
               ModifySL(tk, newSL, tp);
         }
      }
   }

   // ---- straddle cleanup: remove opposite pending when one side is filled ----
   if(hasBuyPos && totalSellStop > 0)
   {
      for(int i = OrdersTotal() - 1; i >= 0; i--)
      {
         ulong tk = OrderGetTicket(i);
         if(tk == 0) continue;
         if(OrderGetString(ORDER_SYMBOL) != _Symbol) continue;
         if((long)OrderGetInteger(ORDER_MAGIC) != Magic) continue;
         if((ENUM_ORDER_TYPE)OrderGetInteger(ORDER_TYPE) == ORDER_TYPE_SELL_STOP)
            DeletePending(tk);
      }
   }
   if(hasSellPos && totalBuyStop > 0)
   {
      for(int i = OrdersTotal() - 1; i >= 0; i--)
      {
         ulong tk = OrderGetTicket(i);
         if(tk == 0) continue;
         if(OrderGetString(ORDER_SYMBOL) != _Symbol) continue;
         if((long)OrderGetInteger(ORDER_MAGIC) != Magic) continue;
         if((ENUM_ORDER_TYPE)OrderGetInteger(ORDER_TYPE) == ORDER_TYPE_BUY_STOP)
            DeletePending(tk);
      }
   }

   // ---- new entries ----
   if(totalTrades < TradeDeviation && timeOk)
   {
      if(g_tradesToday >= MaxTradesPerDay) return;
      if(TimeCurrent() - g_lastEntryTime < MinSecondsBetweenEntries) return;

      double lot = CalcLot();
      double margin = 0.0;
      if(!OrderCalcMargin(ORDER_TYPE_BUY, _Symbol, lot, g_ask, margin) || margin > AccountInfoDouble(ACCOUNT_MARGIN_FREE))
         return;

      if(g_rateChange > Signal_2_Period * g_point && g_avgSpread <= g_maxSpread && totalBuyStop < TradeDeviation)
      {
         double price = g_ask + (totalBuyStop + 1.0) * (g_point * g_TD);
         double sl    = (StopLoss > 0) ? price - StopLoss * g_point : 0.0;
         if(PlacePending(ORDER_TYPE_BUY_STOP, lot, price, sl) != 0)
         {
            g_lastBuyOrder  = (int)TimeCurrent();
            g_lastEntryTime = TimeCurrent();
         }
      }
      if(g_rateChange < -Signal_2_Period * g_point && g_avgSpread <= g_maxSpread && totalSellStop < TradeDeviation)
      {
         double price = g_bid - (totalSellStop + 1.0) * (g_point * g_TD);
         double sl    = (StopLoss > 0) ? price + StopLoss * g_point : 0.0;
         if(PlacePending(ORDER_TYPE_SELL_STOP, lot, price, sl) != 0)
         {
            g_lastSellOrder = (int)TimeCurrent();
            g_lastEntryTime = TimeCurrent();
         }
      }
   }
}

//====================================================================
//  TESTER REPORT (net of profit, swap and commission)
//====================================================================
double OnTester()
{
   double net = 0.0;
   if(HistorySelect(0, TimeCurrent()))
   {
      int total = HistoryDealsTotal();
      for(int i = 0; i < total; i++)
      {
         ulong t = HistoryDealGetTicket(i);
         if(t == 0) continue;
         if((long)HistoryDealGetInteger(t, DEAL_MAGIC) != Magic) continue;
         if(HistoryDealGetString(t, DEAL_SYMBOL) != _Symbol) continue;
         if(HistoryDealGetInteger(t, DEAL_ENTRY) != DEAL_ENTRY_OUT) continue;
         net += HistoryDealGetDouble(t, DEAL_PROFIT) +
                HistoryDealGetDouble(t, DEAL_SWAP) +
                HistoryDealGetDouble(t, DEAL_COMMISSION);
      }
   }
   return net;
}

//====================================================================
//  DAY FILTER
//====================================================================
bool AllowedDay(int dow)
{
   if(dow == 0 && !Sunday)    return false;
   if(dow == 1 && !Monday)    return false;
   if(dow == 2 && !Tuesday)   return false;
   if(dow == 3 && !Wednesday) return false;
   if(dow == 4 && !Thursday)  return false;
   if(dow == 5 && !Friday)    return false;
   if(dow == 6 && !Saturday)  return false;
   return true;
}
