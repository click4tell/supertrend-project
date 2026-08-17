#property copyright   "AurumTrend v1.00 - pullback reversal with H1 regime filter for XAUUSD"
#property version     "1.00"
#property description "Trend-following pullback: H1 EMA100 regime decides direction; M15 EMA20 pullback reversal entry; ATR stops/targets; EOD close avoids -64.7 long swap; spread filter; broker-aware sizing."
#property strict

//====================================================================
//  INPUTS
//====================================================================
input group "=== Trend Regime (H1) ==="
input int    RegimeEMA       = 100;    // H1 EMA for regime (0=off, both directions)
input bool   TradeBothWays   = true;   // true=long in uptrend/short in downtrend, false=long only

input group "=== Pullback Entry (M15) ==="
input int    PullEMA         = 20;     // M15 EMA for pullback
input int    ATR_Period      = 14;     // ATR period
input double SL_ATR          = 1.5;    // Stop loss = ATR x
input double TP_ATR          = 2.5;    // Take profit = ATR x
input double MaxDipATR       = 1.5;    // Max pullback depth (ATR) - skip deeper dips

input group "=== Risk ==="
input double FixedLot        = 0.0;    // Fixed lot (0 = AutoMM)
input double AutoMM          = 2.0;    // Risk per trade (% of balance)
input int    MaxTradesPerDay = 4;      // Max new trades per day
input int    MinSecondsBetweenEntries = 600;

input group "=== Management ==="
input double BE_ATR          = 1.0;    // Breakeven after ATR x profit
input double Trail_ATR       = 0.0;    // Trailing distance in ATR (0 = off)
input bool   CloseEOD        = true;   // Close all before swap hour
input int    EODHour         = 21;     // Server hour to close all

input group "=== Filters ==="
input bool   UseTimeFilter   = true;   // Use time filter
input int    TimeStartTrade  = 8;      // Start hour (server)
input int    TimeEndTrade    = 20;     // End hour (server)
input int    Max_Spread      = 20;     // Max spread (points)
input int    Magic           = 77203;  // Magic number

//====================================================================
//  GLOBALS
//====================================================================
int      g_digits;
double   g_point        = 0.0;
double   g_tickValue    = 0.0;
double   g_tickSize     = 0.0;
double   g_moneyPerPointPerLot = 0.0;
double   g_stopsLevel   = 0.0;
double   g_freezeLevel  = 0.0;
double   g_volMin       = 0.01;
double   g_volMax       = 100.0;
double   g_volStep      = 0.01;
double   g_swapLong     = 0.0;
double   g_swapShort    = 0.0;
double   g_commLong     = 0.0;
double   g_commShort    = 0.0;
double   g_marginSO     = 50.0;
double   g_bid          = 0.0;
double   g_ask          = 0.0;
double   g_maxSpread    = 0.0;
datetime g_lastBarTime  = 0;
datetime g_lastEntryTime= 0;
int      g_tradesToday  = 0;
datetime g_dayStartStamp= 0;
ulong    g_lastSeenPosTicket = 0;

int      hPull  = INVALID_HANDLE;
int      hATR   = INVALID_HANDLE;
int      hRegime= INVALID_HANDLE;

#define  ENTRY_TF PERIOD_M15

//====================================================================
//  HELPERS
//====================================================================
double NormalizeLots(double lots)
{
   if(g_volStep > 0.0) lots = MathFloor(lots / g_volStep + 0.0000001) * g_volStep;
   if(lots < g_volMin) lots = g_volMin;
   if(lots > g_volMax) lots = g_volMax;
   return NormalizeDouble(lots, 8);
}

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

   if(g_volMin <= 0.0)  g_volMin  = 0.01;
   if(g_volStep <= 0.0) g_volStep = g_volMin;

   if(g_tickSize > 0.0 && g_tickValue > 0.0)
      g_moneyPerPointPerLot = g_tickValue * g_point / g_tickSize;
   else
      g_moneyPerPointPerLot = g_tickValue;
   if(g_moneyPerPointPerLot <= 0.0)
      g_moneyPerPointPerLot = 1.0;

   g_marginSO = AccountInfoDouble(ACCOUNT_MARGIN_SO_SO);
   if(g_marginSO <= 0.0) g_marginSO = 50.0;
   g_maxSpread = (double)Max_Spread * g_point;
}

void PrintBrokerSummary()
{
   PrintFormat("AurumTrend v1.00 | %s | digits=%d point=%.5f", _Symbol, g_digits, g_point);
   PrintFormat("  tickValue=%.4f tickSize=%.5f -> %.4f USD/point/lot | vol %.2f..%.2f step %.2f",
               g_tickValue, g_tickSize, g_moneyPerPointPerLot, g_volMin, g_volMax, g_volStep);
   PrintFormat("  swapLong=%.2f swapShort=%.2f commLong=%.4f commShort=%.4f stopOut=%.1f%%",
               g_swapLong, g_swapShort, g_commLong, g_commShort, g_marginSO);
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

   hPull   = iMA(_Symbol, ENTRY_TF, PullEMA, 0, MODE_EMA, PRICE_CLOSE);
   hATR    = iATR(_Symbol, ENTRY_TF, ATR_Period);
   hRegime = (RegimeEMA > 0) ? iMA(_Symbol, PERIOD_H1, RegimeEMA, 0, MODE_EMA, PRICE_CLOSE) : INVALID_HANDLE;
   if(hPull == INVALID_HANDLE || hATR == INVALID_HANDLE || (RegimeEMA > 0 && hRegime == INVALID_HANDLE))
   {
      Print("AurumTrend: indicator handle creation failed");
      return INIT_FAILED;
   }

   g_dayStartStamp = DayStart(TimeCurrent());
   g_tradesToday   = CountTradesToday();
   g_lastBarTime   = iTime(_Symbol, ENTRY_TF, 0);

   g_lastSeenPosTicket = 0;
   for(int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong tk = PositionGetTicket(i);
      if(tk > g_lastSeenPosTicket) g_lastSeenPosTicket = tk;
   }
   return INIT_SUCCEEDED;
}

void OnDeinit(const int reason)
{
   if(hPull   != INVALID_HANDLE) IndicatorRelease(hPull);
   if(hATR    != INVALID_HANDLE) IndicatorRelease(hATR);
   if(hRegime != INVALID_HANDLE) IndicatorRelease(hRegime);
}

//====================================================================
//  LOT SIZING
//====================================================================
double CalcLot(double slPoints)
{
   if(slPoints <= 0.0) slPoints = MathMax(40.0, g_stopsLevel);
   double roundTripCost = (g_commLong + g_commShort) + MathMax(MathAbs(g_swapLong), MathAbs(g_swapShort));
   double riskPerLot    = slPoints * g_moneyPerPointPerLot + roundTripCost;
   if(riskPerLot <= 0.0) riskPerLot = 1.0;

   double lot = g_volMin;
   if(FixedLot > 0.0)
      lot = NormalizeLots(FixedLot);
   else
      lot = NormalizeLots(AccountInfoDouble(ACCOUNT_BALANCE) * AutoMM / 100.0 / riskPerLot);

   double marginPerLot = 0.0;
   if(OrderCalcMargin(ORDER_TYPE_BUY, _Symbol, 1.0, g_ask, marginPerLot) && marginPerLot > 0.0)
   {
      double equity = AccountInfoDouble(ACCOUNT_EQUITY);
      double riskMoney = (FixedLot > 0.0) ? lot * riskPerLot : AccountInfoDouble(ACCOUNT_BALANCE) * AutoMM / 100.0;
      double capBySO   = (equity - MathMax(riskMoney, 0.0)) * (100.0 / g_marginSO) / marginPerLot;
      double capByFree = AccountInfoDouble(ACCOUNT_MARGIN_FREE) / marginPerLot;
      double cap = MathMin(capByFree, capBySO);
      if(cap > 0.0 && lot > cap) lot = NormalizeLots(cap);
   }
   if(lot < g_volMin) lot = g_volMin;
   if(lot > g_volMax) lot = g_volMax;
   return NormalizeLots(lot);
}

//====================================================================
//  POSITION MANAGEMENT (breakeven + trail)
//====================================================================
void ManagePosition(ulong tk)
{
   if(!PositionSelectByTicket(tk)) return;
   if(PositionGetString(POSITION_SYMBOL) != _Symbol) return;
   if((long)PositionGetInteger(POSITION_MAGIC) != Magic) return;

   double openP = PositionGetDouble(POSITION_PRICE_OPEN);
   double sl    = PositionGetDouble(POSITION_SL);
   double tp    = PositionGetDouble(POSITION_TP);
   ENUM_POSITION_TYPE ptype = (ENUM_POSITION_TYPE)PositionGetInteger(POSITION_TYPE);

   double atrArr[1];
   if(CopyBuffer(hATR, 0, 0, 1, atrArr) != 1) return;
   double atr = atrArr[0];
   if(atr <= 0.0) return;
   double atrPts = atr / g_point;

   double rawPoints = (ptype == POSITION_TYPE_BUY) ? (g_bid - openP) / g_point
                                                   : (openP - g_ask) / g_point;

   if(rawPoints >= BE_ATR * atrPts)
   {
      double newSL;
      if(Trail_ATR > 0.0)
         newSL = (ptype == POSITION_TYPE_BUY) ? g_bid - Trail_ATR * atr : g_ask + Trail_ATR * atr;
      else
      {
         double buf = MathMax(3.0, g_stopsLevel) * g_point;
         newSL = (ptype == POSITION_TYPE_BUY) ? openP + buf : openP - buf;
      }
      if((sl == 0.0) ||
         (ptype == POSITION_TYPE_BUY  && newSL > sl) ||
         (ptype == POSITION_TYPE_SELL && newSL < sl))
      {
         MqlTradeRequest req = {};
         MqlTradeResult  res = {};
         req.action   = TRADE_ACTION_SLTP;
         req.symbol   = _Symbol;
         req.position = tk;
         req.sl       = NormalizeDouble(newSL, g_digits);
         req.tp       = NormalizeDouble(tp, g_digits);
         OrderSend(req, res);
      }
   }
}

//====================================================================
//  END-OF-DAY CLOSE (before swap charge)
//====================================================================
void CloseAllPositions(string comment)
{
   for(int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong tk = PositionGetTicket(i);
      if(tk == 0) continue;
      if(PositionGetString(POSITION_SYMBOL) != _Symbol) continue;
      if((long)PositionGetInteger(POSITION_MAGIC) != Magic) continue;
      ENUM_POSITION_TYPE ptype = (ENUM_POSITION_TYPE)PositionGetInteger(POSITION_TYPE);
      double lot = PositionGetDouble(POSITION_VOLUME);
      MqlTradeRequest req = {};
      MqlTradeResult  res = {};
      req.action   = TRADE_ACTION_DEAL;
      req.symbol   = _Symbol;
      req.volume   = lot;
      req.type     = (ptype == POSITION_TYPE_BUY) ? ORDER_TYPE_SELL : ORDER_TYPE_BUY;
      req.price    = (ptype == POSITION_TYPE_BUY) ? g_bid : g_ask;
      req.position = tk;
      req.deviation = 0;
      req.magic    = Magic;
      req.comment  = comment;
      OrderSend(req, res);
   }
}

//====================================================================
//  ENTRY SIGNAL - pullback reversal aligned with H1 regime
//====================================================================
bool EntrySignal(bool &buy)
{
   // H1 regime (completed bar 1)
   if(RegimeEMA > 0)
   {
      double rArr[1], hcArr[1];
      if(hRegime == INVALID_HANDLE) return false;
      if(CopyBuffer(hRegime, 0, 1, 1, rArr) != 1) return false;
      if(CopyClose(_Symbol, PERIOD_H1, 1, 1, hcArr) != 1) return false;
      bool regimeUp = (hcArr[0] > rArr[0]);
      if(!TradeBothWays && !regimeUp) return false;
      if(!regimeUp) buy = false;      // downtrend -> sell only
      else          buy = true;       // uptrend  -> buy only
   }
   else
   {
      buy = true;   // no regime filter -> long only path (TradeBothWays controls shorts below)
   }

   // M15 pullback reversal (completed bars 1 and 2)
   double emaArr[2], atrArr[2], closeArr[2], lowArr[2], highArr[2];
   if(CopyBuffer(hPull, 0, 1, 2, emaArr)  != 2) return false;
   if(CopyBuffer(hATR,  0, 1, 2, atrArr)  != 2) return false;
   if(CopyClose(_Symbol, ENTRY_TF, 1, 2, closeArr) != 2) return false;
   if(CopyLow(_Symbol, ENTRY_TF, 1, 2, lowArr)  != 2) return false;
   if(CopyHigh(_Symbol, ENTRY_TF, 1, 2, highArr) != 2) return false;

   // closeArr[0]=bar1(older), closeArr[1]=bar0(newer); same for ema/low/high
   bool pullbackUp = (closeArr[0] < emaArr[0]) && (closeArr[1] > emaArr[1]);   // dip below EMA then close back above
   bool pullbackDn = (closeArr[0] > emaArr[0]) && (closeArr[1] < emaArr[1]);   // bounce above EMA then close back below

   if(buy && pullbackUp)
   {
      // skip too-deep dips (price pierced more than MaxDipATR below EMA)
      if(MaxDipATR > 0.0 && atrArr[1] > 0.0 &&
         (emaArr[0] - lowArr[0]) > MaxDipATR * atrArr[0]) return false;
      return true;
   }
   if(!buy && TradeBothWays && pullbackDn)
   {
      if(MaxDipATR > 0.0 && atrArr[1] > 0.0 &&
         (highArr[0] - emaArr[0]) > MaxDipATR * atrArr[0]) return false;
      return true;
   }
   return false;
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

   if(g_tickValue <= 0.0 || g_tickSize <= 0.0)
   {
      FetchBrokerData();
      PrintBrokerSummary();
   }

   MqlDateTime dt;
   TimeToStruct(TimeCurrent(), dt);
   if(dt.day_of_week == 0 || dt.day_of_week == 6) return;   // weekend off

   datetime ds = DayStart(TimeCurrent());
   if(ds != g_dayStartStamp) { g_dayStartStamp = ds; g_tradesToday = CountTradesToday(); }

   // EOD close before swap hour
   if(CloseEOD && dt.hour >= EODHour)
   {
      if(PositionsTotal() > 0) CloseAllPositions("EOD");
      return;
   }

   for(int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong tk = PositionGetTicket(i);
      if(tk == 0) continue;
      if(tk > g_lastSeenPosTicket) { g_lastSeenPosTicket = tk; g_tradesToday++; }
      ManagePosition(tk);
   }

   datetime barTime = iTime(_Symbol, ENTRY_TF, 0);
   if(barTime == g_lastBarTime) return;
   g_lastBarTime = barTime;

   if(UseTimeFilter && (dt.hour < TimeStartTrade || dt.hour > TimeEndTrade)) return;
   if(g_ask - g_bid > g_maxSpread) return;
   if(PositionsTotal() > 0) return;
   if(g_tradesToday >= MaxTradesPerDay) return;
   if(TimeCurrent() - g_lastEntryTime < MinSecondsBetweenEntries) return;

   bool buy = true;
   if(!EntrySignal(buy)) return;

   double atrArr[1];
   if(CopyBuffer(hATR, 0, 1, 1, atrArr) != 1) return;
   double atr = atrArr[0];
   if(atr <= 0.0) return;
   double slDist = MathMax(SL_ATR * atr, g_stopsLevel * g_point + g_point);
   double tpDist = TP_ATR * atr;

   double lot = CalcLot(slDist / g_point);
   double margin = 0.0;
   if(!OrderCalcMargin(ORDER_TYPE_BUY, _Symbol, lot, g_ask, margin) || margin > AccountInfoDouble(ACCOUNT_MARGIN_FREE))
      return;

   MqlTradeRequest req = {};
   MqlTradeResult  res = {};
   req.action    = TRADE_ACTION_DEAL;
   req.symbol    = _Symbol;
   req.volume    = lot;
   req.deviation = 0;
   req.magic     = Magic;
   req.comment   = "AurumTrend";
   req.type_time = ORDER_TIME_GTC;
   if(buy)
   {
      req.type  = ORDER_TYPE_BUY;
      req.price = g_ask;
      req.sl    = NormalizeDouble(g_ask - slDist, g_digits);
      req.tp    = NormalizeDouble(g_ask + tpDist, g_digits);
   }
   else
   {
      req.type  = ORDER_TYPE_SELL;
      req.price = g_bid;
      req.sl    = NormalizeDouble(g_bid + slDist, g_digits);
      req.tp    = NormalizeDouble(g_bid - tpDist, g_digits);
   }
   if(OrderSend(req, res))
      g_lastEntryTime = TimeCurrent();
}

//====================================================================
//  TESTER REPORT
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
