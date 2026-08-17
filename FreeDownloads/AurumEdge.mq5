#property copyright   "AurumEdge v1.00 - trend-following pullback for XAUUSD M1"
#property version     "1.00"
#property description "Redesigned for REAL-TICKS viability: H1 trend filter, M1 EMA pullback entry, ATR-based SL/TP, spread filter, end-of-day close (avoids negative overnight swap), broker-aware lot sizing."
#property strict

//====================================================================
//  INPUTS
//====================================================================
input group "=== Trend Filter (H1) ==="
input int    TrendEMA        = 100;    // H1 EMA period (trend)

input group "=== Entry Timing (M1) ==="
input int    SignalEMA       = 20;     // M1 EMA period (pullback)
input int    ATR_Period      = 14;     // ATR period (M1)
input double SL_ATR          = 1.5;    // Stop loss = ATR x
input double TP_ATR          = 2.5;    // Take profit = ATR x

input group "=== Risk ==="
input double FixedLot        = 0.0;    // Fixed lot (0 = AutoMM)
input double AutoMM          = 2.0;    // Risk per trade (% of balance)
input int    MaxTradesPerDay = 6;      // Max new trades per day
input int    MinSecondsBetweenEntries = 300;

input group "=== Position Management ==="
input double BE_ATR          = 1.0;    // Move to breakeven after ATR x profit
input double Trail_ATR       = 0.0;    // Trailing distance in ATR (0 = off)
input bool   CloseEOD        = true;   // Close all before end of day
input int    EODHour         = 22;     // Server hour to close all positions

input group "=== Filters ==="
input bool   UseTimeFilter   = true;   // Use time filter
input int    TimeStartTrade  = 8;      // Start hour (server)
input int    TimeEndTrade    = 20;     // End hour (server)
input int    Max_Spread      = 20;     // Max spread (points)
input int    Magic           = 77201;  // Magic number

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

int      hTrend  = INVALID_HANDLE;
int      hSignal = INVALID_HANDLE;
int      hATR    = INVALID_HANDLE;

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
   PrintFormat("AurumEdge v1.00 | %s | digits=%d point=%.5f", _Symbol, g_digits, g_point);
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

   hTrend  = iMA(_Symbol, PERIOD_H1, TrendEMA,  0, MODE_EMA, PRICE_CLOSE);
   hSignal = iMA(_Symbol, _Period,  SignalEMA, 0, MODE_EMA, PRICE_CLOSE);
   hATR    = iATR(_Symbol, _Period, ATR_Period);
   if(hTrend == INVALID_HANDLE || hSignal == INVALID_HANDLE || hATR == INVALID_HANDLE)
   {
      Print("AurumEdge: indicator handle creation failed");
      return INIT_FAILED;
   }

   g_dayStartStamp = DayStart(TimeCurrent());
   g_tradesToday   = CountTradesToday();
   g_lastBarTime   = iTime(_Symbol, _Period, 0);

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
   if(hTrend  != INVALID_HANDLE) IndicatorRelease(hTrend);
   if(hSignal != INVALID_HANDLE) IndicatorRelease(hSignal);
   if(hATR    != INVALID_HANDLE) IndicatorRelease(hATR);
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
//  POSITION MANAGEMENT (breakeven + trail), executed every tick
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
   double atrPoints = atr / g_point;

   double rawPoints = (ptype == POSITION_TYPE_BUY) ? (g_bid - openP) / g_point
                                                   : (openP - g_ask) / g_point;
   double BEpoints = BE_ATR * atrPoints;

   if(rawPoints >= BEpoints)
   {
      double newSL;
      if(Trail_ATR > 0.0)
      {
         // trailing behind the price
         if(ptype == POSITION_TYPE_BUY)
            newSL = g_bid - Trail_ATR * atr;
         else
            newSL = g_ask + Trail_ATR * atr;
      }
      else
      {
         // simple breakeven (entry + small buffer)
         double buf = MathMax(3.0, g_stopsLevel) * g_point;
         newSL = (ptype == POSITION_TYPE_BUY) ? openP + buf : openP - buf;
      }
      if(ptype == POSITION_TYPE_BUY && newSL < openP + g_point) newSL = openP + g_point;
      if(ptype == POSITION_TYPE_SELL && newSL > openP - g_point) newSL = openP - g_point;

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
//  END-OF-DAY CLOSE (avoid negative overnight swap)
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
//  ENTRY SIGNAL - evaluated once per new M1 bar
//====================================================================
bool EntrySignal(bool &buy)
{
   // --- H1 trend (completed bar, shift 1) ---
   double trendArr[1], closeArr[1];
   if(CopyBuffer(hTrend, 0, 1, 1, trendArr) != 1) return false;
   if(CopyClose(_Symbol, PERIOD_H1, 1, 1, closeArr) != 1) return false;
   bool trendUp = (closeArr[0] > trendArr[0]);

   // --- M1 pullback cross (completed bars, shifts 1 and 2) ---
   double sigArr[2], closeM[2];
   if(CopyBuffer(hSignal, 0, 1, 2, sigArr) != 2) return false;
   if(CopyClose(_Symbol, _Period, 1, 2, closeM) != 2) return false;
   // closeM[0] = bar 1 (older), closeM[1] = bar 0 (newer); arrays are in order [0..1] from shift 1
   bool crossUp   = (closeM[0] <= sigArr[0] && closeM[1] > sigArr[1]);
   bool crossDown = (closeM[0] >= sigArr[0] && closeM[1] < sigArr[1]);

   if(trendUp && crossUp)  { buy = true;  return true; }
   if(!trendUp && crossDown){ buy = false; return true; }
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
   if(!AllowedDay(dt.day_of_week)) return;

   // end of day close
   if(CloseEOD && dt.hour >= EODHour)
   {
      if(PositionsTotal() > 0) CloseAllPositions("EOD close");
      return;
   }

   // new day counter refresh
   datetime ds = DayStart(TimeCurrent());
   if(ds != g_dayStartStamp) { g_dayStartStamp = ds; g_tradesToday = CountTradesToday(); }

   double spread = g_ask - g_bid;

   // ---- manage open position ----
   for(int i = PositionsTotal() - 1; i >= 0; i--)
   {
      ulong tk = PositionGetTicket(i);
      if(tk == 0) continue;
      if(tk > g_lastSeenPosTicket) { g_lastSeenPosTicket = tk; g_tradesToday++; }
      ManagePosition(tk);
   }

   // ---- entry on new bar ----
   datetime barTime = iTime(_Symbol, _Period, 0);
   if(barTime == g_lastBarTime) return;
   g_lastBarTime = barTime;

   // filters
   if(UseTimeFilter && (dt.hour < TimeStartTrade || dt.hour > TimeEndTrade)) return;
   if(spread > g_maxSpread) return;
   if(PositionsTotal() > 0) return;              // only 1 position at a time
   if(g_tradesToday >= MaxTradesPerDay) return;
   if(TimeCurrent() - g_lastEntryTime < MinSecondsBetweenEntries) return;

   bool buy = true;
   if(!EntrySignal(buy)) return;

   // ATR for SL/TP
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
   req.comment   = "AurumEdge";
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
   {
      g_lastEntryTime = TimeCurrent();
   }
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

//====================================================================
//  DAY FILTER
//====================================================================
bool AllowedDay(int dow)
{
   if(dow == 0 || dow == 6) return false;   // weekend off
   return true;
}
