//+------------------------------------------------------------------+
//| ForexTrend Professional EA - Version 1.74 (Linear Profit)        |
//| Based on v1.70 (Fixed & Clean)                                   |
//| New features for smoother / more linear equity curve:            |
//|  1) Trailing stop (start + distance in ATR multiples)            |
//|  2) Cooldown bars after position close (avoids whipsaw)          |
//|  3) Risk-based lot sizing (fixed % of equity per trade)          |
//|  4) Max equity drawdown guard (pauses new entries)               |
//+------------------------------------------------------------------+
#property copyright "KM@2025"
#property link      "https://mql5expert.ir"
#property description "Trading involves high risks, including potential loss of capital.\n The Multi-TF SuperTrend EA is provided as is without any warranties.\n Past performance is not indicative of future results.\n The developer is not liable for any losses or damages \n arising from the use of this EA.\n Use at your own risk and consult a financial advisor"
#property version   "1.74"
#property strict

//--- Input Parameters
input string info = "(Period = H1) (Symbol = XAUUSD)";
input string ActivationPassword = "";               // Activator Code (REAL accounts only)
input double ATR_Multiplier_SL_Base = 1.7;          // ATR Multiplier for Stop Loss
input double ATR_Multiplier_TP_Base = 2.3;          // ATR Multiplier for Take Profit
input double BaseLotSize = 0.01;                    // Base Lot Size
input double LotIncrementPer1000 = 0.01;            // Lot Increment per $1000
input int    ATR_Period = 35;                       // ATR Period
input double MaxATRThreshold = 1410.0;              // Max ATR (points; XAUUSD H1 ~300-900)
input double MinATRThreshold = 300.0;               // Min ATR (points; skip low-vol/dead market)
input double MaxSpread = 50.0;                      // Max Spread (points; XAUUSD ~40-60, FX ~15)
input int    TradingStartHour = 0;                  // Trading Start Hour (server time)
input int    TradingEndHour = 23;                   // Trading End Hour (server time)
input int    MaxTradesPerBar = 1;                   // Max Trades per Bar (current timeframe)
input int    SuperTrend_ATR_Period = 35;            // SuperTrend ATR Period
input double SuperTrend_Multiplier = 16.0;          // SuperTrend Multiplier
input int    MinTimeframesForSignal = 4;            // Minimum timeframes for signal (1-9)
input bool   EnableRegimeFilter = true;             // Require D1+W1 SuperTrend alignment (regime gate)
input bool   EnableHedging = false;                 // Enable Hedging Mode
input bool   EnableDashboard = true;                // Enable Dashboard Display
input int    Dashboard_X = 20;                      // Dashboard X Distance
input int    Dashboard_Y = 20;                      // Dashboard Y Distance
input int    MagicNumber = 202509;                  // Magic number for trades
input datetime FixedExpirationDate = D'2030.12.31'; // Fixed Expiration Date (YYYY.MM.DD)
//--- Linear-profit additions (v1.71)
input bool   EnableTrailingStop = true;             // Enable Trailing Stop
input double TrailingStartATR = 1.0;                // Trailing Start (ATR multiples in profit)
input double TrailingDistanceATR = 1.0;             // Trailing Distance (ATR multiples)
input int    CooldownBarsAfterExit = 3;             // Cooldown bars after close (0=off)
input bool   EnableRiskBasedSizing = true;          // Risk-based lot sizing
input double RiskPercentPerTrade = 0.5;             // Risk % of equity per trade
input bool   EnableMaxDrawdownGuard = true;         // Pause new entries after max DD
input double MaxEquityDrawdownPct = 15.0;           // Max equity drawdown % (pause threshold)
input int    DrawdownResetBars = 24;                // Reset DD peak after N bars without new high
input bool   EnableBreakEven = true;                // Move SL to breakeven after profit
input double BreakEvenTriggerATR = 1.2;             // Break-even trigger (ATR multiples)
input double BreakEvenBufferATR = 0.2;              // Break-even SL buffer (ATR multiples)

// Hardcoded whitelisted activation codes (for specific accounts - no input needed)
//string allowed_codes[] = {"PUQQMSkffHo=","Cyopo0tdz0A=","kMZkyq/B5As=","P7U5gVWO/W8=","44VvirgL4u4=","GnGljXniNdg=","BBaJf67Vah0=","XoHgIqCQ+hg="};
string allowed_codes[] = {};

//--- Global Variables
int atr_handles[];                 // ATR handles per TF (for supertrend)
ENUM_TIMEFRAMES tf_values[];       // timeframes array
string tf_names[];                 // names for dashboard
int directions[];                  // direction per tf (1 up, -1 down, 0 unknown)
int trend_counts[];                // consecutive bars count per tf
int atrHandle = INVALID_HANDLE;    // ATR handle for SL/TP
double atrBuffer[];                // ATR buffer
int tradesInCurrentBar = 0;
datetime currentBarStartTime = 0;
datetime lastDashboardBarTime = 0; // dashboard refresh on new bar only
datetime lastATRBarTime = 0;       // ATR cache per bar
double cachedATRPoints = 0.0;      // ATR value in points (previous closed bar)
static double point;
static int digits;
long stopsLevel;
int up_count, down_count, neutral_count;
int overall_signal = 0;            // 1: BUY, -1: SELL, 0: Neutral
bool is_hedging = false;
datetime lastCalcTimes[9];         // last bar times per TF
//--- Linear-profit globals (v1.71)
datetime lastExitBarTime = 0;      // bar time when last position was closed
double peakEquity = 0.0;           // peak equity for drawdown guard
datetime lastPeakBarTime = 0;      // bar time of the last equity peak
datetime lastTrailBarTime = 0;     // trailing stop updated once per bar
datetime lastBreakEvenBarTime = 0;  // break-even updated once per bar
int positionsPrev = 0;             // previous position count (exit detection)

//--- Validated copies of inputs (input vars cannot be modified at runtime)
int g_tradeStartHour = 0;
int g_tradeEndHour = 24;
int g_minTFs = 5;

//--- Colors for Dashboard
color COLOR_UP = clrLime;
color COLOR_DOWN = clrOrangeRed;
color COLOR_SIGNAL_BUY = clrLime;
color COLOR_SIGNAL_SELL = clrOrangeRed;
color COLOR_NEUTRAL = clrGray;
color COLOR_BG = clrNavy;
color COLOR_TEXT = clrWhite;
color COLOR_TITLE = clrYellow;
color COLOR_SUCCESS = clrLime;
color COLOR_ERROR = clrRed;

//+------------------------------------------------------------------+
//| Expert initialization function                                   |
//+------------------------------------------------------------------+
int OnInit()
{
   // Check if in testing/backtest mode
   bool is_testing = MQLInfoInteger(MQL_TESTER);
   ENUM_ACCOUNT_TRADE_MODE account_type = (ENUM_ACCOUNT_TRADE_MODE)AccountInfoInteger(ACCOUNT_TRADE_MODE);
   string trade_mode = (account_type == ACCOUNT_TRADE_MODE_DEMO) ? "demo" :
                       (account_type == ACCOUNT_TRADE_MODE_CONTEST) ? "contest" : "real";

   // Activation required ONLY on real accounts (not demo / contest / backtest)
   bool require_activation = (account_type == ACCOUNT_TRADE_MODE_REAL) && !is_testing;
   if(require_activation)
   {
      Print("Activation password is required for REAL accounts only.");
      string client = IntegerToString(AccountInfoInteger(ACCOUNT_LOGIN));
      if(!CheckActivation(client, ActivationPassword))
      {
         Alert("اطلاعات خود را از زیر کپی کنید و برای فروشنده ارسال نمایید");
         Alert("https://t.me/Mq5_expert_robot_bot");
         Alert(client);
         ShowClientInfoDialog(client);
         return(INIT_FAILED);
      }
   }

   // Fixed expiration check (skipped in backtest mode)
   if(!is_testing && TimeCurrent() > FixedExpirationDate)
   {
      Alert("Expert has reached fixed expiration date! Please contact the vendor.");
      return(INIT_FAILED);
   }

   Comment("Mode = ", trade_mode);

   // basic checks
   if(AccountInfoInteger(ACCOUNT_TRADE_ALLOWED) == 0)
   {
      Print("Trading is not allowed on this account.");
      return(INIT_FAILED);
   }
   if(SymbolInfoDouble(_Symbol, SYMBOL_BID) <= 0.0)
   {
      Print("Symbol bid price not available.");
      return(INIT_FAILED);
   }

   is_hedging = EnableHedging;

   point = _Point;
   digits = _Digits;

   // read stops level correctly
   stopsLevel = SymbolInfoInteger(_Symbol, SYMBOL_TRADE_STOPS_LEVEL);
   if(stopsLevel <= 0) stopsLevel = 100; // default

   // validate session hours
   g_tradeStartHour = (TradingStartHour >= 0 && TradingStartHour <= 23) ? TradingStartHour : 0;
   g_tradeEndHour   = (TradingEndHour >= 1 && TradingEndHour <= 24) ? TradingEndHour : 24;
   if(g_tradeStartHour >= g_tradeEndHour)
   {
      PrintFormat("Invalid trading session (%d-%d). Using 0-24.", g_tradeStartHour, g_tradeEndHour);
      g_tradeStartHour = 0;
      g_tradeEndHour = 24;
   }
   g_minTFs = MathMax(1, MathMin(9, MinTimeframesForSignal));

   // ATR handle for current timeframe (used for SL/TP calculations)
   atrHandle = iATR(_Symbol, PERIOD_CURRENT, ATR_Period);
   if(atrHandle == INVALID_HANDLE)
   {
      Print("Failed to create ATR indicator handle for current timeframe.");
      return(INIT_FAILED);
   }

   // prepare arrays for 9 timeframes
   ArrayResize(atr_handles, 9);
   ArrayResize(tf_values, 9);
   ArrayResize(tf_names, 9);
   ArrayResize(directions, 9);
   ArrayResize(trend_counts, 9);

   // assign timeframes and names
   tf_values[0] = PERIOD_M1;   tf_names[0] = "1 Minute";
   tf_values[1] = PERIOD_M5;   tf_names[1] = "5 Minutes";
   tf_values[2] = PERIOD_M15;  tf_names[2] = "15 Minutes";
   tf_values[3] = PERIOD_M30;  tf_names[3] = "30 Minutes";
   tf_values[4] = PERIOD_H1;   tf_names[4] = "1 Hour";
   tf_values[5] = PERIOD_H4;   tf_names[5] = "4 Hours";
   tf_values[6] = PERIOD_D1;   tf_names[6] = "Daily";
   tf_values[7] = PERIOD_W1;   tf_names[7] = "Weekly";
   tf_values[8] = PERIOD_MN1;  tf_names[8] = "Monthly";

   // create ATR handles for SuperTrend calculation per TF
   for(int k = 0; k < 9; k++)
   {
      atr_handles[k] = iATR(_Symbol, tf_values[k], SuperTrend_ATR_Period);
      if(atr_handles[k] == INVALID_HANDLE)
      {
         PrintFormat("Failed to create ATR handle for TF %s", tf_names[k]);
         return(INIT_FAILED);
      }
      lastCalcTimes[k] = 0;
      directions[k] = 0;
      trend_counts[k] = 0;
   }

   ArraySetAsSeries(atrBuffer, true);

   peakEquity = AccountInfoDouble(ACCOUNT_EQUITY);
   lastPeakBarTime = TimeCurrent();
   positionsPrev = 0;

   // initial compute
   LoadAndComputeSuperTrend();

   Print("ForexTrend Pro v1.74 (Linear) initialized.");
   return(INIT_SUCCEEDED);
}

//+------------------------------------------------------------------+
//| Expert deinitialization function                                 |
//+------------------------------------------------------------------+
void OnDeinit(const int reason)
{
   if(atrHandle != INVALID_HANDLE) IndicatorRelease(atrHandle);
   for(int k = 0; k < ArraySize(atr_handles); k++)
   {
      if(atr_handles[k] != INVALID_HANDLE) IndicatorRelease(atr_handles[k]);
   }

   // delete dashboard and client-info objects if created
   for(int i = ObjectsTotal(0) - 1; i >= 0; i--)
   {
      string nm = ObjectName(0, i);
      if(StringFind(nm, "ForexTrend_Dashboard_", 0) == 0 ||
         StringFind(nm, "ClientInfo", 0) == 0)
         ObjectDelete(0, nm);
   }
}

//+------------------------------------------------------------------+
//| Check trading session (server time)                              |
//+------------------------------------------------------------------+
bool IsTradingSessionValid()
{
   MqlDateTime timeStruct;
   TimeToStruct(TimeTradeServer(), timeStruct);
   int hour = timeStruct.hour % 24;
   int minute = timeStruct.min;

   // avoid Fri close / Mon open micro-gap
   if(timeStruct.day_of_week == 5 && hour == 23 && minute >= 55) return false;
   if(timeStruct.day_of_week == 1 && hour == 0 && minute < 1) return false;

   return hour >= g_tradeStartHour && hour < g_tradeEndHour;
}

//+------------------------------------------------------------------+
//| Compute trend direction and count for a given timeframe          |
//| (standard SuperTrend with final upper/lower band logic)          |
//+------------------------------------------------------------------+
void ComputeTrend(ENUM_TIMEFRAMES tf, int atr_handle_local, int &direction, int &trend_count)
{
   int calc_bars = MathMin(200, Bars(_Symbol, tf));
   if(calc_bars < SuperTrend_ATR_Period + 1)
   {
      direction = 0;
      trend_count = 0;
      return;
   }

   double high[], low[], close[], atrb[];
   ArrayResize(high, calc_bars);
   ArrayResize(low, calc_bars);
   ArrayResize(close, calc_bars);
   ArrayResize(atrb, calc_bars);

   if(CopyHigh(_Symbol, tf, 0, calc_bars, high) < calc_bars ||
      CopyLow(_Symbol, tf, 0, calc_bars, low) < calc_bars ||
      CopyClose(_Symbol, tf, 0, calc_bars, close) < calc_bars ||
      CopyBuffer(atr_handle_local, 0, 0, calc_bars, atrb) < calc_bars)
   {
      direction = 0;
      trend_count = 0;
      return;
   }

   // Arrays not as series: index 0 oldest, calc_bars-1 newest
   double st_upper[], st_lower[];
   ArrayResize(st_upper, calc_bars);
   ArrayResize(st_lower, calc_bars);
   int trend_arr[];
   ArrayResize(trend_arr, calc_bars);

   int pos = SuperTrend_ATR_Period;
   for(int j = pos; j < calc_bars; j++)
   {
      double hl2 = (high[j] + low[j]) / 2.0;
      double atrv = atrb[j];

      if(atrv <= 0.0)
      {
         if(j > pos)
         {
            trend_arr[j] = trend_arr[j-1];
            st_upper[j] = st_upper[j-1];
            st_lower[j] = st_lower[j-1];
         }
         else
         {
            trend_arr[j] = 0;
            st_upper[j] = hl2;
            st_lower[j] = hl2;
         }
         continue;
      }

      double basic_upper = hl2 + SuperTrend_Multiplier * atrv;
      double basic_lower = hl2 - SuperTrend_Multiplier * atrv;

      if(j == pos)
      {
         st_upper[j] = basic_upper;
         st_lower[j] = basic_lower;
         trend_arr[j] = (close[j] >= hl2) ? 1 : -1;
      }
      else
      {
         // --- Standard SuperTrend final bands ---
         if(basic_upper < st_upper[j-1] || close[j-1] > st_upper[j-1])
            st_upper[j] = basic_upper;
         else
            st_upper[j] = st_upper[j-1];

         if(basic_lower > st_lower[j-1] || close[j-1] < st_lower[j-1])
            st_lower[j] = basic_lower;
         else
            st_lower[j] = st_lower[j-1];

         if(trend_arr[j-1] == 1)
            trend_arr[j] = (close[j] <= st_lower[j]) ? -1 : 1;
         else
            trend_arr[j] = (close[j] >= st_upper[j]) ? 1 : -1;
      }
   }

   direction = trend_arr[calc_bars-1];
   if(direction == 0)
   {
      double hl2_current = (high[calc_bars-1] + low[calc_bars-1]) / 2.0;
      direction = (close[calc_bars-1] >= hl2_current) ? 1 : -1;
   }

   // count consecutive same direction from newest back
   trend_count = 1;
   for(int j = calc_bars - 2; j >= pos; j--)
   {
      if(trend_arr[j] == direction) trend_count++;
      else break;
   }
}

//+------------------------------------------------------------------+
//| Load indicator data and compute multi-TF SuperTrend             |
//+------------------------------------------------------------------+
bool LoadAndComputeSuperTrend()
{
   for(int k = 0; k < 9; k++)
   {
      datetime barTime = iTime(_Symbol, tf_values[k], 0);
      if(barTime != lastCalcTimes[k]) // only when new bar in that TF
      {
         ComputeTrend(tf_values[k], atr_handles[k], directions[k], trend_counts[k]);
         lastCalcTimes[k] = barTime;
      }
   }

   up_count = 0;
   down_count = 0;
   neutral_count = 0;
   for(int k = 0; k < 9; k++)
   {
      if(directions[k] == 1) up_count++;
      else if(directions[k] == -1) down_count++;
      else neutral_count++;
   }

   if(up_count >= g_minTFs)
      overall_signal = 1; // BUY
   else if(down_count >= g_minTFs)
      overall_signal = -1; // SELL
   else
      overall_signal = 0; // NEUTRAL

   return true;
}

//+------------------------------------------------------------------+
//| Load ATR data for SL/TP calculation                              |
//+------------------------------------------------------------------+
bool LoadATRData()
{
   int atr_copy_size = ATR_Period + 20;
   if(CopyBuffer(atrHandle, 0, 0, atr_copy_size, atrBuffer) < atr_copy_size)
      return false;
   return true;
}

//+------------------------------------------------------------------+
//| Calculate lot size: risk-based (default) or balance-based        |
//+------------------------------------------------------------------+
double CalculateLotSize()
{
   if(EnableRiskBasedSizing)
   {
      double equity = AccountInfoDouble(ACCOUNT_EQUITY);
      double riskAmount = equity * RiskPercentPerTrade / 100.0;
      double slDistancePoints = cachedATRPoints * ATR_Multiplier_SL_Base;
      if(slDistancePoints <= 0.0) return(BaseLotSize);
      double tickSize = SymbolInfoDouble(_Symbol, SYMBOL_TRADE_TICK_SIZE);
      double tickValue = SymbolInfoDouble(_Symbol, SYMBOL_TRADE_TICK_VALUE);
      if(tickSize <= 0.0 || tickValue <= 0.0) return(BaseLotSize);
      double lossPerLot = (slDistancePoints * point) / tickSize * tickValue;
      if(lossPerLot <= 0.0) return(BaseLotSize);
      double lotSize = riskAmount / lossPerLot;
      double minlot = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_MIN);
      double maxlot = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_MAX);
      double lotstep = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_STEP);
      int lot_digits = 0;
      double temp_step = lotstep;
      while(temp_step < 1 && temp_step > 0)
      {
         temp_step *= 10;
         lot_digits++;
      }
      lotSize = MathMin(lotSize, maxlot);
      lotSize = MathMax(lotSize, minlot);
      lotSize = NormalizeDouble(MathRound(lotSize / lotstep) * lotstep, lot_digits);
      return(lotSize);
   }

   double balance = AccountInfoDouble(ACCOUNT_BALANCE);
   double lotSize = BaseLotSize + MathFloor(balance / 1000.0) * LotIncrementPer1000;
   double minlot = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_MIN);
   double maxlot = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_MAX);
   double lotstep = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_STEP);
   double orig_lotstep = lotstep;
   int lot_digits = 0;
   double temp_step = lotstep;
   while(temp_step < 1 && temp_step > 0)
   {
      temp_step *= 10;
      lot_digits++;
   }
   lotSize = MathMin(lotSize, maxlot);
   lotSize = MathMax(lotSize, minlot);
   lotSize = NormalizeDouble(MathRound(lotSize / orig_lotstep) * orig_lotstep, lot_digits);
   return lotSize;
}

//+------------------------------------------------------------------+
//| Count open positions for current symbol and magic number         |
//+------------------------------------------------------------------+
int CountPositions()
{
   int count = 0;
   for(int p = 0; p < PositionsTotal(); p++)
   {
      ulong ticket = PositionGetTicket(p);
      if(ticket == 0) continue;
      if(!PositionSelectByTicket(ticket)) continue;
      if(PositionGetString(POSITION_SYMBOL) == _Symbol &&
         PositionGetInteger(POSITION_MAGIC) == MagicNumber)
         count++;
   }
   return count;
}

//+------------------------------------------------------------------+
//| Calculate total profit of open positions                         |
//+------------------------------------------------------------------+
double CalculateTotalProfit()
{
   double totalProfit = 0.0;
   for(int i = 0; i < PositionsTotal(); i++)
   {
      ulong ticket = PositionGetTicket(i);
      if(ticket == 0) continue;
      if(!PositionSelectByTicket(ticket)) continue;
      if(PositionGetString(POSITION_SYMBOL) != _Symbol) continue;
      if(PositionGetInteger(POSITION_MAGIC) != MagicNumber) continue;
      totalProfit += PositionGetDouble(POSITION_PROFIT);
   }
   return totalProfit;
}

//+------------------------------------------------------------------+
//| Calculate SL and TP in USD for open positions                    |
//+------------------------------------------------------------------+
void CalculateSLTPinUSD(double &slUSD, double &tpUSD)
{
   slUSD = 0.0;
   tpUSD = 0.0;
   double tickValue = SymbolInfoDouble(_Symbol, SYMBOL_TRADE_TICK_VALUE);
   if(tickValue == 0) return;
   int total = PositionsTotal();
   if(total == 0) return;

   for(int i = 0; i < total; i++)
   {
      ulong ticket = PositionGetTicket(i);
      if(ticket == 0) continue;
      if(!PositionSelectByTicket(ticket)) continue;
      if(PositionGetString(POSITION_SYMBOL) != _Symbol) continue;
      if(PositionGetInteger(POSITION_MAGIC) != MagicNumber) continue;

      long pos_type = PositionGetInteger(POSITION_TYPE);
      double open_price = PositionGetDouble(POSITION_PRICE_OPEN);
      double sl = PositionGetDouble(POSITION_SL);
      double tp = PositionGetDouble(POSITION_TP);
      double volume = PositionGetDouble(POSITION_VOLUME);

      double sl_distance = 0.0, tp_distance = 0.0;
      if(pos_type == POSITION_TYPE_BUY)
      {
         if(sl > 0.0) sl_distance = (open_price - sl) / point;
         if(tp > 0.0) tp_distance = (tp - open_price) / point;
      }
      else
      {
         if(sl > 0.0) sl_distance = (sl - open_price) / point;
         if(tp > 0.0) tp_distance = (open_price - tp) / point;
      }

      slUSD += sl_distance * tickValue * volume;
      tpUSD += tp_distance * tickValue * volume;
   }
}

//+------------------------------------------------------------------+
//| Apply trailing stop (once per bar, ATR-based)                    |
//+------------------------------------------------------------------+
void ApplyTrailingStop()
{
   if(!EnableTrailingStop) return;
   datetime curBar = iTime(_Symbol, PERIOD_CURRENT, 0);
   if(curBar == lastTrailBarTime) return; // update only once per bar
   lastTrailBarTime = curBar;
   if(cachedATRPoints <= 0.0) return;

   double trailDist = TrailingDistanceATR * cachedATRPoints * point;
   double startDist = TrailingStartATR * cachedATRPoints * point;
   if(trailDist <= 0.0 || startDist <= 0.0) return;

   double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);
   double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);

   for(int i = 0; i < PositionsTotal(); i++)
   {
      ulong ticket = PositionGetTicket(i);
      if(ticket == 0) continue;
      if(!PositionSelectByTicket(ticket)) continue;
      if(PositionGetString(POSITION_SYMBOL) != _Symbol) continue;
      if(PositionGetInteger(POSITION_MAGIC) != MagicNumber) continue;

      long posType = PositionGetInteger(POSITION_TYPE);
      double openPrice = PositionGetDouble(POSITION_PRICE_OPEN);
      double currentSL  = PositionGetDouble(POSITION_SL);
      double currentTP  = PositionGetDouble(POSITION_TP);

      MqlTradeRequest request = {};
      MqlTradeResult result = {};

      if(posType == POSITION_TYPE_BUY)
      {
         if(bid - openPrice < startDist) continue;          // not enough profit yet
         double newSL = NormalizeDouble(bid - trailDist, digits);
         if(newSL <= openPrice) continue;                    // never below entry
         if(newSL > currentSL + 0.5 * point)                 // improve SL only
         {
            request.action   = TRADE_ACTION_SLTP;
            request.symbol   = _Symbol;
            request.position = ticket;
            request.sl       = newSL;
            request.tp       = currentTP;
            if(!OrderSend(request, result))
               PrintFormat("Trail SL failed: ret=%d comment=%s", result.retcode, result.comment);
         }
      }
      else if(posType == POSITION_TYPE_SELL)
      {
         if(openPrice - ask < startDist) continue;
         double newSL = NormalizeDouble(ask + trailDist, digits);
         if(newSL >= openPrice) continue;                    // never above entry
         if(currentSL == 0.0 || newSL < currentSL - 0.5 * point)
         {
            request.action   = TRADE_ACTION_SLTP;
            request.symbol   = _Symbol;
            request.position = ticket;
            request.sl       = newSL;
            request.tp       = currentTP;
            if(!OrderSend(request, result))
               PrintFormat("Trail SL failed: ret=%d comment=%s", result.retcode, result.comment);
         }
      }
   }
}

//+------------------------------------------------------------------+
//| Helper function to create or update a label object               |
//+------------------------------------------------------------------+
//+------------------------------------------------------------------+
//| Apply break-even protection (once per bar, ATR-based)            |
//+------------------------------------------------------------------+
void ApplyBreakEven()
{
   if(!EnableBreakEven) return;
   datetime curBar = iTime(_Symbol, PERIOD_CURRENT, 0);
   if(curBar == lastBreakEvenBarTime) return; // update only once per bar
   lastBreakEvenBarTime = curBar;
   if(cachedATRPoints <= 0.0) return;

   double trigDist = BreakEvenTriggerATR * cachedATRPoints * point;
   double beSLDist = BreakEvenBufferATR * cachedATRPoints * point;
   if(trigDist <= 0.0 || beSLDist <= 0.0) return;

   double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);
   double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);

   for(int i = 0; i < PositionsTotal(); i++)
   {
      ulong ticket = PositionGetTicket(i);
      if(ticket == 0) continue;
      if(!PositionSelectByTicket(ticket)) continue;
      if(PositionGetString(POSITION_SYMBOL) != _Symbol) continue;
      if(PositionGetInteger(POSITION_MAGIC) != MagicNumber) continue;

      long posType = PositionGetInteger(POSITION_TYPE);
      double openPrice = PositionGetDouble(POSITION_PRICE_OPEN);
      double currentSL = PositionGetDouble(POSITION_SL);
      double currentTP = PositionGetDouble(POSITION_TP);

      MqlTradeRequest request = {};
      MqlTradeResult result = {};

      if(posType == POSITION_TYPE_BUY)
      {
         // only move to breakeven if SL is still below entry (not yet moved)
         if(currentSL < openPrice && bid - openPrice >= trigDist)
         {
            double newSL = NormalizeDouble(openPrice + beSLDist, digits);
            request.action   = TRADE_ACTION_SLTP;
            request.symbol   = _Symbol;
            request.position = ticket;
            request.sl       = newSL;
            request.tp       = currentTP;
            if(!OrderSend(request, result))
               PrintFormat("BreakEven SL failed: ret=%d comment=%s", result.retcode, result.comment);
         }
      }
      else if(posType == POSITION_TYPE_SELL)
      {
         if(currentSL > openPrice && openPrice - ask >= trigDist)
         {
            double newSL = NormalizeDouble(openPrice - beSLDist, digits);
            request.action   = TRADE_ACTION_SLTP;
            request.symbol   = _Symbol;
            request.position = ticket;
            request.sl       = newSL;
            request.tp       = currentTP;
            if(!OrderSend(request, result))
               PrintFormat("BreakEven SL failed: ret=%d comment=%s", result.retcode, result.comment);
         }
      }
   }
}

void CreateOrUpdateLabel(string name, int x, int y, string text, color col, int size)
{
   long chart_id = 0;
   if(ObjectFind(chart_id, name) < 0)
   {
      ObjectCreate(chart_id, name, OBJ_LABEL, 0, 0, 0);
      ObjectSetInteger(chart_id, name, OBJPROP_CORNER, CORNER_LEFT_UPPER);
      ObjectSetInteger(chart_id, name, OBJPROP_SELECTABLE, false);
      ObjectSetInteger(chart_id, name, OBJPROP_HIDDEN, false);
      ObjectSetInteger(chart_id, name, OBJPROP_ZORDER, 10);
   }
   ObjectSetInteger(chart_id, name, OBJPROP_XDISTANCE, x);
   ObjectSetInteger(chart_id, name, OBJPROP_YDISTANCE, y);
   ObjectSetString(chart_id, name, OBJPROP_TEXT, text);
   ObjectSetInteger(chart_id, name, OBJPROP_COLOR, col);
   ObjectSetString(chart_id, name, OBJPROP_FONT, "Arial");
   ObjectSetInteger(chart_id, name, OBJPROP_FONTSIZE, size);
}

//+------------------------------------------------------------------+
//| Draw and update dashboard (called only on new bar)               |
//+------------------------------------------------------------------+
void UpdateDashboard()
{
   double slUSD = 0.0, tpUSD = 0.0;
   CalculateSLTPinUSD(slUSD, tpUSD);
   double totalProfit = CalculateTotalProfit();
   double accountEquity = AccountInfoDouble(ACCOUNT_EQUITY);

   // Compute current spread and ATR for dashboard
   double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);
   double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);
   double spread_points = (ask > 0 && bid > 0) ? (ask - bid) / point : 0.0;
   double atrValue_points = 0.0;
   bool atr_loaded = LoadATRData();
   if(atr_loaded && ArraySize(atrBuffer) > 1)
      atrValue_points = atrBuffer[1] / point;
   else if(atr_loaded && ArraySize(atrBuffer) > 0)
      atrValue_points = atrBuffer[0] / point;

   string prefix = "ForexTrend_Dashboard_";
   int x = Dashboard_X;
   int y = Dashboard_Y;
   int row_height = 15;
   int col1_width = 100;
   int col2_width = 100;
   int col3_width = 50;
   int total_width = col1_width + col2_width + col3_width + 20;
   int total_height = 22 * row_height;

   long chart_id = 0;

   // Background
   string bg_name = prefix + "BG";
   if(ObjectFind(chart_id, bg_name) < 0)
   {
      ObjectCreate(chart_id, bg_name, OBJ_RECTANGLE_LABEL, 0, 0, 0);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_XDISTANCE, x);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_YDISTANCE, y);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_XSIZE, total_width);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_YSIZE, total_height);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_BGCOLOR, COLOR_BG);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_BORDER_COLOR, clrWhite);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_CORNER, CORNER_LEFT_UPPER);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_BACK, false);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_SELECTABLE, false);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_HIDDEN, false);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_ZORDER, 0);
   }
   else
   {
      ObjectSetInteger(chart_id, bg_name, OBJPROP_XSIZE, total_width);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_YSIZE, total_height);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_BGCOLOR, COLOR_BG);
      ObjectSetInteger(chart_id, bg_name, OBJPROP_BORDER_COLOR, clrWhite);
   }

   int current_y = y + 5;

   // Title
   CreateOrUpdateLabel(prefix + "Title", x + 10, current_y, "SuperTrend Dashboard", COLOR_TITLE, 10);
   current_y += row_height;

   // Header
   CreateOrUpdateLabel(prefix + "Header1", x + 10, current_y, "Timeframe", COLOR_TEXT, 9);
   CreateOrUpdateLabel(prefix + "Header2", x + 10 + col1_width, current_y, "Status", COLOR_TEXT, 9);
   CreateOrUpdateLabel(prefix + "Header3", x + 10 + col1_width + col2_width, current_y, "Bars", COLOR_TEXT, 9);
   current_y += row_height;

   // Separator 1
   CreateOrUpdateLabel(prefix + "Sep1", x + 10, current_y, "----------------------------------------------------------", COLOR_TEXT, 9);
   current_y += row_height;

   // Timeframe rows
   for(int k = 0; k < 9; k++)
   {
      string tf_prefix = prefix + "TF" + IntegerToString(k);
      CreateOrUpdateLabel(tf_prefix + "_TF", x + 10, current_y, tf_names[k], COLOR_TEXT, 9);

      string trend_word = (directions[k] == 1) ? "Uptrend" : (directions[k] == -1 ? "Downtrend" : "Unknown");
      color status_color = (directions[k] == 1) ? COLOR_UP : (directions[k] == -1 ? COLOR_DOWN : COLOR_NEUTRAL);
      CreateOrUpdateLabel(tf_prefix + "_Status", x + 10 + col1_width, current_y, trend_word, status_color, 9);

      CreateOrUpdateLabel(tf_prefix + "_Bars", x + 10 + col1_width + col2_width, current_y, IntegerToString(trend_counts[k]), COLOR_TEXT, 9);
      current_y += row_height;
   }

   // Separator 2
   CreateOrUpdateLabel(prefix + "Sep2", x + 10, current_y, "----------------------------------------------------------", COLOR_TEXT, 9);
   current_y += row_height;

   // Counts and Signal
   string counts_text = StringFormat("Up=%d, Down=%d, Neutral=%d    Signal: ", up_count, down_count, neutral_count);
   CreateOrUpdateLabel(prefix + "Counts", x + 10, current_y, counts_text, COLOR_TEXT, 9);

   string signal_text = (overall_signal == 1 ? "BUY" : (overall_signal == -1 ? "SELL" : "OFF"));
   color signal_color = (overall_signal == 1 ? COLOR_SIGNAL_BUY : (overall_signal == -1 ? COLOR_SIGNAL_SELL : COLOR_NEUTRAL));
   CreateOrUpdateLabel(prefix + "Signal", x + 10 + 200, current_y, signal_text, signal_color, 9);
   current_y += row_height;

   // Separator 3
   CreateOrUpdateLabel(prefix + "Sep3", x + 10, current_y, "----------------------------------------------------------", COLOR_TEXT, 9);
   current_y += row_height;

   // SL/TP
   string sltp_text = (slUSD != 0.0 && tpUSD != 0.0) ? StringFormat("SL: %.2f USD, TP: %.2f USD", slUSD, tpUSD) : "SL: N/A, TP: N/A";
   CreateOrUpdateLabel(prefix + "SLTP", x + 10, current_y, sltp_text, COLOR_TEXT, 9);
   current_y += row_height;

   // Profit and Equity
   string profit_equity_text = StringFormat("Profit: %.2f USD, Equity: %.2f USD", totalProfit, accountEquity);
   CreateOrUpdateLabel(prefix + "ProfitEquity", x + 10, current_y, profit_equity_text, COLOR_TEXT, 9);
   current_y += row_height;

   // Spread
   string spread_text = StringFormat("Spread: %.1f pts", spread_points);
   CreateOrUpdateLabel(prefix + "Spread", x + 10, current_y, spread_text, COLOR_TEXT, 9);
   current_y += row_height;

   // ATR Value
   string atr_text = StringFormat("ATR Value: %.1f pts", atrValue_points);
   CreateOrUpdateLabel(prefix + "ATR", x + 10, current_y, atr_text, COLOR_TEXT, 9);
   current_y += row_height;

   // Stop Level
   string stop_text = StringFormat("Stop Level: %d points", (int)stopsLevel);
   CreateOrUpdateLabel(prefix + "StopLevel", x + 10, current_y, stop_text, COLOR_TEXT, 9);
   current_y += row_height;

   // ATR Loaded Status
   string atr_loaded_text = StringFormat("ATR Loaded: %s", atr_loaded ? "Yes" : "No");
   color atr_loaded_color = atr_loaded ? COLOR_SUCCESS : COLOR_ERROR;
   CreateOrUpdateLabel(prefix + "ATRLoaded", x + 10, current_y, atr_loaded_text, atr_loaded_color, 9);
}

//+------------------------------------------------------------------+
//| Expert tick function                                             |
//+------------------------------------------------------------------+
void OnTick()
{
   datetime curBar = iTime(_Symbol, PERIOD_CURRENT, 0);

   // Multi-TF SuperTrend (heavy calculation only on each TF bar change)
   LoadAndComputeSuperTrend();

   // Dashboard refresh only on new current-timeframe bar
   if(EnableDashboard && curBar != lastDashboardBarTime)
   {
      lastDashboardBarTime = curBar;
      UpdateDashboard();
   }

   // --- Trailing stop (runs regardless of session / new-entry rules) ---
   ApplyTrailingStop();
   // --- Break-even protection (smooths equity, cuts round-trips) ---
   ApplyBreakEven();

   // --- Exit detection (for cooldown) ---
   int posCountNow = CountPositions();
   if(positionsPrev > 0 && posCountNow < positionsPrev)
      lastExitBarTime = curBar;
   positionsPrev = posCountNow;

   if(!IsTradingSessionValid()) return;

   // No new trades while a position is open (when hedging is disabled)
   if(!is_hedging && CountPositions() > 0) return;

   // --- Cooldown after last exit ---
   if(CooldownBarsAfterExit > 0 && lastExitBarTime != 0)
   {
      long barsSinceExit = (curBar - lastExitBarTime) / PeriodSeconds(PERIOD_CURRENT);
      if(barsSinceExit < CooldownBarsAfterExit)
         return;
   }

   // --- Max drawdown guard (peak reset prevents permanent lockout) ---
   double equityNow = AccountInfoDouble(ACCOUNT_EQUITY);
   if(equityNow > peakEquity)
   {
      peakEquity = equityNow;
      lastPeakBarTime = curBar;
   }
   else if(curBar - lastPeakBarTime >= DrawdownResetBars * PeriodSeconds(PERIOD_CURRENT))
   {
      peakEquity = equityNow;   // stale peak -> fresh start
      lastPeakBarTime = curBar;
   }
   if(EnableMaxDrawdownGuard && peakEquity > 0.0)
   {
      double ddPct = (peakEquity - equityNow) / peakEquity * 100.0;
      if(ddPct > MaxEquityDrawdownPct)
         return; // pause new entries until recovery or peak reset
   }

   if(curBar != currentBarStartTime)
   {
      currentBarStartTime = curBar;
      tradesInCurrentBar = 0;
   }
   if(tradesInCurrentBar >= MaxTradesPerBar) return;

   double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);
   double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);
   if(ask <= 0 || bid <= 0) return;
   if((ask - bid) / point > MaxSpread) return;

   // ATR cached once per bar (index 1 = previous closed bar -> no repaint)
   if(curBar != lastATRBarTime)
   {
      lastATRBarTime = curBar;
      cachedATRPoints = 0.0;
      if(LoadATRData() && ArraySize(atrBuffer) > 1)
         cachedATRPoints = atrBuffer[1] / point;
   }
   if(cachedATRPoints <= 0.0) return;            // ATR not ready yet (warm-up)
   if(cachedATRPoints > MaxATRThreshold) return; // avoid extreme volatility
   if(cachedATRPoints < MinATRThreshold) return; // skip low-volatility (dead) market

   double slPips = ATR_Multiplier_SL_Base * cachedATRPoints;
   double tpPips = ATR_Multiplier_TP_Base * cachedATRPoints;

   double lotSize = CalculateLotSize();

   long min_dist_points = (stopsLevel > 0 ? stopsLevel : 100);
   double min_distance = min_dist_points * point;

   MqlTradeRequest request = {};
   MqlTradeResult result = {};

   // --- Regime filter: D1 and W1 SuperTrend must both agree (mandatory veto) ---
   if(EnableRegimeFilter)
   {
      if(overall_signal == 1 && (directions[6] != 1 || directions[7] != 1))
         return; // no BUY unless Daily AND Weekly are bullish
      if(overall_signal == -1 && (directions[6] != -1 || directions[7] != -1))
         return; // no SELL unless Daily AND Weekly are bearish
   }

   if(overall_signal == 1)
   {
      double sl = NormalizeDouble(ask - slPips * point, digits);
      double tp = NormalizeDouble(ask + tpPips * point, digits);

      if((ask - sl < min_distance) || (tp - ask < min_distance)) return;

      request.action = TRADE_ACTION_DEAL;
      request.symbol = _Symbol;
      request.volume = lotSize;
      request.type = ORDER_TYPE_BUY;
      request.price = ask;
      request.sl = sl;
      request.tp = tp;
      request.deviation = 10;
      request.magic = MagicNumber;
      request.comment = "Buy";
      if(OrderSend(request, result))
         tradesInCurrentBar++;
      else
         PrintFormat("Buy failed: ret=%d comment=%s", result.retcode, result.comment);
   }
   else if(overall_signal == -1)
   {
      double sl = NormalizeDouble(bid + slPips * point, digits);
      double tp = NormalizeDouble(bid - tpPips * point, digits);

      if((sl - bid < min_distance) || (bid - tp < min_distance)) return;

      request.action = TRADE_ACTION_DEAL;
      request.symbol = _Symbol;
      request.volume = lotSize;
      request.type = ORDER_TYPE_SELL;
      request.price = bid;
      request.sl = sl;
      request.tp = tp;
      request.deviation = 10;
      request.magic = MagicNumber;
      request.comment = "Sell";
      if(OrderSend(request, result))
         tradesInCurrentBar++;
      else
         PrintFormat("Sell failed: ret=%d comment=%s", result.retcode, result.comment);
   }
}

//+------------------------------------------------------------------+
//| Helper: Activation Check Function (for whitelisted accounts)     |
//+------------------------------------------------------------------+
bool CheckActivation(string client, string password)
{
   string masterKey = "xAI2026"; // change to a secret 7-character key and keep it hidden!
   uchar key[], src[], dst[];

   StringToCharArray(masterKey, key); // Convert key to array

   // Encrypt client string
   StringToCharArray(client, src);
   CryptEncode(CRYPT_DES, src, key, dst);

   // Encode to BASE64
   ArrayInitialize(key, 0x00); // Clear key
   CryptEncode(CRYPT_BASE64, dst, key, src);

   string encrypted_client = CharArrayToString(src);

   // If password is empty, check against whitelisted codes
   if(StringLen(password) == 0)
   {
      for(int i = 0; i < ArraySize(allowed_codes); i++)
      {
         if(encrypted_client == allowed_codes[i])
            return true;
      }
      return false; // Not whitelisted
   }

   // Otherwise, check against provided password
   return (encrypted_client == password);
}

//+------------------------------------------------------------------+
//| Helper: Show Client Info Dialog                                  |
//+------------------------------------------------------------------+
void ShowClientInfoDialog(string client_info)
{
   string dialog_name = "ClientInfoDialog";
   string text_name = "ClientInfoText";
   string instruction_name = "ClientInfoInstruction";

   // Create dialog background
   if(ObjectFind(ChartID(), dialog_name) < 0)
   {
      ObjectCreate(ChartID(), dialog_name, OBJ_RECTANGLE_LABEL, 0, 0, 0);
      ObjectSetInteger(ChartID(), dialog_name, OBJPROP_CORNER, CORNER_LEFT_UPPER);
      ObjectSetInteger(ChartID(), dialog_name, OBJPROP_XDISTANCE, 50);
      ObjectSetInteger(ChartID(), dialog_name, OBJPROP_YDISTANCE, 50);
      ObjectSetInteger(ChartID(), dialog_name, OBJPROP_XSIZE, 400);
      ObjectSetInteger(ChartID(), dialog_name, OBJPROP_YSIZE, 150);
      ObjectSetInteger(ChartID(), dialog_name, OBJPROP_BGCOLOR, clrLightGray);
      ObjectSetInteger(ChartID(), dialog_name, OBJPROP_BORDER_TYPE, BORDER_RAISED);
      ObjectSetInteger(ChartID(), dialog_name, OBJPROP_BORDER_COLOR, clrBlack);
      ObjectSetInteger(ChartID(), dialog_name, OBJPROP_ZORDER, 10);
      ObjectSetInteger(ChartID(), dialog_name, OBJPROP_BACK, false);
   }

   // Create instruction label
   if(ObjectFind(ChartID(), instruction_name) < 0)
   {
      ObjectCreate(ChartID(), instruction_name, OBJ_LABEL, 0, 0, 0);
      ObjectSetInteger(ChartID(), instruction_name, OBJPROP_CORNER, CORNER_LEFT_UPPER);
      ObjectSetInteger(ChartID(), instruction_name, OBJPROP_XDISTANCE, 60);
      ObjectSetInteger(ChartID(), instruction_name, OBJPROP_YDISTANCE, 60);
      ObjectSetInteger(ChartID(), instruction_name, OBJPROP_FONTSIZE, 10);
      ObjectSetInteger(ChartID(), instruction_name, OBJPROP_COLOR, clrBlack);
      ObjectSetInteger(ChartID(), instruction_name, OBJPROP_ZORDER, 11);
      ObjectSetInteger(ChartID(), instruction_name, OBJPROP_BACK, false);
      ObjectSetString(ChartID(), instruction_name, OBJPROP_TEXT, "کد فعال‌سازی نامعتبر است. این اطلاعات حساب را کپی کرده و برای فروشنده ارسال کنید:");
   }

   // Create text label with client info
   if(ObjectFind(ChartID(), text_name) < 0)
   {
      ObjectCreate(ChartID(), text_name, OBJ_EDIT, 0, 0, 0);
      ObjectSetInteger(ChartID(), text_name, OBJPROP_CORNER, CORNER_LEFT_UPPER);
      ObjectSetInteger(ChartID(), text_name, OBJPROP_XDISTANCE, 60);
      ObjectSetInteger(ChartID(), text_name, OBJPROP_YDISTANCE, 80);
      ObjectSetInteger(ChartID(), text_name, OBJPROP_XSIZE, 380);
      ObjectSetInteger(ChartID(), text_name, OBJPROP_YSIZE, 30);
      ObjectSetInteger(ChartID(), text_name, OBJPROP_FONTSIZE, 10);
      ObjectSetInteger(ChartID(), text_name, OBJPROP_COLOR, clrBlack);
      ObjectSetInteger(ChartID(), text_name, OBJPROP_BGCOLOR, clrWhite);
      ObjectSetInteger(ChartID(), text_name, OBJPROP_READONLY, false);
      ObjectSetInteger(ChartID(), text_name, OBJPROP_ZORDER, 11);
      ObjectSetInteger(ChartID(), text_name, OBJPROP_BACK, false);
      ObjectSetString(ChartID(), text_name, OBJPROP_TEXT, client_info);
   }

   ChartRedraw();
}
