//+------------------------------------------------------------------+
//|                                              MonkeyPips_v305.mq5 |
//|                                   Optimized for XAUUSD (M1)      |
//|                                                  Copyright trevone |
//|                                    https://www.mql5.com/en/users/trevone |
//+------------------------------------------------------------------+
#property copyright "Copyright trevone"
#property link      "https://www.mql5.com/en/users/trevone"
#property version   "3.05"

#include <Trade\Trade.mqh>

//--- trade manager mode
enum ENUM_TRADE_MANAGER
  {
   TRADE_PRIMARY   = 0,  // Primary
   TRADE_SECONDARY = 1   // Secondary
  };

//+------------------------------------------------------------------+
//| Input parameters (defaults tuned for XAUUSD M1)                  |
//+------------------------------------------------------------------+
input group "=== Trade Manager ==="
input ENUM_TRADE_MANAGER TradeManager   = TRADE_PRIMARY;      // Trade Manager
input string             TradeComment   = "MonkeyPips v3.05"; // Trade comment
input long               MagicNumber    = 33431;              // Magic number
input int                Slippage       = 3;                  // Slippage (points)
input int                MaxSpread      = 45;                 // Max spread (points) -> $0.45 for gold
input double             FixedLot       = 0;                  // Fixed lot (0 = automatic)
input int                RiskPercent    = 30;                 // Risk percent
input int                MaxDrawdown    = 90;                 // Max drawdown (percent)
input int                StartHour      = 2;                  // Start hour (broker time)
input int                EndHour        = 22;                 // End hour (broker time)
input int                GMTOffset      = 0;                  // GMT offset

input group "=== Order Management ==="
input int TradeDeviation  = 2;                                // Max unprotected orders
input int TradeDelta      = 25;                               // Pending order distance (points) -> $0.25
input int Trailing        = 8;                                // Trailing stop (points) -> $0.08 (bumped to stop level)
input int StartTrailing   = 12;                               // Start trailing (points) -> $0.12
input int VelocityTrigger = 60;                               // Velocity trigger (points) -> $0.60 on M1 gold
input int VelocityTime    = 15;                               // Velocity time (seconds) -> keep pendings alive longer
input int DeleteRatio     = 30;                               // Delete ratio (unused, kept from original)
input int OrderExpiry     = 90;                               // Pending order expiry (seconds)
input int TickSample      = 200;                              // Tick sample size

//--- trade object
CTrade trade;

//--- runtime adjusted values (MQL5 inputs are read-only, so we keep copies)
int tradeDelta;
int trailing;

//--- global state
int    gmt;
int    size;
int    stoplevel;

double marginRequirement;
double maxLot;
double minLot;
double lotSize;
double currentSpread;
double avgSpread;
double maxSpread;
double rateChange;
double commissionPoints;

double spreadSize[];
double tick[];
int    tickTime[];

int    lastBuyOrder;
int    lastSellOrder;

bool   calculateCommission = true;
datetime lastCommissionScan = 0;

double maxEquity = 0;

//+------------------------------------------------------------------+
//| Expert initialization function                                   |
//+------------------------------------------------------------------+
int OnInit()
  {
   //--- margin required for 1 lot (MQL5 equivalent of MODE_MARGINREQUIRED)
   marginRequirement = 0;
   if(!OrderCalcMargin(ORDER_TYPE_BUY, _Symbol, 1.0, SymbolInfoDouble(_Symbol, SYMBOL_ASK), marginRequirement))
      marginRequirement = 0;
   marginRequirement *= 0.01;

   maxLot = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_MAX);
   minLot = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_MIN);

   currentSpread = NormalizeDouble(SymbolInfoDouble(_Symbol, SYMBOL_ASK) -
                                   SymbolInfoDouble(_Symbol, SYMBOL_BID), _Digits);

   stoplevel = (int)MathMax(SymbolInfoInteger(_Symbol, SYMBOL_TRADE_FREEZE_LEVEL),
                            SymbolInfoInteger(_Symbol, SYMBOL_TRADE_STOPS_LEVEL));

   //--- MQL4 allowed changing inputs at runtime; in MQL5 we adjust copies instead
   tradeDelta = MathMax(TradeDelta, stoplevel);
   trailing   = MathMax(Trailing, stoplevel);

   avgSpread = currentSpread;
   size      = MathMax(TickSample, 10);   // guard against tiny/zero sample size
   ArrayResize(spreadSize, size);
   ArrayFill(spreadSize, 0, size, avgSpread);

   maxSpread = NormalizeDouble(MaxSpread * _Point, _Digits);

   //--- trade object settings
   trade.SetExpertMagicNumber((ulong)MagicNumber);
   trade.SetDeviationInPoints(Slippage);
   trade.SetTypeFillingBySymbol(_Symbol);

   PrintFormat("MonkeyPips: %s | Point=%.5f | StopLevel=%d pts | Margin/1lot=%.2f",
               _Symbol, _Point, stoplevel, marginRequirement / 0.01);

   Display();
   return(INIT_SUCCEEDED);
  }

//+------------------------------------------------------------------+
//| Expert deinitialization function                                 |
//+------------------------------------------------------------------+
void OnDeinit(const int reason)
  {
   Comment("");
  }

//+------------------------------------------------------------------+
//| Estimate commission in points from the last closed deal         |
//+------------------------------------------------------------------+
void Commission()
  {
   if(MQLInfoInteger(MQL_TESTER))
      return;

   //--- scan history at most once every 10 seconds (M1 optimization)
   if(TimeCurrent() - lastCommissionScan < 10)
      return;
   lastCommissionScan = TimeCurrent();

   if(!HistorySelect(0, TimeCurrent()))
      return;

   for(int pos = HistoryDealsTotal() - 1; pos >= 0; pos--)
     {
      ulong ticket = HistoryDealGetTicket(pos);
      if(ticket == 0)
         continue;
      if(HistoryDealGetString(ticket, DEAL_SYMBOL) != _Symbol)
         continue;
      if((ENUM_DEAL_ENTRY)HistoryDealGetInteger(ticket, DEAL_ENTRY) != DEAL_ENTRY_OUT)
         continue;

      double profit = HistoryDealGetDouble(ticket, DEAL_PROFIT);
      if(profit == 0.0)
         continue;

      double closePrice = HistoryDealGetDouble(ticket, DEAL_PRICE);
      long   positionId = (long)HistoryDealGetInteger(ticket, DEAL_POSITION_ID);
      double openPrice  = 0;

      //--- find the matching opening deal (same position id)
      for(int j = HistoryDealsTotal() - 1; j >= 0; j--)
        {
         ulong t = HistoryDealGetTicket(j);
         if(t == 0)
            continue;
         if((long)HistoryDealGetInteger(t, DEAL_POSITION_ID) == positionId &&
            (ENUM_DEAL_ENTRY)HistoryDealGetInteger(t, DEAL_ENTRY) == DEAL_ENTRY_IN)
           {
            openPrice = HistoryDealGetDouble(t, DEAL_PRICE);
            break;
           }
        }

      if(openPrice == 0 || closePrice == openPrice)
         continue;

      calculateCommission = false;
      double rate = MathAbs(profit / (closePrice - openPrice));
      commissionPoints = (-HistoryDealGetDouble(ticket, DEAL_COMMISSION)) / rate;
      break;
     }
  }

//+------------------------------------------------------------------+
//| Total commission of all deals of the selected position           |
//+------------------------------------------------------------------+
double PositionCommission()
  {
   double commission = 0;
   long positionId = (long)PositionGetInteger(POSITION_IDENTIFIER);
   if(HistorySelectByPosition(positionId))
     {
      for(int i = HistoryDealsTotal() - 1; i >= 0; i--)
        {
         ulong dealTicket = HistoryDealGetTicket(i);
         if(dealTicket != 0)
            commission += HistoryDealGetDouble(dealTicket, DEAL_COMMISSION);
        }
     }
   return(commission);
  }

//+------------------------------------------------------------------+
//| Convert broker hour to local/GMT hour                            |
//+------------------------------------------------------------------+
int OfflineGMT()
  {
   MqlDateTime dt;
   TimeToStruct(TimeCurrent(), dt);

   int bkrH    = dt.hour;
   int gOffset = bkrH - GMTOffset;
   if(gOffset < 0)       gOffset += 24;
   else if(gOffset > 23) gOffset -= 24;
   return(gOffset);
  }

//+------------------------------------------------------------------+
//| Expert tick function                                             |
//+------------------------------------------------------------------+
void OnTick()
  {
   int totalBuyStop     = 0;
   int totalSellStop    = 0;
   int totalTrades      = 0;
   int totalUnprotected = 0;

   if(calculateCommission)
      Commission();

   gmt = OfflineGMT();
   PrepareSpread();
   ManageTicks();

   double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);
   double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);

   //--- manage open positions (market orders)
   for(int pos = 0; pos < PositionsTotal(); pos++)
     {
      ulong ticket = PositionGetTicket(pos);
      if(ticket == 0)
         continue;
      if(!PositionSelectByTicket(ticket))
         continue;
      if(PositionGetString(POSITION_SYMBOL) != _Symbol)
         continue;
      if(PositionGetInteger(POSITION_MAGIC) != MagicNumber)
         continue;

      totalTrades++;

      ENUM_POSITION_TYPE ptype     = (ENUM_POSITION_TYPE)PositionGetInteger(POSITION_TYPE);
      double             openPrice = PositionGetDouble(POSITION_PRICE_OPEN);
      double             sl        = PositionGetDouble(POSITION_SL);
      double             tp        = PositionGetDouble(POSITION_TP);

      if(ptype == POSITION_TYPE_BUY)
        {
         double accountEquity = AccountInfoDouble(ACCOUNT_BALANCE) +
                                PositionGetDouble(POSITION_PROFIT) +
                                PositionCommission() +
                                PositionGetDouble(POSITION_SWAP);

         if(sl == 0 || (sl > 0 && sl < openPrice))
            totalUnprotected++;

         //--- normal trailing
         if(bid - openPrice > (trailing * _Point) + (StartTrailing * _Point) + commissionPoints)
           {
            if(sl == 0.0 || bid - sl > trailing * _Point)
              {
               double newSL = NormalizeDouble(bid - trailing * _Point, _Digits);
               if(newSL != sl)
                  trade.PositionModify(ticket, newSL, tp);
              }
           }
         //--- drawdown protection trailing
         else
           {
            if(accountEquity > maxEquity ||
               accountEquity / AccountInfoDouble(ACCOUNT_BALANCE) < (double)MaxDrawdown / 100)
              {
               if(bid < openPrice - VelocityTrigger * _Point)
                 {
                  if(sl == 0.0 || bid - sl > trailing * _Point)
                    {
                     double newSL = NormalizeDouble(bid - trailing * _Point, _Digits);
                     if(newSL != sl)
                        trade.PositionModify(ticket, newSL, tp);
                    }
                 }
              }
           }
        }
      else if(ptype == POSITION_TYPE_SELL)
        {
         double accountEquity = AccountInfoDouble(ACCOUNT_BALANCE) +
                                PositionGetDouble(POSITION_PROFIT) +
                                PositionCommission() +
                                PositionGetDouble(POSITION_SWAP);

         if(sl == 0 || (sl > 0 && sl > openPrice))
            totalUnprotected++;

         //--- normal trailing
         if(openPrice - ask > (trailing * _Point) + (StartTrailing * _Point) + commissionPoints)
           {
            if(sl == 0.0 || sl - ask > trailing * _Point)
              {
               double newSL = NormalizeDouble(ask + trailing * _Point, _Digits);
               if(newSL != sl)
                  trade.PositionModify(ticket, newSL, tp);
              }
           }
         //--- drawdown protection trailing
         else
           {
            if(accountEquity > maxEquity ||
               accountEquity / AccountInfoDouble(ACCOUNT_BALANCE) < (double)MaxDrawdown / 100)
              {
               if(ask > openPrice + VelocityTrigger * _Point)
                 {
                  if(sl == 0.0 || sl - ask > trailing * _Point)
                    {
                     double newSL = NormalizeDouble(ask + trailing * _Point, _Digits);
                     if(newSL != sl)
                        trade.PositionModify(ticket, newSL, tp);
                    }
                 }
              }
           }
        }
     }

   //--- manage pending orders (buy/sell stops)
   for(int pos = 0; pos < OrdersTotal(); pos++)
     {
      ulong ticket = OrderGetTicket(pos);
      if(ticket == 0)
         continue;
      if(OrderGetString(ORDER_SYMBOL) != _Symbol)
         continue;
      if(OrderGetInteger(ORDER_MAGIC) != MagicNumber)
         continue;

      totalTrades++;

      ENUM_ORDER_TYPE otype = (ENUM_ORDER_TYPE)OrderGetInteger(ORDER_TYPE);

      if(otype == ORDER_TYPE_BUY_STOP)
        {
         if((int)TimeCurrent() - lastBuyOrder > VelocityTime)
            trade.OrderDelete(ticket);
         totalBuyStop++;
         totalUnprotected++;
        }
      else if(otype == ORDER_TYPE_SELL_STOP)
        {
         if((int)TimeCurrent() - lastSellOrder > VelocityTime)
            trade.OrderDelete(ticket);
         totalSellStop++;
         totalUnprotected++;
        }
     }

   //--- track the maximum balance while no trades are open
   if(totalTrades == 0)
     {
      double balance = AccountInfoDouble(ACCOUNT_BALANCE);
      if(balance > maxEquity)
         maxEquity = balance;
     }

   //--- Primary manager: open new pending orders
   if(TradeManager == TRADE_PRIMARY)
     {
      bool timeOk = false;
      if((StartHour < EndHour && gmt >= StartHour && gmt <= EndHour) ||
         (StartHour > EndHour && ((gmt <= EndHour && gmt >= 0) ||
          (gmt <= 23 && gmt >= StartHour))))
         timeOk = true;

      if(timeOk && totalUnprotected < TradeDeviation)
        {
         double volume = LotSize();

         if(rateChange > VelocityTrigger * _Point && avgSpread <= maxSpread && totalBuyStop < TradeDeviation)
           {
            double price = ask + (totalBuyStop + 1.0) * (_Point * tradeDelta);
            if(PlacePending(ORDER_TYPE_BUY_STOP, volume, price))
               lastBuyOrder = (int)TimeCurrent();
           }

         if(rateChange < -VelocityTrigger * _Point && avgSpread <= maxSpread && totalSellStop < TradeDeviation)
           {
            double price = bid - (totalSellStop + 1.0) * (_Point * tradeDelta);
            if(PlacePending(ORDER_TYPE_SELL_STOP, volume, price))
               lastSellOrder = (int)TimeCurrent();
           }
        }
     }

   Display();
  }

//+------------------------------------------------------------------+
//| Place a pending stop order                                       |
//+------------------------------------------------------------------+
bool PlacePending(ENUM_ORDER_TYPE type, double volume, double price)
  {
   bool supportExpiry = ((SymbolInfoInteger(_Symbol, SYMBOL_EXPIRATION_MODE) & SYMBOL_EXPIRATION_TIME) != 0) &&
                        (OrderExpiry > 0);
   datetime expiration = supportExpiry ? TimeCurrent() + OrderExpiry : 0;
   ENUM_ORDER_TYPE_TIME timeType = supportExpiry ? ORDER_TIME_SPECIFIED : ORDER_TIME_GTC;

   bool result = false;
   if(type == ORDER_TYPE_BUY_STOP)
      result = trade.BuyStop(volume, price, _Symbol, 0, 0, timeType, expiration, TradeComment);
   else if(type == ORDER_TYPE_SELL_STOP)
      result = trade.SellStop(volume, price, _Symbol, 0, 0, timeType, expiration, TradeComment);

   if(!result)
      PrintFormat("%s failed: %s", (type == ORDER_TYPE_BUY_STOP ? "BuyStop" : "SellStop"),
                  trade.ResultRetcodeDescription());
   return(result);
  }

//+------------------------------------------------------------------+
//| Lot size calculation                                             |
//+------------------------------------------------------------------+
double LotSize()
  {
   if(FixedLot > 0)
      lotSize = NormalizeDouble(FixedLot, 2);
   else
     {
      if(marginRequirement > 0)
        {
         double raw = AccountInfoDouble(ACCOUNT_BALANCE) * ((double)RiskPercent / 1000) * 0.01 / marginRequirement;
         lotSize = MathMax(MathMin(NormalizeDouble(raw, 2), maxLot), minLot);
        }
      else
         lotSize = minLot;
     }
   return(NormalizeLots(lotSize));
  }

//+------------------------------------------------------------------+
//| Normalize lots to the broker lot step                            |
//+------------------------------------------------------------------+
double NormalizeLots(double p)
  {
   double ls = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_STEP);
   if(ls <= 0)
      ls = 0.01;

   double norm = MathRound(p / ls) * ls;
   if(norm < minLot) norm = minLot;
   if(norm > maxLot) norm = maxLot;
   return(norm);
  }

//+------------------------------------------------------------------+
//| Update the rolling average spread (LWMA)                         |
//+------------------------------------------------------------------+
void PrepareSpread()
  {
   if(MQLInfoInteger(MQL_TESTER))
      return;

   double spreadSizeTemp[];
   ArrayResize(spreadSizeTemp, size - 1);
   ArrayCopy(spreadSizeTemp, spreadSize, 0, 1, size - 1);

   ArrayResize(spreadSizeTemp, size);
   spreadSizeTemp[size - 1] = NormalizeDouble(SymbolInfoDouble(_Symbol, SYMBOL_ASK) -
                                              SymbolInfoDouble(_Symbol, SYMBOL_BID), _Digits);
   ArrayCopy(spreadSize, spreadSizeTemp, 0, 0);

   //--- linear weighted moving average (equivalent of iMAOnArray MODE_LWMA)
   double sum       = 0;
   double weightSum = 0;
   for(int i = 0; i < size; i++)
     {
      sum       += spreadSize[i] * (i + 1);
      weightSum += (i + 1);
     }
   avgSpread = (weightSum > 0) ? sum / weightSum : currentSpread;
  }

//+------------------------------------------------------------------+
//| Update the tick velocity buffer                                 |
//+------------------------------------------------------------------+
void ManageTicks()
  {
   double tickTemp[];
   int    tickTimeTemp[];

   ArrayResize(tickTemp, size - 1);
   ArrayResize(tickTimeTemp, size - 1);
   ArrayCopy(tickTemp, tick, 0, 1, size - 1);
   ArrayCopy(tickTimeTemp, tickTime, 0, 1, size - 1);

   ArrayResize(tickTemp, size);
   ArrayResize(tickTimeTemp, size);
   tickTemp[size - 1]     = SymbolInfoDouble(_Symbol, SYMBOL_BID);
   tickTimeTemp[size - 1] = (int)TimeCurrent();

   ArrayCopy(tick, tickTemp, 0, 0);
   ArrayCopy(tickTime, tickTimeTemp, 0, 0);

   int    timeNow   = tickTime[size - 1];
   double priceNow  = tick[size - 1];
   double priceThen = 0;
   bool   found     = false;

   //--- find the price `VelocityTime` seconds ago
   for(int i = size - 1; i >= 0; i--)
     {
      if(timeNow - tickTime[i] > VelocityTime)
        {
         priceThen = tick[i];
         found     = true;
         break;
        }
     }

   //--- FIXED: if there is not enough history yet, keep rate at 0
   //--- (old code compared to 0 price and used a symbol-dependent clamp)
   rateChange = found ? (priceNow - priceThen) : 0;
  }

//+------------------------------------------------------------------+
//| Format an hour in 12-hour AM/PM notation                         |
//+------------------------------------------------------------------+
string NiceHour(int kgmt)
  {
   string m = "AM";
   if(kgmt > 12)
     {
      kgmt -= 12;
      m = "PM";
     }
   else if(kgmt == 12)
      m = "PM";
   return(IntegerToString(kgmt) + m);
  }

//+------------------------------------------------------------------+
//| Show info on the chart                                           |
//+------------------------------------------------------------------+
void Display()
  {
   string display = "Monkey Pips v3.05 [XAUUSD M1]\n";
   display += "----------------------------------------\n";
   display += (TradeManager == TRADE_PRIMARY) ? "TradeManager: Primary\n" : "TradeManager: Secondary\n";
   display += "----------------------------------------\n";
   display += StringFormat("Leverage: %d   Lots: %.2f\n", (int)AccountInfoInteger(ACCOUNT_LEVERAGE), lotSize);
   display += StringFormat("Avg. Spread: %.2f of %.2f\n", avgSpread, maxSpread);
   display += StringFormat("Commission: %.2f\n", commissionPoints);
   display += StringFormat("GMT Now: %s\n", NiceHour(gmt));
   display += "----------------------------------------\n";
   display += StringFormat("Set: %s\n", TradeComment);
   display += "----------------------------------------\n";
   display += StringFormat("Velocity: %.2f\n", rateChange);
   Comment(display);
  }
//+------------------------------------------------------------------+
