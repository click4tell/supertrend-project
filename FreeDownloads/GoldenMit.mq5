//+------------------------------------------------------------------+
//|                                                   GoldenMit (MQL5)|
//|                      نسخه طلایی Bahar1 — مخصوص XAUUSD             |
//|   واحدها مقیاس‌شده برای طلا (دلار به‌جای نقطه) + سقف معامله روزانه |
//|   پایه: Bahar1.mq5 v1.01 (رفع خطای 10015 + باگ TimeToTrade)      |
//+------------------------------------------------------------------+
#property copyright "Copyright 2019, Kamran Monkaresi )"
#property link      "moncaresi@gmail.com"
#property version   "1.00"
#property description "GoldenMit — Bahar1 gold edition: dollar-scale params + daily trade cap + cooldown"

enum manager { P = 0, B = 1 };

input string  TimeFilter        = "||======= Time Filter  =======||";
input bool    UseTimeFilter     = true;
input int     TimeStartTrade    = 3;   // Start Trade
input int     TimeEndTrade      = 22;  // End Trade
input string  TradingDays       = "-- Days to open a new trades --";
input bool    Sunday            = false;
input bool    Monday            = true;
input bool    Tuesday           = true;
input bool    Wednesday         = true;
input bool    Thursday          = true;
input bool    Friday            = true;
input bool    Saturday          = false;
input int     Signal_2          = 30;
input int     Signal_2_Period   = 150; // SignalToTrade (نقطه؛ 150 = 1.5 دلار روی طلا)
input int     StopLoss          = 100;
input int     TrailingLoss      = 100;
input int     TrailingStop      = 50;  // نقطه؛ 50 = 0.5 دلار روی طلا
input double  FixedLot          = 0.0;
input double  AutoMM            = 10.0;
input int     Max_Spread        = 30;  // نقطه؛ 30 = 0.3 دلار روی طلا
input int     TradeDeviation    = 3;   // حداکثر پندینگ همزمان
input int     VelocityTime      = 10;  // پنجره سرعت (ثانیه)
input int     TradeDelta        = 100; // فاصله پندینگ (نقطه؛ 100 = 1 دلار روی طلا)
input int     DeleteRatio       = 60;
input int     TickSample        = 100;
input int     MaxTradesPerDay   = 8;   // حداکثر ورود در روز (بهینه: 8)
input int     MinSecondsBetweenEntries = 180; // حداقل فاصله بین ورودها (بهینه: 180)

int          Slippage           = 0;
int          Magic              = 56343;
string       Open_Comment       = "GoldenMit";

string LockedInfo;
double CECount;
double Balance = 0.0;
bool   DayOfWeeK;
bool   TimeToTrade = true;      // fix: وقتی UseTimeFilter=false فعال بماند
manager TradeManager = P;
int    r, size, digits, stoplevel;
double marginRequirement, maxLot, minLot, points, currentSpread, avgSpread, maxSpread, initialBalance, rateChange, deleteRatio, commissionPoints;
string BackgroundName;
string BackgroundName2;
long   ChartColor;
double spreadSize[];
double tick[];
int    tickTime[];
double initial_deposit = 0;
bool   Locked = false;
int    lastBuyOrder, lastSellOrder;
int    TS = 5;          // mutable TrailingStop copy
int    TD = 1;          // mutable TradeDelta copy
bool   calculateCommission = true;
double max = 0;
bool   LockedDate = false;
datetime ExpiryDate = D'2019.12.31';
//---------------------------------------------------------------------
bool LockedAccount = false;
int AccountNo1 = 1679729;
int AccountNo2 = 58127;
int AccountNo3 = 123456;

// --- GoldenMit: ضد بیش‌فعالی ---
datetime lastEntryTime     = 0;
int      tradesToday       = 0;
ulong    lastSeenPosTicket = 0;
datetime dayStartStamp     = 0;
double   maxEquity         = 0.0;

//==================== توابع کمکی MQL5 ====================
// LWMA روی آرایه (جایگزین iMAOnArray که در MQL5 وجود ندارد)
double LWMA(const double &arr[], int total, int period, int shift)
{
   if(period <= 0 || total <= 0) return 0.0;
   double sum = 0.0, wsum = 0.0;
   int w = period;
   for(int i = shift; i < shift + period && i < total; i++)
   {
      sum += arr[i] * w;
      wsum += w;
      w--;
   }
   return (wsum > 0.0) ? sum / wsum : 0.0;
}

bool DeletePending(ulong ticket)
{
   MqlTradeRequest req = {};
   MqlTradeResult  res = {};
   req.action = TRADE_ACTION_REMOVE;
   req.order  = ticket;
   return OrderSend(req, res);
}

// fix: قیمت پندینگ را طوری اصلاح می‌کند که همیشه خارج از STOPS_LEVEL و
// با بافر حداقلی از بازار باشد — حذف خطای 10015 Invalid price
double SafePendingPrice(ENUM_ORDER_TYPE type, double price)
{
   double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);
   double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);
   double stopsLvl = (double)SymbolInfoInteger(_Symbol, SYMBOL_TRADE_STOPS_LEVEL) * _Point;
   double minGap   = MathMax(_Point * 3.0, stopsLvl + _Point);
   if(type == ORDER_TYPE_BUY_STOP || type == ORDER_TYPE_BUY_LIMIT || type == ORDER_TYPE_BUY_STOP_LIMIT)
   {
      if(price < ask + minGap)
         price = ask + minGap;
   }
   else
   {
      if(price > bid - minGap)
         price = bid - minGap;
   }
   return NormalizeDouble(price, _Digits);
}

bool ModifySL(ulong posTicket, double sl, double tp)
{
   MqlTradeRequest req = {};
   MqlTradeResult  res = {};
   req.action   = TRADE_ACTION_SLTP;
   req.symbol   = _Symbol;
   req.position = posTicket;
   req.sl       = NormalizeDouble(sl, _Digits);
   req.tp       = NormalizeDouble(tp, _Digits);
   return OrderSend(req, res);
}

ulong PlaceStop(ENUM_ORDER_TYPE type, double lot, double price)
{
   MqlTradeRequest req = {};
   MqlTradeResult  res = {};
   req.action    = TRADE_ACTION_PENDING;
   req.symbol    = _Symbol;
   req.volume    = lot;
   req.type      = type;
   req.price     = SafePendingPrice(type, price);
   req.sl        = 0;
   req.tp        = 0;
   req.deviation = Slippage;
   req.magic     = Magic;
   req.comment   = Open_Comment;
   req.type_time = ORDER_TIME_GTC;
   // fix: یک بار retry با قیمت به‌روز (بازار بین محاسبه و ارسال جابه‌جا شده)
   for(int attempt = 0; attempt < 2; attempt++)
   {
      if(OrderSend(req, res))
         return res.order;
      req.price = SafePendingPrice(type, req.price);
   }
   Print("OrderSend err ", res.retcode, " ", res.comment);
   return 0;
}

// شروع روز معاملاتی (ساعت 00:00 سرور)
datetime DayStart(datetime t)
{
   MqlDateTime d;
   TimeToStruct(t, d);
   d.hour = 0;
   d.min  = 0;
   d.sec  = 0;
   return StructToTime(d);
}

//==================== INIT ====================
int OnInit()
{
   if(GlobalVariableCheck("Initial Deposit"))
      GlobalVariableDel("initial Deposit");
   GlobalVariableSet("Initial Deposit", AccountInfoDouble(ACCOUNT_EQUITY));
   initial_deposit = GlobalVariableGet("Initial Deposit");

   ChartColor = ChartGetInteger(0, CHART_COLOR_BACKGROUND, 0);
   BackgroundName = "Background-" + MQLInfoString(MQL_PROGRAM_NAME);
   if(ObjectFind(0, BackgroundName) == -1)
      ChartBackground(BackgroundName, clrDarkBlue, 2, 15, 140, 155);
   BackgroundName2 = "Background2-" + MQLInfoString(MQL_PROGRAM_NAME);
   if(ObjectFind(0, BackgroundName2) == -1)
      ChartBackground2(BackgroundName2, clrDarkBlue, 2, 15, 140, 155);

   marginRequirement = SymbolInfoDouble(_Symbol, SYMBOL_MARGIN_INITIAL) * 0.01;
   maxLot   = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_MAX);
   minLot   = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_MIN);
   digits   = (int)SymbolInfoInteger(_Symbol, SYMBOL_DIGITS);
   currentSpread = NormalizeDouble(SymbolInfoDouble(_Symbol, SYMBOL_ASK) - SymbolInfoDouble(_Symbol, SYMBOL_BID), digits);
   stoplevel = (int)MathMax(SymbolInfoInteger(_Symbol, SYMBOL_TRADE_FREEZE_LEVEL), SymbolInfoInteger(_Symbol, SYMBOL_TRADE_STOPS_LEVEL));
   TD = MathMax(TradeDelta, stoplevel);
   TS = MathMax(TrailingStop, stoplevel);
   avgSpread = currentSpread;
   size = TickSample;
   ArrayResize(spreadSize, size);
   ArrayFill(spreadSize, 0, size, avgSpread);
   maxSpread    = NormalizeDouble((double)Max_Spread * _Point, digits);
   deleteRatio  = NormalizeDouble((double)DeleteRatio / 100, 2);
   initialBalance = AccountInfoDouble(ACCOUNT_BALANCE);

   //--- Expiry Date
   if((TimeCurrent() >= ExpiryDate) && (LockedDate == true))
   {
      Locked = true;
      LockedInfo = StringFormat("Expert has expired (%s)", TimeToString(ExpiryDate, TIME_DATE));
   }
   //--- Account
   if(LockedAccount == true)
   {
      if((AccountInfoInteger(ACCOUNT_TRADE_MODE) != ACCOUNT_TRADE_MODE_DEMO) &&
         (AccountInfoInteger(ACCOUNT_LOGIN) != AccountNo1) &&
         (AccountInfoInteger(ACCOUNT_LOGIN) != AccountNo2) &&
         (AccountInfoInteger(ACCOUNT_LOGIN) != AccountNo3))
      {
         Locked = true;
         LockedInfo = "Locked version. Expert run only on specific account.";
      }
   }
   dayStartStamp = DayStart(TimeCurrent());
   Print("GoldenMit MQL5 ready. Magic=", Magic, " Symbol=", _Symbol);
   return INIT_SUCCEEDED;
}

void OnDeinit(const int reason) { }

//==================== کمیسیون ====================
void commission()
{
   if(MQLInfoInteger(MQL_TESTER) || MQLInfoInteger(MQL_OPTIMIZATION) ||
      MQLInfoInteger(MQL_VISUAL_MODE) || AccountInfoInteger(ACCOUNT_TRADE_MODE) == ACCOUNT_TRADE_MODE_DEMO)
   {
      if(!HistorySelect(0, TimeCurrent())) return;
      double tv = SymbolInfoDouble(_Symbol, SYMBOL_TRADE_TICK_VALUE);
      double ts = SymbolInfoDouble(_Symbol, SYMBOL_TRADE_TICK_SIZE);
      for(int pos = HistoryDealsTotal() - 1; pos >= 0; pos--)
      {
         ulong d = HistoryDealGetTicket(pos);
         if(d == 0) continue;
         if(HistoryDealGetString(d, DEAL_SYMBOL) != _Symbol) continue;
         if((long)HistoryDealGetInteger(d, DEAL_MAGIC) != Magic) continue;
         if(HistoryDealGetInteger(d, DEAL_ENTRY) != DEAL_ENTRY_OUT) continue;
         if(HistoryDealGetDouble(d, DEAL_PROFIT) != 0.0)
         {
            calculateCommission = false;
            double vol = HistoryDealGetDouble(d, DEAL_VOLUME);
            double rate = (vol > 0 && ts > 0) ? vol * tv / ts : 0;
            if(rate > 0)
               commissionPoints = -HistoryDealGetDouble(d, DEAL_COMMISSION) / rate;
            break;
         }
      }
   }
}

//==================== TICK ====================
void OnTick()
{
   if(Locked) { Comment(LockedInfo); return; }

   // ردیابی اوج اکویتی (برای گزارش)
   double eqNow = AccountInfoDouble(ACCOUNT_EQUITY);
   if(eqNow > maxEquity) maxEquity = eqNow;

   MqlDateTime dt;
   TimeToStruct(TimeCurrent(), dt);

   if(AllowedDay(dt.day_of_week) == false)
   {
      Comment("\n"
              "\n"
              "\n Today is not allowed for trading");
      return;
   }

   //Check time to trade
   if(UseTimeFilter == true)
   {
      int hour = dt.hour;
      if(hour <= TimeStartTrade || hour >= TimeEndTrade)
         TimeToTrade = false;
      else
         TimeToTrade = true;
   }

   // --- GoldenMit: شمارش روزانه و تشخیص پوزیشن جدید ---
   datetime ds = DayStart(TimeCurrent());
   if(ds != dayStartStamp)
   {
      dayStartStamp = ds;
      tradesToday   = 0;
   }

   int totalBuyStop = 0;
   int totalSellStop = 0;
   if(calculateCommission) commission();
   prepareSpread();
   manageTicks();

   int totalTrades = 0;
   bool ok;

   // --- مدیریت سفارش‌های پندینگ (BuyStop/SellStop) ---
   for(int pos = OrdersTotal() - 1; pos >= 0; pos--)
   {
      ulong tk = OrderGetTicket(pos);
      if(tk == 0) continue;
      if(OrderGetString(ORDER_SYMBOL) != _Symbol) continue;
      if((long)OrderGetInteger(ORDER_MAGIC) != Magic) continue;
      totalTrades++;
      ENUM_ORDER_TYPE ot = (ENUM_ORDER_TYPE)OrderGetInteger(ORDER_TYPE);
      if(ot == ORDER_TYPE_BUY_STOP)
      {
         if((int)TimeCurrent() - lastBuyOrder > VelocityTime &&
            rateChange < Signal_2_Period * _Point * deleteRatio)
            ok = DeletePending(tk);
         totalBuyStop++;
      }
      else if(ot == ORDER_TYPE_SELL_STOP)
      {
         if((int)TimeCurrent() - lastSellOrder > VelocityTime &&
            rateChange > -Signal_2_Period * _Point * deleteRatio)
            ok = DeletePending(tk);
         totalSellStop++;
      }
   }

   // --- مدیریت پوزیشن‌ها (تریلینگ) ---
   for(int pos = PositionsTotal() - 1; pos >= 0; pos--)
   {
      ulong tk = PositionGetTicket(pos);
      if(tk == 0) continue;
      if(PositionGetString(POSITION_SYMBOL) != _Symbol) continue;
      if((long)PositionGetInteger(POSITION_MAGIC) != Magic) continue;
      totalTrades++;

      // GoldenMit: پوزیشن جدید با تیکت بزرگ‌تر از آخرین دیده‌شده → شمارش روزانه
      if(tk > lastSeenPosTicket)
      {
         lastSeenPosTicket = tk;
         tradesToday++;
      }

      double bid = SymbolInfoDouble(_Symbol, SYMBOL_BID);
      double ask = SymbolInfoDouble(_Symbol, SYMBOL_ASK);
      double openP = PositionGetDouble(POSITION_PRICE_OPEN);
      double sl    = PositionGetDouble(POSITION_SL);
      double tp    = PositionGetDouble(POSITION_TP);
      double eq    = AccountInfoDouble(ACCOUNT_EQUITY);
      double bl    = AccountInfoDouble(ACCOUNT_BALANCE);

      if((ENUM_POSITION_TYPE)PositionGetInteger(POSITION_TYPE) == POSITION_TYPE_BUY)
      {
         if(bid - openP + commissionPoints > TS * _Point)
         {
            if(sl == 0.0 || bid - sl > TS * _Point)
               if(NormalizeDouble(bid - (TS * _Point), _Digits) != sl)
                  ok = ModifySL(tk, NormalizeDouble(bid - (TS * _Point), _Digits), tp);
         }
         else
         {
            if(eq > max || (bl > 0 && eq / bl < (double)StopLoss / 100))
            {
               if(rateChange < -Signal_2 * _Point && bid < openP - (Signal_2_Period * _Point))
                  if(sl == 0.0 || bid - sl > (TS * _Point * TrailingLoss))
                     if(NormalizeDouble(bid - (TS * _Point * TrailingLoss), _Digits) != sl)
                        ok = ModifySL(tk, NormalizeDouble(bid - (TS * _Point * TrailingLoss), _Digits), tp);
            }
         }
      }
      else // SELL
      {
         if(openP - commissionPoints - ask > TS * _Point)
         {
            if(sl == 0.0 || sl - ask > TS * _Point)
               if(NormalizeDouble(ask + (TS * _Point), _Digits) != sl)
                  ok = ModifySL(tk, NormalizeDouble(ask + (TS * _Point), _Digits), tp);
         }
         else
         {
            if(eq > max || (bl > 0 && eq / bl < (double)StopLoss / 100))
            {
               if(rateChange > Signal_2 * _Point && ask > openP + (Signal_2_Period * _Point))
                  if(sl == 0.0 || sl - ask > (TS * _Point * TrailingLoss))
                     if(NormalizeDouble(ask + (TS * _Point * TrailingLoss), _Digits) != sl)
                        ok = ModifySL(tk, NormalizeDouble(ask + (TS * _Point * TrailingLoss), _Digits), tp);
            }
         }
      }
   }

   if(totalTrades == 0)
   {
      if(AccountInfoDouble(ACCOUNT_BALANCE) > max) max = AccountInfoDouble(ACCOUNT_BALANCE);
   }

   // --- ورود جدید (با گیت‌های GoldenMit) ---
   if(TradeManager == 0 && totalTrades < TradeDeviation && TimeToTrade == true)
   {
      // گیت روزانه: حداکثر MaxTradesPerDay ورود در روز
      if(tradesToday >= MaxTradesPerDay) return;
      // گیت فاصله: حداقل MinSecondsBetweenEntries ثانیه بین ورودها
      if(TimeCurrent() - lastEntryTime < MinSecondsBetweenEntries) return;

      double lot = CalcLot();
      if(rateChange > Signal_2_Period * _Point && avgSpread <= maxSpread && totalBuyStop < TradeDeviation)
      {
         double margin = 0;
         if(!OrderCalcMargin(ORDER_TYPE_BUY, _Symbol, lot, SymbolInfoDouble(_Symbol, SYMBOL_ASK), margin) ||
            margin > AccountInfoDouble(ACCOUNT_MARGIN_FREE))
         {
            Print("Notice: margin insufficient, skip entry");
            return;
         }
         if(PlaceStop(ORDER_TYPE_BUY_STOP, lot,
                      SymbolInfoDouble(_Symbol, SYMBOL_ASK) + (totalBuyStop + 1.0) * (_Point * TD)) != 0)
         {
            lastBuyOrder = (int)TimeCurrent();
            lastEntryTime = TimeCurrent();
         }
      }
      if(rateChange < -Signal_2_Period * _Point && avgSpread <= maxSpread && totalSellStop < TradeDeviation)
      {
         double margin = 0;
         if(!OrderCalcMargin(ORDER_TYPE_SELL, _Symbol, lot, SymbolInfoDouble(_Symbol, SYMBOL_BID), margin) ||
            margin > AccountInfoDouble(ACCOUNT_MARGIN_FREE))
         {
            Print("Notice: margin insufficient, skip entry");
            return;
         }
         if(PlaceStop(ORDER_TYPE_SELL_STOP, lot,
                      SymbolInfoDouble(_Symbol, SYMBOL_BID) - (totalSellStop + 1.0) * (_Point * TD)) != 0)
         {
            lastSellOrder = (int)TimeCurrent();
            lastEntryTime = TimeCurrent();
         }
      }
   }
}

//==================== لات ====================
double CalcLot()
{
   double lot = 0;
   if(FixedLot > 0)
   {
      lot = NormalizeDouble(FixedLot, 2);
   }
   else
   {
      if(marginRequirement > 0)
         lot = MathMax(MathMin(NormalizeDouble((AccountInfoDouble(ACCOUNT_BALANCE) * ((double)AutoMM / 1000) * 0.01 / marginRequirement), 2), maxLot), minLot);
      else
         lot = minLot;   // fallback if symbol margin not reported
   }
   lot = NormalizeLots(lot);
   if(lot < minLot) lot = minLot;
   // سقف با مارجین آزاد — جلوگیری از مرجین‌کال
   double margin = 0;
   if(OrderCalcMargin(ORDER_TYPE_BUY, _Symbol, lot, SymbolInfoDouble(_Symbol, SYMBOL_ASK), margin) && margin > 0)
   {
      double maxByMargin = AccountInfoDouble(ACCOUNT_MARGIN_FREE) / margin * lot;
      if(maxByMargin < lot)
      {
         lot = MathFloor(maxByMargin / SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_STEP)) * SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_STEP);
         if(lot < minLot) lot = minLot;
      }
   }
   return lot;
}

double NormalizeLots(double p)
{
   double ls = SymbolInfoDouble(_Symbol, SYMBOL_VOLUME_STEP);
   return(MathRound(p / ls) * ls);
}

//==================== اسپرد ====================
void prepareSpread()
{
   if(MQLInfoInteger(MQL_TESTER) || MQLInfoInteger(MQL_OPTIMIZATION) ||
      MQLInfoInteger(MQL_VISUAL_MODE) || AccountInfoInteger(ACCOUNT_TRADE_MODE) == ACCOUNT_TRADE_MODE_DEMO)
   {
      double spreadSize_temp[];
      ArrayResize(spreadSize_temp, size - 1);
      ArrayCopy(spreadSize_temp, spreadSize, 0, 1, size - 1);
      ArrayResize(spreadSize_temp, size);
      spreadSize_temp[size - 1] = NormalizeDouble(SymbolInfoDouble(_Symbol, SYMBOL_ASK) - SymbolInfoDouble(_Symbol, SYMBOL_BID), digits);
      ArrayCopy(spreadSize, spreadSize_temp, 0, 0);
      avgSpread = LWMA(spreadSize, size, size, 0);
   }
}

//==================== تیک‌ها ====================
void manageTicks()
{
   double tick_temp[], avgtick_temp[];
   int tickTime_temp[];
   ArrayResize(tick_temp, size - 1);
   ArrayResize(tickTime_temp, size - 1);
   ArrayCopy(tick_temp, tick, 0, 1, size - 1);
   ArrayCopy(tickTime_temp, tickTime, 0, 1, size - 1);
   ArrayResize(tick_temp, size);
   ArrayResize(tickTime_temp, size);
   tick_temp[size - 1] = SymbolInfoDouble(_Symbol, SYMBOL_BID);
   tickTime_temp[size - 1] = (int)TimeCurrent();
   ArrayCopy(tick, tick_temp, 0, 0);
   ArrayCopy(tickTime, tickTime_temp, 0, 0);

   int timeNow = tickTime[size - 1];
   double priceNow = tick[size - 1];
   double priceThen = 0;
   int period = 0;
   for(int i = size - 1; i >= 0; i--)
   {
      period++;
      if(timeNow - tickTime[i] > VelocityTime)
      {
         priceThen = tick[i];
         break;
      }
   }

   rateChange = (priceNow - priceThen);
   if(rateChange / _Point > 5000) rateChange = 0;

   ObjectSetString(0, "Designer", OBJPROP_TEXT, " moncaresi@gmail.com ");
   ObjectSetInteger(0, "Designer", OBJPROP_FONTSIZE, 10);
   ObjectSetString(0, "Designer", OBJPROP_FONT, "Rockwell Extra");
   ObjectSetInteger(0, "Designer", OBJPROP_COLOR, clrBlack);

   Comment("----------------------------------------------"
           + "\n Balance      :  " + DoubleToString(initialBalance, 0) + " USD"
           + "\n max           :  " + DoubleToString(max, 2) + "  USD"
           + "\n Percentage :  " + DoubleToString((((AccountInfoDouble(ACCOUNT_EQUITY) - initial_deposit) / initial_deposit) * 100), 2) + "  %"
           + "\n--------------------------------------------"
           + "\n SellOrder    :  " + DoubleToString(lastSellOrder, 0)
           + "\n BuyOrder   :  " + DoubleToString(lastBuyOrder, 0)
           + "\n TodayTrades  :  " + IntegerToString(tradesToday)
           + "\n--------------------------------------------"
           + "\n swap          :  " + DoubleToString(0, 4) + " USD"
           + "\n commission  :  " + DoubleToString(0, 4) + " USD"
           + "\n spread        :  " + DoubleToString((double)SymbolInfoInteger(_Symbol, SYMBOL_SPREAD), 1) + " PIP"
           + "\n--------------------------------------------");
}

//==================== گزارش تستر ====================
double OnTester()
{
   double profit = 0.0, gp = 0.0, gl = 0.0;
   int trades = 0;
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
         double p = HistoryDealGetDouble(t, DEAL_PROFIT) +
                    HistoryDealGetDouble(t, DEAL_SWAP) +
                    HistoryDealGetDouble(t, DEAL_COMMISSION);
         profit += p;
         if(p >= 0.0) gp += p; else gl -= p;
         trades++;
      }
   }
   double pf = (gl > 0.0) ? gp / gl : (gp > 0.0 ? 999.0 : 0.0);
   double finalBal = AccountInfoDouble(ACCOUNT_BALANCE);
   double dd = (maxEquity > 0.0) ? 100.0 * (maxEquity - finalBal) / maxEquity : 0.0;
   if(dd < 0.0) dd = 0.0;
   Print("OnTester: profit=", DoubleToString(profit, 2),
         " PF=", DoubleToString(pf, 2),
         " DD=", DoubleToString(dd, 2), "%",
         " trades=", trades,
         " balance=", DoubleToString(finalBal, 2));
   return profit;
}

//==================== پس‌زمینه چارت ====================
void ChartBackground(string StringName, color ImageColor, int Xposition, int Yposition, int Xsize, int Ysize)
{
   if(ObjectFind(0, StringName) == -1)
   {
      ObjectCreate(0, StringName, OBJ_RECTANGLE_LABEL, 0, 0, 0);
      ObjectSetInteger(0, StringName, OBJPROP_XDISTANCE, Xposition);
      ObjectSetInteger(0, StringName, OBJPROP_YDISTANCE, Yposition);
      ObjectSetInteger(0, StringName, OBJPROP_XSIZE, Xsize);
      ObjectSetInteger(0, StringName, OBJPROP_YSIZE, Ysize);
      ObjectSetInteger(0, StringName, OBJPROP_BGCOLOR, ImageColor);
      ObjectSetInteger(0, StringName, OBJPROP_BORDER_TYPE, BORDER_FLAT);
      ObjectSetInteger(0, StringName, OBJPROP_BORDER_COLOR, clrWhite);
      ObjectSetInteger(0, StringName, OBJPROP_BACK, false);
      ObjectSetInteger(0, StringName, OBJPROP_SELECTABLE, false);
      ObjectSetInteger(0, StringName, OBJPROP_SELECTED, false);
      ObjectSetInteger(0, StringName, OBJPROP_HIDDEN, false);
      ObjectSetInteger(0, StringName, OBJPROP_ZORDER, 0);
   }
}

void ChartBackground2(string StringName2, color ImageColor, int Xposition, int Yposition, int Xsize, int Ysize)
{
   if(ObjectFind(0, StringName2) == -1)
   {
      ObjectCreate(0, StringName2, OBJ_RECTANGLE_LABEL, 0, 0, 0);
      ObjectSetInteger(0, StringName2, OBJPROP_CORNER, 0);
      ObjectSetInteger(0, StringName2, OBJPROP_XDISTANCE, 2);
      ObjectSetInteger(0, StringName2, OBJPROP_YDISTANCE, 170);
      ObjectSetInteger(0, StringName2, OBJPROP_XSIZE, Xsize);
      ObjectSetInteger(0, StringName2, OBJPROP_YSIZE, 30);
      ObjectSetInteger(0, StringName2, OBJPROP_BGCOLOR, clrDarkKhaki);
      ObjectSetInteger(0, StringName2, OBJPROP_BORDER_TYPE, BORDER_FLAT);
      ObjectSetInteger(0, StringName2, OBJPROP_BORDER_COLOR, clrWhite);
      ObjectSetInteger(0, StringName2, OBJPROP_BACK, false);
      ObjectSetInteger(0, StringName2, OBJPROP_SELECTABLE, false);
      ObjectSetInteger(0, StringName2, OBJPROP_SELECTED, false);
      ObjectSetInteger(0, StringName2, OBJPROP_HIDDEN, false);
      ObjectSetInteger(0, StringName2, OBJPROP_ZORDER, 0);
      ObjectCreate(0, "Designer", OBJ_LABEL, 0, 0, 0);
      ObjectSetInteger(0, "Designer", OBJPROP_CORNER, 0);
      ObjectSetInteger(0, "Designer", OBJPROP_XDISTANCE, 0);
      ObjectSetInteger(0, "Designer", OBJPROP_YDISTANCE, 175);
   }
}

bool AllowedDay(int fDayOfWeek)
{
   bool Allowed = true;

   if(fDayOfWeek == 0 && Sunday == false) Allowed = false;    //Sunday
   if(fDayOfWeek == 1 && Monday == false) Allowed = false;    //Monday
   if(fDayOfWeek == 2 && Tuesday == false) Allowed = false;
   if(fDayOfWeek == 3 && Wednesday == false) Allowed = false;
   if(fDayOfWeek == 4 && Thursday == false) Allowed = false;
   if(fDayOfWeek == 5 && Friday == false) Allowed = false;
   if(fDayOfWeek == 6 && Saturday == false) Allowed = false;  //Saturday

   return(Allowed);
}
