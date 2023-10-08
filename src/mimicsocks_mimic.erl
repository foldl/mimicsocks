%@doc       change the stat. characters of tcp packages
%@author    foldl
-module(mimicsocks_mimic).

-behaviour(gen_server).

%% API
-export([start_link/1, stop/1, recv/2, flush/1, change/1, change/2, suspend/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

%helpers
-export([choice/1]).

-include("mimicsocks.hrl").

-define(EPSILON, 1/1000000.0).

-record(state,
    {
        output,
        size_dist,      % identity, constant, uniform, gaussian
        delay_dist,     % identity, constant, uniform, gaussian, poission
        queue = queue:new(),
        total,
        create_t,
        last_recv_t,
        last_send_t,
        size_esti,       % welford or iir
        delay_esti,
        suspended = false
    }).

%@doc online mean & variance estimator
-record(param_esti,
    {
        algo,
        state
    }).

stop(Pid) -> gen_server:call(Pid, stop).

flush(Pid) -> Pid ! flush.

suspend(Pid, MilliSec) -> Pid ! {suspend, MilliSec}.

start_link(Args) -> gen_server:start_link(?MODULE, Args, []).

recv(Pid, Data) when is_binary(Data) ->
    Pid ! {recv, self(), Data};
recv(Pid, Data) when is_list(Data) ->
    [recv(Pid, X) || X <- Data].

change(Pid) -> change(Pid, {rand_size_model(), rand_delay_model()}).

change(Pid, {SizeModel, DelayModel}) -> Pid ! {change, SizeModel, DelayModel}.

%% callback funcitons
init([Output]) ->
    init([Output, rand_size_model(), rand_delay_model(), iir]);
init([Output, SizeModel, DelayModel, Estimator]) ->
    T = cur_tick(),
    {ok, #state{
        output = Output,
        size_dist = SizeModel,
        delay_dist = DelayModel,
        queue = queue:new(),
        total = 0,
        create_t = T,
        last_recv_t = T,
        last_send_t = T,
        size_esti = esti_init(Estimator),
        delay_esti = esti_init(Estimator),
        suspended = false
    }}.

handle_call(stop, _From, State) ->
    {stop, normal, stopped, State};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({flush, Ref, _From}, #state{output = Output} = State) ->
    R = handle_info0(flush, State),
    Output ! {flush, Ref, self()},
    R;
handle_info(resume, State) ->
    {noreply, State#state{suspended = false}};
handle_info({suspend, MilliSec}, State) ->
    timer:send_after(MilliSec, resume),
    handle_info0(flush, State#state{suspended = true});
handle_info({change, SizeModel, DelayModel}, State) ->
    {noreply, State#state{size_dist = SizeModel, delay_dist = DelayModel}};
handle_info(stop, State) ->
    {stop, normal, State};
handle_info(Info, #state{suspended = Suspended} = State) ->
    {noreply, NewState} = handle_info0(Info, State),
    case Suspended of
        true ->
            handle_info0(flush, NewState);
        _ ->
            case queue:is_empty(NewState#state.queue) of
                false -> schedule(NewState);
                _ -> ok
            end,
            {noreply, NewState}
    end.

handle_info0({recv, _From, Data}, #state{last_recv_t = LastT, delay_esti = DelayEsti,
                                        size_esti = SizeEsti,
                                        queue = Q, total = Total} = State) ->
    T = cur_tick(),
    NewDelayEsti = esti_run(T - LastT, DelayEsti),
    NewSizeEsti  = esti_run(size(Data), SizeEsti),
    NewState = State#state{last_recv_t = T,
                           delay_esti = NewDelayEsti,
                           size_esti  = NewSizeEsti,
                           total = Total + size(Data),
                           queue = queue:in(Data, Q)},
    {noreply, NewState};
handle_info0(flush, State) ->
    flush0(State),
    {noreply, State#state{queue = queue:new(), total = 0}};
handle_info0({flush, N}, #state{output = Output, queue = Q, total = Total} = State) ->
    N2 = min(N, queue:len(Q)),
    Self = self(),
    {NewQ, SendTotal} =
        lists:foldl(fun (_, {AQueue, Acc}) ->
                        {{value, Bin}, Q2} = queue:out(AQueue),
                        Output ! {recv, Self, Bin},
                        {Q2, Acc + size(Bin)}
                    end, {Q, 0},
                    lists:seq(1, N2)),
    {noreply, State#state{queue = NewQ, total = Total - SendTotal}};
handle_info0({schedule, Size}, State) ->
    NewState = schedule_send(Size, State),
    {noreply, NewState}.

terminate(_Reason, State) ->
    flush0(State),
    normal.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

% ----------------------
% helpers
% ----------------------

flush0(#state{output = Output, queue = Q} = _State) ->
    Pid = self(),
    lists:foreach(fun (X) -> Output ! {recv, Pid, X} end, queue:to_list(Q)).

cur_tick() -> erlang:monotonic_time(millisecond).

schedule_send(Size, State) when Size =< 0 -> State;
schedule_send(Size, #state{output = Output, queue = Q, total = Total} = State) ->
    case queue:out(Q) of
        {empty, _Q2} -> State;
        {{value, Bin}, Q2} ->
            SZ = size(Bin),
            case Size >= SZ of
                true ->
                    Output ! {recv, self(), Bin},
                    schedule_send(Size - SZ, State#state{queue = Q2, total = Total - SZ});
                _ ->
                    <<Send:Size/binary, Rem/binary>> = Bin,
                    Output ! {recv, self(), Send},
                    State#state{queue = queue:in_r(Rem, Q2), total = Total - Size}
            end
    end.

schedule_delay(#state{delay_dist = identity} = _State) ->
    0;
schedule_delay(#state{last_send_t = LastT,
                delay_esti = DelayEsti, delay_dist = constant} = _State) ->
    {Mean, _Var} = esti_get(DelayEsti),
    Mean + LastT - cur_tick();
schedule_delay(#state{last_send_t = LastT,
                delay_esti = DelayEsti, delay_dist = uniform} = _State) ->
    {Mean, Var} = esti_get(DelayEsti),
    X = math:sqrt(12 * Var),
    Mean + rand:uniform() * X + LastT - cur_tick();
schedule_delay(#state{last_send_t = LastT,
                delay_esti = DelayEsti, delay_dist = gaussian} = _State) ->
    {Mean, Var} = esti_get(DelayEsti),
    Z = rand:normal(Mean, Var),
    LastT + Z - cur_tick();
schedule_delay(#state{last_send_t = LastT,
                delay_esti = DelayEsti, delay_dist = poission} = _State) ->
    % here, the delay between two packages follows exponential distribution
    % pdf(x) = lambda exp(-lambda * x), for x >= 0
    % while lambda can be estimated as 1/Mean
    % let's generate exponential distribution random variable by inverse transforming
    {Mean, _Var} = esti_get(DelayEsti),
    Z = - math:log(max(rand:uniform(), ?EPSILON)) * Mean,
    LastT + Z - cur_tick().

schedule_size(#state{size_dist = identity, queue = Q} = _State) ->
    size(queue:head(Q));
schedule_size(#state{size_dist = constant, size_esti = SizeEsti} = _State) ->
    {Mean, _Var} = esti_get(SizeEsti),
    Mean;
schedule_size(#state{size_dist = uniform, size_esti = SizeEsti} = _State) ->
    {Mean, Var} = esti_get(SizeEsti),
    X = math:sqrt(12 * Var),
    Mean + rand:uniform() * X;
schedule_size(#state{size_dist = gaussian, size_esti = SizeEsti} = _State) ->
    {Mean, Var} = esti_get(SizeEsti),
    rand:normal(Mean, Var).

-define(Q_LEN, 4).
-define(Q_BYTES, 100 * 1024).

schedule(#state{queue = Q, total = Total, create_t = CreateT} = State) ->
    T = cur_tick(),
    case {T - CreateT < 2000, queue:len(Q), Total} of
        {true, _, _} -> self() ! flush;
        {_, _L, T} when T < 100  -> self() ! flush;
        {_, L, _T} when L > ?Q_LEN  -> self() ! {flush, queue:len(Q) - ?Q_LEN};
        {_, _L, T} when T > ?Q_BYTES -> self() ! {flush, 1};
        _ ->
            Delay = min(schedule_delay(State), 100),
            Size = round(schedule_size(State)),
            case {Delay > 10, Size > 0} of
                {_, false} -> self() ! flush;
                {true, true} -> timer:send_after(Delay, {schedule, Size});
                {_, true} -> self() ! {schedule, Size}
            end
    end.

%@doc init a algorithm for mean/variance estimation
esti_init(welford) ->
    #param_esti{algo = {fun welford_run/2, fun welford_get/1},
                state = welford_init()};
esti_init(iir) ->
    #param_esti{algo = {fun iir_run/2, fun iir_get/1},
                state = iir_init()}.

esti_run(X, #param_esti{algo = {RunFun, _GetFun}, state = AlgoData} = EsitState) ->
    EsitState#param_esti{state = RunFun(X, AlgoData)}.

esti_get(#param_esti{algo = {_RunFun, GetFun}, state = AlgoData} = _EsitState) ->
    GetFun(AlgoData).

% -----------------------
% welford algorithm
% -----------------------

%@doc online mean & variance estimator
-record(welford_state,
    {
        n = 0,
        mean = 0.0,
        m2 = 0.0
    }).

welford_init() ->
    #welford_state{}.

welford_run(X, #welford_state{n = N, mean = Mean, m2 = M2} = _State) ->
    NewN = N + 1,
    Delta = X - Mean,
    NewMean = Mean + Delta / NewN,
    Delta2 = X - NewMean,
    NewM2 = M2 + Delta2 * Delta2,
    #welford_state{n = NewN, mean = NewMean, m2 = NewM2}.

welford_get(#welford_state{n = N, mean = Mean, m2 = M2} = _State) when N > 1 ->
    {Mean, M2 / (N - 1)};
welford_get(#welford_state{mean = Mean} = _State) ->
    {Mean, 0}.

% -----------------------
% IIR-based estimator
% -----------------------

%@doc online mean & variance estimator
-record(iir_state,
    {
        mean = 0.0,
        var = 0.0
    }).

iir_init() ->
    #iir_state{}.

-define(MEAN_ALPHA, 0.1).
-define(VAR_ALPHA, 0.05).

iir_run(X, #iir_state{mean = Mean, var = Var} = _State) ->
    NewMean = ?MEAN_ALPHA * X + (1 - ?MEAN_ALPHA) * Mean,
    Delta = X - NewMean,
    NewVar = ?VAR_ALPHA * Delta * Delta + (1 - ?VAR_ALPHA) * Var,
    #iir_state{mean = NewMean, var = NewVar}.

iir_get(#iir_state{mean = Mean, var = Var} = _State) ->
    {Mean, Var}.

choice(L) ->
    Len = length(L),
    lists:nth(rand:uniform(Len), L).

rand_size_model() -> choice([identity, constant, uniform, gaussian]).
rand_delay_model() -> choice([identity, constant, uniform, gaussian, poission]).