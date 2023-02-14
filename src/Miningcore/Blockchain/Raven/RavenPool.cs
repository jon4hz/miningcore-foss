using System.Globalization;
using System.Reactive;
using System.Reactive.Linq;
using System.Reactive.Threading.Tasks;
using Autofac;
using AutoMapper;
using Microsoft.IO;
using Miningcore.Blockchain.Bitcoin;
using Miningcore.Configuration;
using Miningcore.Extensions;
using Miningcore.JsonRpc;
using Miningcore.Messaging;
using Miningcore.Mining;
using Miningcore.Nicehash;
using Miningcore.Notifications.Messages;
using Miningcore.Persistence;
using Miningcore.Persistence.Repositories;
using Miningcore.Stratum;
using Miningcore.Time;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NLog;
using Npgsql.Replication.PgOutput.Messages;
using static Miningcore.Util.ActionUtils;

namespace Miningcore.Blockchain.Raven;

[CoinFamily(CoinFamily.Raven)]
public class RavenPool : PoolBase
{
    public RavenPool(IComponentContext ctx,
        JsonSerializerSettings serializerSettings,
        IConnectionFactory cf,
        IStatsRepository statsRepo,
        IMapper mapper,
        IMasterClock clock,
        IMessageBus messageBus,
        RecyclableMemoryStreamManager rmsm,
        NicehashService nicehashService) :
        base(ctx, serializerSettings, cf, statsRepo, mapper, clock, messageBus, rmsm, nicehashService)
    {
    }

    protected RavenJobParams currentJobParams;
    private long currentJobId;
    protected RavenJobManager manager;
    private RavenTemplate coin;

    protected virtual async Task OnSubscribeAsync(StratumConnection connection, Timestamped<JsonRpcRequest> tsRequest)
    {
        var request = tsRequest.Value;

        if(request.Id == null)
            throw new StratumException(StratumError.MinusOne, "missing request id");

        var context = connection.ContextAs<RavenWorkerContext>();
        var requestParams = request.ParamsAs<string[]>();

        var data = new object[]
        {
            new object[]
            {
                new object[] { RavenStratumMethods.SetDifficulty, connection.ConnectionId },
                new object[] { RavenStratumMethods.MiningNotify, connection.ConnectionId }
            }
        }
        .Concat(manager.GetSubscriberData(connection))
        .ToArray();

        await connection.RespondAsync(data, request.Id);

        // setup worker context
        context.IsSubscribed = true;
        context.UserAgent = requestParams.FirstOrDefault()?.Trim();

        // Nicehash support
        var nicehashDiff = await GetNicehashStaticMinDiff(context, coin.Name, coin.GetAlgorithmName());

        if(nicehashDiff.HasValue)
        {
            logger.Info(() => $"[{connection.ConnectionId}] Nicehash detected. Using API supplied difficulty of {nicehashDiff.Value}");

            context.VarDiff = null; // disable vardiff
            context.SetDifficulty(nicehashDiff.Value);
        }

        var minerJobParams = await CreateWorkerJob(connection, (int) currentJobParams.Height, currentJobParams.CleanJobs);
        // send intial update
        await connection.NotifyAsync(RavenStratumMethods.SetDifficulty, new object[] { RavenUtils.EncodeTarget(context.Difficulty) });
        await connection.NotifyAsync(RavenStratumMethods.MiningNotify, minerJobParams);
    }

    protected virtual async Task OnAuthorizeAsync(StratumConnection connection, Timestamped<JsonRpcRequest> tsRequest, CancellationToken ct)
    {
        var request = tsRequest.Value;

        if(request.Id == null)
            throw new StratumException(StratumError.MinusOne, "missing request id");

        var context = connection.ContextAs<RavenWorkerContext>();
        var requestParams = request.ParamsAs<string[]>();
        var workerValue = requestParams?.Length > 0 ? requestParams[0] : null;
        var password = requestParams?.Length > 1 ? requestParams[1] : null;
        var passParts = password?.Split(PasswordControlVarsSeparator);

        // extract worker/miner
        var split = workerValue?.Split('.');
        var minerName = split?.FirstOrDefault()?.Trim();
        var workerName = split?.Skip(1).FirstOrDefault()?.Trim() ?? string.Empty;

        // assumes that minerName is an address
        context.IsAuthorized = await manager.ValidateAddressAsync(minerName, ct);
        context.Miner = minerName;
        context.Worker = workerName;

        if(context.IsAuthorized)
        {
            // respond
            await connection.RespondAsync(context.IsAuthorized, request.Id);

            // log association
            logger.Info(() => $"[{connection.ConnectionId}] Authorized worker {workerValue}");

            // extract control vars from password
            var staticDiff = GetStaticDiffFromPassparts(passParts);

            // Static diff
            if(staticDiff.HasValue &&
               (context.VarDiff != null && staticDiff.Value >= context.VarDiff.Config.MinDiff ||
                   context.VarDiff == null && staticDiff.Value > context.Difficulty))
            {
                context.VarDiff = null; // disable vardiff
                context.SetDifficulty(staticDiff.Value);

                logger.Info(() => $"[{connection.ConnectionId}] Setting static difficulty of {staticDiff.Value}");

                await connection.NotifyAsync(RavenStratumMethods.SetDifficulty, new object[] { RavenUtils.EncodeTarget(context.Difficulty) });
            }
        }

        else
        {
            await connection.RespondErrorAsync(StratumError.UnauthorizedWorker, "Authorization failed", request.Id, context.IsAuthorized);

            if(clusterConfig?.Banning?.BanOnLoginFailure is null or true)
            {
                // issue short-time ban if unauthorized to prevent DDos on daemon (validateaddress RPC)
                logger.Info(() => $"[{connection.ConnectionId}] Banning unauthorized worker {minerName} for {loginFailureBanTimeout.TotalSeconds} sec");

                banManager.Ban(connection.RemoteEndpoint.Address, loginFailureBanTimeout);

                Disconnect(connection);
            }
        }
    }

    private async Task<object> CreateWorkerJob(StratumConnection connection, int block, bool update)
    {
        var context = connection.ContextAs<RavenWorkerContext>();
        var job = new RavenWorkerJob(NextJobId(), context.ExtraNonce1);
        var kawpowHasher = await coin.KawpowHasher.GetCacheAsync(logger, block); // TODO: dont create hasher for every job

        manager.PrepareWorkerJob(job, out var headerHash);


        var result = new object[]
        {
             job.Id,
             headerHash,
             kawpowHasher.SeedHash.ToHexString(),
             RavenUtils.EncodeTarget(context.Difficulty),
             update,
             job.Height,
             job.Bits
        };

        // update context
        lock(context)
        {
            context.AddJob(job);
        }

        return result;
    }

    private string NextJobId()
    {
        return Interlocked.Increment(ref currentJobId).ToString(CultureInfo.InvariantCulture);
    }

    protected virtual async Task OnSubmitAsync(StratumConnection connection, Timestamped<JsonRpcRequest> tsRequest, CancellationToken ct)
    {
        var request = tsRequest.Value;
        var context = connection.ContextAs<RavenWorkerContext>();

        try
        {
            if(request.Id == null)
                throw new StratumException(StratumError.MinusOne, "missing request id");

            // check age of submission (aged submissions are usually caused by high server load)
            var requestAge = clock.Now - tsRequest.Timestamp.UtcDateTime;

            if(requestAge > maxShareAge)
            {
                logger.Warn(() => $"[{connection.ConnectionId}] Dropping stale share submission request (server overloaded?)");
                return;
            }

            // check worker state
            context.LastActivity = clock.Now;

            // validate worker
            if(!context.IsAuthorized)
                throw new StratumException(StratumError.UnauthorizedWorker, "unauthorized worker");
            else if(!context.IsSubscribed)
                throw new StratumException(StratumError.NotSubscribed, "not subscribed");

            var requestParams = request.ParamsAs<string[]>();

            /* if(requestParams is not object[] submitParams)
                throw new StratumException(StratumError.Other, "invalid params"); */

            // submit
            var share = await manager.SubmitShareAsync(connection, requestParams, ct);
            await connection.RespondAsync(true, request.Id);

            // publish
            messageBus.SendMessage(share);

            // telemetry
            PublishTelemetry(TelemetryCategory.Share, clock.Now - tsRequest.Timestamp.UtcDateTime, true);

            logger.Info(() => $"[{connection.ConnectionId}] Share accepted: D={Math.Round(share.Difficulty * coin.ShareMultiplier, 3)}");

            // update pool stats
            if(share.IsBlockCandidate)
                poolStats.LastPoolBlockTime = clock.Now;

            // update client stats
            context.Stats.ValidShares++;

            await UpdateVarDiffAsync(connection, false, ct);
        }

        catch(StratumException ex)
        {
            // telemetry
            PublishTelemetry(TelemetryCategory.Share, clock.Now - tsRequest.Timestamp.UtcDateTime, false);

            // update client stats
            context.Stats.InvalidShares++;
            logger.Info(() => $"[{connection.ConnectionId}] Share rejected: {ex.Message} [{context.UserAgent}]");

            // banning
            ConsiderBan(connection, context, poolConfig.Banning);

            throw;
        }
    }

    protected virtual async Task OnNewJobAsync(object job)
    {
        logger.Info(() => $"Broadcasting jobs");

        currentJobParams = job as RavenJobParams;

        await Guard(() => ForEachMinerAsync(async (connection, ct) =>
        {
            var context = connection.ContextAs<RavenWorkerContext>();

            var minerJobParams = await CreateWorkerJob(connection, (int) currentJobParams.Height, currentJobParams.CleanJobs);

            if(context.ApplyPendingDifficulty())
                await connection.NotifyAsync(RavenStratumMethods.SetDifficulty, new object[] { RavenUtils.EncodeTarget(context.Difficulty) });

            // send job
            await connection.NotifyAsync(RavenStratumMethods.MiningNotify, minerJobParams);
        }));
    }

    public override double HashrateFromShares(double shares, double interval)
    {
        var multiplier = BitcoinConstants.Pow2x32;
        var result = shares * multiplier / interval;

        if(coin.HashrateMultiplier.HasValue)
            result *= coin.HashrateMultiplier.Value;

        return result;
    }

    public override double ShareMultiplier => coin.ShareMultiplier;

    #region Overrides

    public override void Configure(PoolConfig pc, ClusterConfig cc)
    {
        coin = pc.Template.As<RavenTemplate>();

        base.Configure(pc, cc);
    }

    protected override async Task SetupJobManager(CancellationToken ct)
    {
        manager = ctx.Resolve<RavenJobManager>(
            new TypedParameter(typeof(IExtraNonceProvider), new RavenExtraNonceProvider(poolConfig.Id, clusterConfig.InstanceId)));

        manager.Configure(poolConfig, clusterConfig);

        await manager.StartAsync(ct);

        if(poolConfig.EnableInternalStratum == true)
        {
            disposables.Add(manager.Jobs
                .Select(job => Observable.FromAsync(() =>
                    Guard(() => OnNewJobAsync(job),
                        ex => logger.Debug(() => $"{nameof(OnNewJobAsync)}: {ex.Message}"))))
                .Concat()
                .Subscribe(_ => { }, ex =>
                {
                    logger.Debug(ex, nameof(OnNewJobAsync));
                }));

            // start with initial blocktemplate
            await manager.Jobs.Take(1).ToTask(ct);
        }

        else
        {
            // keep updating NetworkStats
            disposables.Add(manager.Jobs.Subscribe());
        }
    }

    protected override async Task InitStatsAsync(CancellationToken ct)
    {
        await base.InitStatsAsync(ct);

        blockchainStats = manager.BlockchainStats;
    }

    protected override WorkerContextBase CreateWorkerContext()
    {
        return new RavenWorkerContext();
    }

    protected override async Task OnRequestAsync(StratumConnection connection,
        Timestamped<JsonRpcRequest> tsRequest, CancellationToken ct)
    {
        var request = tsRequest.Value;

        try
        {
            switch(request.Method)
            {
                case RavenStratumMethods.Subscribe:
                    await OnSubscribeAsync(connection, tsRequest);
                    break;

                case RavenStratumMethods.Authorize:
                    await OnAuthorizeAsync(connection, tsRequest, ct);
                    break;

                case RavenStratumMethods.SubmitShare:
                    await OnSubmitAsync(connection, tsRequest, ct);
                    break;

                case BitcoinStratumMethods.GetTransactions:
                    // ignored
                    break;

                case BitcoinStratumMethods.MiningMultiVersion:
                    // ignored
                    break;

                default:
                    logger.Debug(() => $"[{connection.ConnectionId}] Unsupported RPC request: {JsonConvert.SerializeObject(request, serializerSettings)}");

                    await connection.RespondErrorAsync(StratumError.Other, $"Unsupported request {request.Method}", request.Id);
                    break;
            }
        }

        catch(StratumException ex)
        {
            await connection.RespondErrorAsync(ex.Code, ex.Message, request.Id, false);
        }
    }

    protected override async Task OnVarDiffUpdateAsync(StratumConnection connection, double newDiff, CancellationToken ct)
    {
        await base.OnVarDiffUpdateAsync(connection, newDiff, ct);

        if(connection.Context.ApplyPendingDifficulty())
        {
            var context = connection.ContextAs<RavenWorkerContext>();
            var minerJobParams = await CreateWorkerJob(connection, (int) currentJobParams.Height, currentJobParams.CleanJobs);

            await connection.NotifyAsync(RavenStratumMethods.SetDifficulty, new object[] { RavenUtils.EncodeTarget(connection.Context.Difficulty) });
            await connection.NotifyAsync(RavenStratumMethods.MiningNotify, minerJobParams);
        }
    }

    #endregion // Overrides
}