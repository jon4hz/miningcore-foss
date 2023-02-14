using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using Miningcore.Blockchain.Bitcoin;
using Miningcore.Blockchain.Bitcoin.Configuration;
using Miningcore.Blockchain.Bitcoin.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Crypto;
using Miningcore.Crypto.Hashing.Kawpow;
using Miningcore.Extensions;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using NBitcoin;
using NBitcoin.DataEncoders;
using Newtonsoft.Json.Linq;
using NLog;
using NLog.Fluent;
using Npgsql.Util;
using Org.BouncyCastle.Math;
using Contract = Miningcore.Contracts.Contract;
using Transaction = NBitcoin.Transaction;

namespace Miningcore.Blockchain.Raven;

public class RavenJobParams
{
    public ulong Height { get; set; }
    public bool CleanJobs { get; set; }
}

public class RavenJob
{
    protected IHashAlgorithm blockHasher;
    protected IMasterClock clock;
    protected IHashAlgorithm coinbaseHasher;
    protected double shareMultiplier;
    protected int extraNoncePlaceHolderLength;
    protected IHashAlgorithm headerHasher;
    protected bool isPoS;
    protected string txComment;
    protected PayeeBlockTemplateExtra payeeParameters;

    protected Network network;
    protected IDestination poolAddressDestination;
    protected RavenTemplate coin;
    private RavenTemplate.BitcoinNetworkParams networkParams;
    protected readonly ConcurrentDictionary<string, bool> submissions = new(StringComparer.OrdinalIgnoreCase);
    protected uint256 blockTargetValue;
    protected byte[] coinbaseFinal;
    protected string coinbaseFinalHex;
    protected byte[] coinbaseInitial;
    protected string coinbaseInitialHex;
    protected string[] merkleBranchesHex;
    protected MerkleTree mt;

    ///////////////////////////////////////////
    // GetJobParams related properties

    protected RavenJobParams jobParams;
    protected string previousBlockHashReversedHex;
    protected Money rewardToPool;
    protected Transaction txOut;

    // serialization constants
    protected byte[] scriptSigFinalBytes;

    protected static byte[] sha256Empty = new byte[32];
    protected uint txVersion = 1u; // transaction version (currently 1) - see https://en.bitcoin.it/wiki/Transaction

    protected static uint txInputCount = 1u;
    protected static uint txInPrevOutIndex = (uint) (Math.Pow(2, 32) - 1);
    protected static uint txInSequence;
    protected static uint txLockTime;

    protected virtual void BuildMerkleBranches()
    {
        var transactionHashes = BlockTemplate.Transactions
            .Select(tx => (tx.TxId ?? tx.Hash)
            //.Select(tx => (tx.TxId)
                .HexToByteArray()
                .ReverseInPlace())
            .ToArray();

        mt = new MerkleTree(transactionHashes);

        merkleBranchesHex = mt.Steps
            .Select(x => x.ToHexString())
            .ToArray();
    }

    protected virtual void BuildCoinbase()
    {
        // generate script parts
        var sigScriptInitial = GenerateScriptSigInitial();
        var sigScriptInitialBytes = sigScriptInitial.ToBytes();

        var sigScriptLength = (uint) (
            sigScriptInitial.Length +
            extraNoncePlaceHolderLength +
            scriptSigFinalBytes.Length);

        // output transaction
        txOut = CreateOutputTransaction();

        // build coinbase initial
        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // version
            bs.ReadWrite(ref txVersion);

            // serialize (simulated) input transaction
            bs.ReadWriteAsVarInt(ref txInputCount);
            bs.ReadWrite(ref sha256Empty);
            bs.ReadWrite(ref txInPrevOutIndex);

            // signature script initial part
            bs.ReadWriteAsVarInt(ref sigScriptLength);
            bs.ReadWrite(ref sigScriptInitialBytes);

            // done
            coinbaseInitial = stream.ToArray();
            coinbaseInitialHex = coinbaseInitial.ToHexString();
        }

        Console.WriteLine("coinbaseInitialHex: " + coinbaseInitialHex);

        // build coinbase final
        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // signature script final part
            bs.ReadWrite(ref scriptSigFinalBytes);

            // tx in sequence
            bs.ReadWrite(ref txInSequence);

            // serialize output transaction
            var txOutBytes = SerializeOutputTransaction(txOut);
            bs.ReadWrite(ref txOutBytes);

            // misc
            bs.ReadWrite(ref txLockTime);

            // Extension point
            AppendCoinbaseFinal(bs);

            // done
            coinbaseFinal = stream.ToArray();
            coinbaseFinalHex = coinbaseFinal.ToHexString();
        }

        Console.WriteLine("coinbaseFinalHex: " + coinbaseFinalHex);
    }

    protected virtual void AppendCoinbaseFinal(BitcoinStream bs)
    {
        if(!string.IsNullOrEmpty(txComment))
        {
            var data = Encoding.ASCII.GetBytes(txComment);
            bs.ReadWriteAsVarString(ref data);
        }
        /* 
                if(coin.HasMasterNodes && !string.IsNullOrEmpty(masterNodeParameters.CoinbasePayload))
                {
                    var data = masterNodeParameters.CoinbasePayload.HexToByteArray();
                    bs.ReadWriteAsVarString(ref data);
                } */
    }

    protected virtual byte[] SerializeOutputTransaction(Transaction tx)
    {
        var withDefaultWitnessCommitment = !string.IsNullOrEmpty(BlockTemplate.DefaultWitnessCommitment);

        var outputCount = (uint) tx.Outputs.Count;
        if(withDefaultWitnessCommitment)
            outputCount++;

        Console.WriteLine("outputCount: " + outputCount);

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // write output count
            bs.ReadWriteAsVarInt(ref outputCount);

            long amount;
            byte[] raw;
            uint rawLength;

            // serialize outputs
            foreach(var output in tx.Outputs)
            {
                amount = output.Value.Satoshi;
                var outScript = output.ScriptPubKey;
                raw = outScript.ToBytes(true);
                rawLength = (uint) raw.Length;

                bs.ReadWrite(ref amount);
                bs.ReadWriteAsVarInt(ref rawLength);
                bs.ReadWrite(ref raw);
            }

            // serialize witness (segwit)
            if(withDefaultWitnessCommitment)
            {
                amount = 0;
                raw = BlockTemplate.DefaultWitnessCommitment.HexToByteArray();
                rawLength = (uint) raw.Length;

                bs.ReadWrite(ref amount);
                bs.ReadWriteAsVarInt(ref rawLength);
                bs.ReadWrite(ref raw);
            }

            return stream.ToArray();
        }
    }

    protected virtual Script GenerateScriptSigInitial()
    {
        var now = ((DateTimeOffset) clock.Now).ToUnixTimeSeconds();

        // script ops
        var ops = new List<Op>();

        // push block height
        ops.Add(Op.GetPushOp(BlockTemplate.Height));

        // optionally push aux-flags
        if(!coin.CoinbaseIgnoreAuxFlags && !string.IsNullOrEmpty(BlockTemplate.CoinbaseAux?.Flags))
            ops.Add(Op.GetPushOp(BlockTemplate.CoinbaseAux.Flags.HexToByteArray()));

        // push timestamp
        ops.Add(Op.GetPushOp(now));

        // push placeholder
        ops.Add(Op.GetPushOp(0));

        return new Script(ops);
    }

    protected virtual Transaction CreateOutputTransaction()
    {
        rewardToPool = new Money(BlockTemplate.CoinbaseValue, MoneyUnit.Satoshi);
        var tx = Transaction.Create(network);

        /* if(coin.HasPayee)
            rewardToPool = CreatePayeeOutput(tx, rewardToPool);

        if(coin.HasMasterNodes)
            rewardToPool = CreateMasternodeOutputs(tx, rewardToPool);

        if(coin.HasFounderFee)
            rewardToPool = CreateFounderOutputs(tx, rewardToPool);

        if(coin.HasMinerFund)
            rewardToPool = CreateMinerFundOutputs(tx, rewardToPool); */

        // Remaining amount goes to pool
        tx.Outputs.Add(rewardToPool, poolAddressDestination);

        return tx;
    }

    /* protected virtual Money CreatePayeeOutput(Transaction tx, Money reward)
    {
        if(payeeParameters?.PayeeAmount != null && payeeParameters.PayeeAmount.Value > 0)
        {
            var payeeReward = new Money(payeeParameters.PayeeAmount.Value, MoneyUnit.Satoshi);
            reward -= payeeReward;

            tx.Outputs.Add(payeeReward, BitcoinUtils.AddressToDestination(payeeParameters.Payee, network));
        }

        return reward;
    } */

    protected bool RegisterSubmit(string extraNonce1, string nonce)
    {
        var key = new StringBuilder()
            .Append(extraNonce1)
            .Append(nonce) // lowercase as we don't want to accept case-sensitive values as valid.
            .ToString();

        return submissions.TryAdd(key, true);
    }

    protected byte[] SerializeHeader(Span<byte> coinbaseHash)
    {
        // build merkle-root
        var merkleRoot = mt.WithFirst(coinbaseHash.ToArray());

        // Build version
        var version = BlockTemplate.Version;

#pragma warning disable 618
        var blockHeader = new BlockHeader
#pragma warning restore 618
        {
            Version = unchecked((int) version),
            Bits = new Target(Encoders.Hex.DecodeData(BlockTemplate.Bits)),
            HashPrevBlock = uint256.Parse(BlockTemplate.PreviousBlockhash),
            HashMerkleRoot = new uint256(merkleRoot),
            BlockTime = DateTimeOffset.FromUnixTimeSeconds(BlockTemplate.CurTime),
            Nonce = BlockTemplate.Height
        };

        return blockHeader.ToBytes();

        /*  var height = BlockTemplate.Height;
         var bits = Encoders.Hex.DecodeData(BlockTemplate.Bits);
         var nTime = BlockTemplate.CurTime;
         var hashMerkleRoot = new uint256(merkleRoot);
         var hashPrevBlock = uint256.Parse(BlockTemplate.PreviousBlockhash);

         using(var stream = new MemoryStream())
         {
             var bs = new BitcoinStream(stream, true);

             bs.ReadWrite(ref version);
             bs.ReadWrite(ref hashPrevBlock);
             bs.ReadWrite(ref hashMerkleRoot);
             bs.ReadWrite(ref nTime);
             bs.ReadWrite(ref bits);
             bs.ReadWrite(ref height);

             return stream.ToArray();
         } */
    }

    protected virtual (Share Share, string BlockHex) ProcessShareInternal(ILogger logger, Cache kawPowHasher,
        StratumConnection worker, ulong nonce, string inputHeaderHash, string mixHash)
    {
        var context = worker.ContextAs<RavenWorkerContext>();
        var extraNonce1 = context.ExtraNonce1;

        // build coinbase
        var coinbase = SerializeCoinbase(extraNonce1);
        Span<byte> coinbaseHash = stackalloc byte[32];
        coinbaseHasher.Digest(coinbase, coinbaseHash);


        //logger.Info(() => $"Coinbase from share: {coinbase.ToHexString()}");
        /* var coinbaseHashHex = coinbaseHash.ToHexString();
        logger.Info(() => $"Coinbase hash from share: {coinbaseHashHex}");
        var merkleRoot = mt.WithFirst(coinbaseHash.ToArray());
        logger.Info(() => $"Merkle root from share: {merkleRoot.ToHexString()}"); */

        // hash block-header
        var headerBytes = SerializeHeader(coinbaseHash);
        Span<byte> headerHash = stackalloc byte[32];
        headerHasher.Digest(headerBytes, headerHash);
        headerHash.Reverse();

        var headerValue = new uint256(headerHash);
        var headerHashHex = headerHash.ToHexString();

        if(headerHashHex != inputHeaderHash)
        {
            logger.Info(() => $"Input: {inputHeaderHash}, Actual: {headerHashHex}");
            throw new StratumException(StratumError.MinusOne, "bad header-hash");
        }

        if(!kawPowHasher.Compute(logger, (int) BlockTemplate.Height, headerHash.ToArray(), nonce, out var mixHashOut, out var resultBytes))
            throw new StratumException(StratumError.MinusOne, "bad hash");

        resultBytes.ReverseInPlace();
        mixHashOut.ReverseInPlace();

        var resultValue = new uint256(resultBytes);
        var resultValueBig = resultBytes.AsSpan().ToBigInteger();
        // calc share-diff
        var shareDiff = (double) new BigRational(RavenConstants.Diff1, resultValueBig) * shareMultiplier;
        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff / stratumDifficulty;

        logger.Info(() => $"Found share with ration {ratio} and diff {shareDiff}");

        // check if the share meets the much harder block difficulty (block candidate)
        var isBlockCandidate = resultValue <= blockTargetValue;

        // test if share meets at least workers current difficulty
        if(!isBlockCandidate && ratio < 0.99)
        {
            // check if share matched the previous difficulty from before a vardiff retarget
            if(context.VarDiff?.LastUpdate != null && context.PreviousDifficulty.HasValue)
            {
                ratio = shareDiff / context.PreviousDifficulty.Value;

                if(ratio < 0.99)
                    throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");

                // use previous difficulty
                stratumDifficulty = context.PreviousDifficulty.Value;
            }

            else
                throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");
        }


        //tmp
        /* var stratumDifficulty = 0.01;
        var isBlockCandidate = true; */

        var result = new Share
        {
            BlockHeight = BlockTemplate.Height,
            NetworkDifficulty = Difficulty,
            Difficulty = stratumDifficulty / shareMultiplier,
        };

        if(isBlockCandidate)
        {
            result.IsBlockCandidate = true;
            result.BlockHash = resultBytes.ReverseInPlace().ToHexString();

            var blockBytes = SerializeBlock(headerBytes, coinbase, nonce, mixHashOut);
            var blockHex = blockBytes.ToHexString();

            return (result, blockHex);
        }

        return (result, null);
    }

    protected virtual byte[] SerializeCoinbase(string extraNonce1)
    {
        var extraNonce1Bytes = extraNonce1.HexToByteArray();

        using(var stream = new MemoryStream())
        {
            stream.Write(coinbaseInitial);
            stream.Write(extraNonce1Bytes);
            stream.Write(coinbaseFinal);

            return stream.ToArray();
        }
    }

    protected virtual byte[] SerializeBlock(byte[] header, byte[] coinbase, ulong nonce, byte[] mixHash)
    {
        var rawTransactionBuffer = BuildRawTransactionBuffer();
        var transactionCount = (uint) BlockTemplate.Transactions.Length + 1; // +1 for prepended coinbase tx

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            bs.ReadWrite(ref header);
            bs.ReadWrite(ref nonce);
            bs.ReadWrite(ref mixHash);
            bs.ReadWriteAsVarInt(ref transactionCount);

            bs.ReadWrite(ref coinbase);
            bs.ReadWrite(ref rawTransactionBuffer);

            return stream.ToArray();
        }
    }

    protected virtual byte[] BuildRawTransactionBuffer()
    {
        using(var stream = new MemoryStream())
        {
            foreach(var tx in BlockTemplate.Transactions)
            {
                var txRaw = tx.Data.HexToByteArray();
                stream.Write(txRaw);
            }

            return stream.ToArray();
        }
    }

    /*     #region Masternodes

        protected MasterNodeBlockTemplateExtra masterNodeParameters;

        protected virtual Money CreateMasternodeOutputs(Transaction tx, Money reward)
        {
            if(masterNodeParameters.Masternode != null)
            {
                Masternode[] masternodes;

                // Dash v13 Multi-Master-Nodes
                if(masterNodeParameters.Masternode.Type == JTokenType.Array)
                    masternodes = masterNodeParameters.Masternode.ToObject<Masternode[]>();
                else
                    masternodes = new[] { masterNodeParameters.Masternode.ToObject<Masternode>() };

                if(masternodes != null)
                {
                    foreach(var masterNode in masternodes)
                    {
                        if(!string.IsNullOrEmpty(masterNode.Payee))
                        {
                            var payeeDestination = BitcoinUtils.AddressToDestination(masterNode.Payee, network);
                            var payeeReward = masterNode.Amount;

                            tx.Outputs.Add(payeeReward, payeeDestination);
                            reward -= payeeReward;
                        }
                    }
                }
            }

            if(masterNodeParameters.SuperBlocks is { Length: > 0 })
            {
                foreach(var superBlock in masterNodeParameters.SuperBlocks)
                {
                    var payeeAddress = BitcoinUtils.AddressToDestination(superBlock.Payee, network);
                    var payeeReward = superBlock.Amount;

                    tx.Outputs.Add(payeeReward, payeeAddress);
                    reward -= payeeReward;
                }
            }

            if(!coin.HasPayee && !string.IsNullOrEmpty(masterNodeParameters.Payee))
            {
                var payeeAddress = BitcoinUtils.AddressToDestination(masterNodeParameters.Payee, network);
                var payeeReward = masterNodeParameters.PayeeAmount;

                tx.Outputs.Add(payeeReward, payeeAddress);
                reward -= payeeReward;
            }

            return reward;
        }

        #endregion // Masternodes */

    /* #region Founder

    protected FounderBlockTemplateExtra founderParameters;

    protected virtual Money CreateFounderOutputs(Transaction tx, Money reward)
    {
        if(founderParameters.Founder != null)
        {
            Founder[] founders;
            if(founderParameters.Founder.Type == JTokenType.Array)
                founders = founderParameters.Founder.ToObject<Founder[]>();
            else
                founders = new[] { founderParameters.Founder.ToObject<Founder>() };

            if(founders != null)
            {
                foreach(var Founder in founders)
                {
                    if(!string.IsNullOrEmpty(Founder.Payee))
                    {
                        var payeeAddress = BitcoinUtils.AddressToDestination(Founder.Payee, network);
                        var payeeReward = Founder.Amount;

                        tx.Outputs.Add(payeeReward, payeeAddress);
                        reward -= payeeReward;
                    }
                }
            }
        }

        return reward;
    }

    #endregion // Founder

    #region Minerfund

    protected MinerFundTemplateExtra minerFundParameters;

    protected virtual Money CreateMinerFundOutputs(Transaction tx, Money reward)
    {
        var payeeReward = minerFundParameters.MinimumValue;

        if(!string.IsNullOrEmpty(minerFundParameters.Addresses?.FirstOrDefault()))
        {
            var payeeAddress = BitcoinUtils.AddressToDestination(minerFundParameters.Addresses[0], network);
            tx.Outputs.Add(payeeReward, payeeAddress);
        }

        reward -= payeeReward;

        return reward;
    }

    #endregion // Founder */

    #region API-Surface

    public BlockTemplate BlockTemplate { get; protected set; }
    public double Difficulty { get; protected set; }

    public string JobId { get; protected set; }

    public void Init(BlockTemplate blockTemplate, string jobId,
        PoolConfig pc, BitcoinPoolConfigExtra extraPoolConfig,
        ClusterConfig cc, IMasterClock clock,
        IDestination poolAddressDestination, Network network,
        bool isPoS, double shareMultiplier, IHashAlgorithm coinbaseHasher,
        IHashAlgorithm headerHasher, IHashAlgorithm blockHasher)
    {
        Contract.RequiresNonNull(blockTemplate);
        Contract.RequiresNonNull(pc);
        Contract.RequiresNonNull(cc);
        Contract.RequiresNonNull(clock);
        Contract.RequiresNonNull(poolAddressDestination);
        Contract.RequiresNonNull(coinbaseHasher);
        Contract.RequiresNonNull(headerHasher);
        Contract.RequiresNonNull(blockHasher);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(jobId));

        coin = pc.Template.As<RavenTemplate>();
        networkParams = coin.GetNetwork(network.ChainName);
        txVersion = coin.CoinbaseTxVersion;
        this.network = network;
        this.clock = clock;
        this.poolAddressDestination = poolAddressDestination;
        BlockTemplate = blockTemplate;
        JobId = jobId;

        var coinbaseString = !string.IsNullOrEmpty(cc.PaymentProcessing?.CoinbaseString) ?
            cc.PaymentProcessing?.CoinbaseString.Trim() : "Miningcore";

        scriptSigFinalBytes = new Script(Op.GetPushOp(Encoding.UTF8.GetBytes(coinbaseString))).ToBytes();

        Difficulty = new Target(System.Numerics.BigInteger.Parse(BlockTemplate.Target, NumberStyles.HexNumber)).Difficulty;

        extraNoncePlaceHolderLength = RavenConstants.ExtranoncePlaceHolderLength;
        this.isPoS = isPoS;
        this.shareMultiplier = shareMultiplier;

        txComment = !string.IsNullOrEmpty(extraPoolConfig?.CoinbaseTxComment) ?
            extraPoolConfig.CoinbaseTxComment : coin.CoinbaseTxComment;

        this.coinbaseHasher = coinbaseHasher;
        this.headerHasher = headerHasher;
        this.blockHasher = blockHasher;

        if(!string.IsNullOrEmpty(BlockTemplate.Target))
            blockTargetValue = new uint256(BlockTemplate.Target);
        else
        {
            var tmp = new Target(BlockTemplate.Bits.HexToByteArray());
            blockTargetValue = tmp.ToUInt256();
        }

        previousBlockHashReversedHex = BlockTemplate.PreviousBlockhash
            .HexToByteArray()
            .ReverseByteOrder()
            .ToHexString();

        BuildMerkleBranches();
        BuildCoinbase();

        /* jobParams = new object[]
        {
            JobId,
            previousBlockHashReversedHex,
            coinbaseInitialHex,
            coinbaseFinalHex,
            merkleBranchesHex,
            BlockTemplate.Version.ToStringHex8(),
            BlockTemplate.Bits,
            BlockTemplate.CurTime.ToStringHex8(),
            false
        }; */

        jobParams = new RavenJobParams
        {
            Height = BlockTemplate.Height,
            CleanJobs = false
        };

        /* var context = worker.ContextAs<RavenWorkerContext>();
        var extraNonce1 = context.ExtraNonce1; */
    }

    /*  public virtual async Task<object> UpdateJobPerWorkerAsync(ILogger logger, RavenWorkerContext context)
     {
         var kawpowHasher = await coin.KawpowHasher.GetCacheAsync(logger, 1);
         var headerHash = CreateHeaderHash(context, kawpowHasher);

         return new object[]
         {
             this.JobId,
             headerHash,
             kawpowHasher.SeedHash.ToHexString(),
             RavenUtils.EncodeTarget(context.Difficulty),
             false,
             BlockTemplate.Height,
             BlockTemplate.Bits
         };
     } */

    public virtual void PrepareWorkerJob(ILogger logger, RavenWorkerJob workerJob, out string headerHash)
    {
        workerJob.Job = this;
        workerJob.Height = BlockTemplate.Height;
        workerJob.Bits = BlockTemplate.Bits;
        headerHash = CreateHeaderHash(logger, workerJob);
    }

    protected virtual string CreateHeaderHash(ILogger logger, RavenWorkerJob workerJob)
    {
        Console.WriteLine("ExtraNonce1: " + workerJob.ExtraNonce1);

        var headerHasher = coin.HeaderHasherValue;
        var coinbaseHasher = coin.CoinbaseHasherValue;
        var extraNonce1 = workerJob.ExtraNonce1;

        var coinbase = SerializeCoinbase(workerJob.ExtraNonce1);
        Span<byte> coinbaseHash = stackalloc byte[32];
        coinbaseHasher.Digest(coinbase, coinbaseHash);

        var headerBytes = SerializeHeader(coinbaseHash);
        Span<byte> headerHash = stackalloc byte[32];
        headerHasher.Digest(headerBytes, headerHash);
        headerHash.Reverse();

        return headerHash.ToHexString();
    }

    public object GetJobParams(bool isNew)
    {
        jobParams.CleanJobs = isNew;
        return jobParams;
    }

    public virtual (Share Share, string BlockHex) ProcessShare(ILogger logger, Cache kawPowHasher, StratumConnection worker, string nonce, string headerHash, string mixHash)
    {
        Contract.RequiresNonNull(worker);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nonce));

        var context = worker.ContextAs<RavenWorkerContext>();

        // mixHash
        if(mixHash.Length != 64)
            throw new StratumException(StratumError.Other, $"incorrect size of mixHash: {mixHash}");

        // validate nonce
        if(nonce.Length != 16)
            throw new StratumException(StratumError.Other, $"incorrect size of nonce: {nonce}");

        // check if nonce is within range
        if(nonce.IndexOf(context.ExtraNonce1.Substring(0, 4)) != 0)
            throw new StratumException(StratumError.Other, $"nonce out of range: {nonce}");

        var nonceLong = ulong.Parse(nonce, NumberStyles.HexNumber);

        /* logger.Info(() => $"NonceHex:    {nonce}");
        logger.Info(() => $"ExtraNonce1: {context.ExtraNonce1}");
        logger.Info(() => $"Nonce:       {nonceLong}"); */


        // dupe check
        if(!RegisterSubmit(context.ExtraNonce1, nonce))
            throw new StratumException(StratumError.DuplicateShare, "duplicate share");

        return ProcessShareInternal(logger, kawPowHasher, worker, nonceLong, headerHash, mixHash);
    }

    #endregion // API-Surface
}
