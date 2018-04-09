using NBitcoin;
using NBitcoin.Crypto;
using System;
using System.Linq;


namespace NTumbleBit.PuzzlePromise
{
    public class PromiseParameters
    {
        public int FakeTransactionCountPerLevel
        {
            get;
            set;
        }
        public int RealTransactionCountPerLevel
        {
            get;
            set;
        }

        public int PaymentsCount // Q
        {
            get;
            set;
        }

        public uint256 FakeFormat
        {
            get; set;
        }

        public PromiseParameters()
        {
            FakeTransactionCountPerLevel = 42;
            RealTransactionCountPerLevel = 42;
            FakeFormat = new uint256(Enumerable.Range(0, 32).Select(o => o == 0 ? (byte)0 : (byte)1).ToArray());
        }

        public PromiseParameters(RsaPubKey serverKey) : this()
        {
            ServerKey = serverKey ?? throw new ArgumentNullException(nameof(serverKey));
        }

        public int GetTotalTransactionsCountPerLevel()
        {
            return FakeTransactionCountPerLevel + RealTransactionCountPerLevel;
        }

        public int GetTotalTransactionsCount()
        {
            return (FakeTransactionCountPerLevel + RealTransactionCountPerLevel) * PaymentsCount;
        }

        public int GetTotalFakeTransactionsCount()
        {
            return FakeTransactionCountPerLevel * PaymentsCount;
        }

        public int GetTotalRealTransactionsCount()
        {
            return RealTransactionCountPerLevel * PaymentsCount;
        }

        public RsaPubKey ServerKey
        {
            get; set;
        }

        public uint256 CreateFakeHash(uint256 salt)
        {
            return Hashes.Hash256(Utils.Combine(salt.ToBytes(), FakeFormat.ToBytes()));
        }

        public uint256 CreateRealHash(Transaction tx, ScriptCoin _Escrow, Money feeVariation)
        {
            /*
                 TODO: Make sure that this function is consestant with the way we hash the real transactions on the client side.
            */
            var escrow = EscrowScriptPubKeyParameters.GetFromCoin(_Escrow);
            var coin = _Escrow.Clone();
            coin.OverrideScriptCode(escrow.GetInitiatorScriptCode());
            var Transaction = tx.Clone();
            // TODO: Make sure you only decrement from Bob's output (the 'i'), but not from the Tumbler's ('Q' - 'i') output
            Transaction.Outputs[0].Value -= feeVariation;
            return Transaction.GetSignatureHash(coin, SigHash.All);
        }
    }
}
