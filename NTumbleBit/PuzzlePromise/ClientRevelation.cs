using NBitcoin;
using System;
using System.Linq;

namespace NTumbleBit.PuzzlePromise
{
    public class ClientRevelation : IBitcoinSerializable
    {
        public ClientRevelation()
        {

        }
        public ClientRevelation(int[] indexes, uint256 indexesSalt, uint256[][] salts, uint[] cashoutFees, Money[][] feeVariations, Script bobCashoutDestination)
        {
            FakeIndexes = indexes;
            Salts = salts;
            BobCashoutDestination = bobCashoutDestination;
            FeeVariations = feeVariations;
            CashoutFees = cashoutFees;
            IndexesSalt = indexesSalt;
            // NOTE: salts is a 2D array so we would do "salts.First()" instead of just "salts"
            if (indexes.Length != salts.First().Length)
                throw new ArgumentException("Indexes and Salts array should be of the same length");
        }


        uint256 _IndexesSalt;
        public uint256 IndexesSalt
        {
            get
            {
                return _IndexesSalt;
            }
            set
            {
                _IndexesSalt = value;
            }
        }

        uint[] _CashoutFees;
        public uint[] CashoutFees
        {
            get
            {
                return _CashoutFees;
            }
            set
            {
                _CashoutFees = value;
            }
        }


        int[] _FakeIndexes;
        public int[] FakeIndexes
        {
            get
            {
                return _FakeIndexes;
            }
            set
            {
                _FakeIndexes = value;
            }
        }

        Script _BobCashoutDestination;
        public Script BobCashoutDestination
        {
            get
            {
                return _BobCashoutDestination;
            }
            set
            {
                _BobCashoutDestination = value;
            }
        }


        uint256[][] _Salts;
        public uint256[][] Salts
        {
            get
            {
                return _Salts;
            }
            set
            {
                _Salts = value;
            }
        }

        Money[][] _FeeVariations;
        public Money[][] FeeVariations
        {
            get
            {
                return _FeeVariations;
            }
            set
            {
                _FeeVariations = value;
            }
        }
     
        public void ReadWrite(BitcoinStream stream)
        {
            stream.ReadWrite(ref _IndexesSalt);
            stream.ReadWrite(ref _FakeIndexes);
            stream.ReadWrite(ref _BobCashoutDestination);
            stream.ReadWrite(ref _CashoutFees);
            stream.ReadWriteC(ref _Salts);
            stream.ReadWriteC(ref _FeeVariations);
        }
    }
}
