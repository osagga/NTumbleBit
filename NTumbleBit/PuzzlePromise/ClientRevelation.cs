using NBitcoin;
using System;

namespace NTumbleBit.PuzzlePromise
{
    public class ClientRevelation : IBitcoinSerializable
    {
        public ClientRevelation()
        {

        }
        public ClientRevelation(int[] indexes, uint256 indexesSalt, uint256[][] salts, Money[][] feeVariations)
        {
            FakeIndexes = indexes;
            Salts = salts;
            FeeVariations = feeVariations;
            IndexesSalt = indexesSalt;
            if (indexes.Length != salts.Length)
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
            stream.ReadWriteC(ref _Salts);
            stream.ReadWriteC(ref _FeeVariations);
        }
    }
}
