using NBitcoin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace NTumbleBit.PuzzleSolver
{
	public class OfferInformation : IBitcoinSerializable
	{

		Money _Fee;
		public Money Fee
		{
			get
			{
				return _Fee;
			}
			set
			{
				_Fee = value;
			}
		}


		LockTime _LockTime;
		public LockTime LockTime
		{
			get
			{
				return _LockTime;
			}
			set
			{
				_LockTime = value;
			}
		}


		PubKey _FulfillKey;
		public PubKey FulfillKey
		{
			get
			{
				return _FulfillKey;
			}
			set
			{
				_FulfillKey = value;
			}
		}

        Script _escapeCashout;
        public Script EscapeCashout
        {
            get
            {
                return _escapeCashout;
            }
            set
            {
                _escapeCashout = value;
            }
        }

        public void ReadWrite(BitcoinStream stream)
		{
			stream.ReadWriteC(ref _Fee);
			stream.ReadWrite(ref _LockTime);
			stream.ReadWriteC(ref _FulfillKey);
            stream.ReadWrite(ref _escapeCashout);
        }
    }
}
