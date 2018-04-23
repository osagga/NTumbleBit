using NBitcoin;
using System;
using System.Collections.Generic;
using System.Text;

namespace NTumbleBit
{
	public class SignatureWrapper : IBitcoinSerializable
	{
		TransactionSignature _Signature;
		Script _cashoutDestination;
        uint _txFee;

		public SignatureWrapper()
		{

		}

		public TransactionSignature Signature
		{
			get
			{
				return _Signature;
			}
		}

		public Script CashoutDestination
		{
			get
			{
				return _cashoutDestination;
			}
		}


		public SignatureWrapper(TransactionSignature signature)
		{
			_Signature = signature;
		}

		public SignatureWrapper(TransactionSignature signature, Script cashoutDestination)
		{
			_Signature = signature;
			_cashoutDestination = cashoutDestination;
		}

        public SignatureWrapper(TransactionSignature signature, uint fee)
        {
            _Signature = signature;
            _txFee = fee;
        }

        public void ReadWrite(BitcoinStream stream)
		{
			var bytes = _Signature?.ToBytes();
			stream.ReadWriteAsVarString(ref bytes);
			if(!stream.Serializing)
			{
				_Signature = new TransactionSignature(bytes);
			}
			stream.ReadWrite(ref _cashoutDestination);
            stream.ReadWrite(ref _txFee);
        }
	}
	public class ArrayWrapper<T> : IBitcoinSerializable where T : IBitcoinSerializable, new()
	{
		public ArrayWrapper()
		{

		}

		public ArrayWrapper(T[] elements)
		{
			_Elements = elements;
		}

		T[] _Elements;
		public T[] Elements
		{
			get
			{
				return _Elements;
			}
			set
			{
				_Elements = value;
			}
		}
		public void ReadWrite(BitcoinStream stream)
		{
			stream.ReadWrite(ref _Elements);
		}
	}
    public class TwoDArrayWrapper<T> : IBitcoinSerializable where T : IBitcoinSerializable, new()
    {
        /*
		  * TODO:
          * Not really sure if this is the best way to solve this problem.
          * used here: TumblerClient.cs #L179
        */
        public TwoDArrayWrapper()
        {

        }

        public TwoDArrayWrapper(T[][] elements)
        {
            _Arrays = elements;
        }

        T[][] _Arrays;
        public T[][] Elements
        {
            get
            {
                return _Arrays;
            }
            set
            {
                _Arrays = value;
            }
        }
        public void ReadWrite(BitcoinStream stream)
        {
            stream.ReadWriteC(ref _Arrays);
        }
    }

}
