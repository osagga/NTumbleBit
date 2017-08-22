using NBitcoin;
using System;
using System.Collections.Generic;
using System.Text;

namespace NTumbleBit
{
	public class SignatureWrapper : IBitcoinSerializable
	{
		TransactionSignature _Signature;
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

		public SignatureWrapper(TransactionSignature signature)
		{
			_Signature = signature;
		}
		public void ReadWrite(BitcoinStream stream)
		{
			var bytes = _Signature?.ToBytes();
			stream.ReadWriteAsVarString(ref bytes);
			if(!stream.Serializing)
			{
				_Signature = new TransactionSignature(bytes);
			}
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
          * Not really sure if this is needed. 
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
