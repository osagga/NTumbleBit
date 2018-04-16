using NBitcoin;
using NTumbleBit.BouncyCastle.Crypto.Digests;
using NTumbleBit.BouncyCastle.Crypto.Generators;
using NTumbleBit.BouncyCastle.Crypto.Parameters;
using NTumbleBit.BouncyCastle.Math;
using System;

namespace NTumbleBit.PuzzlePromise
{
    public class XORKey
	{
		public XORKey(PuzzleSolution puzzleSolution, bool padding = true) : this(puzzleSolution._Value)
		{
            Padding = padding;
		}

        public XORKey(RsaPubKey pubKey) : this(Utils.GenerateEncryptableInteger(pubKey._Key))
		{
		}
		public XORKey(byte[] key)
		{
			if(key == null)
				throw new ArgumentNullException(nameof(key));
			if(key.Length != KeySize)
				throw new ArgumentException("Key has invalid length from expected " + KeySize);
			_Value = new BigInteger(1, key);
		}

		private XORKey(BigInteger value)
		{
            _Value = value ?? throw new ArgumentNullException(nameof(value));
		}

		private BigInteger _Value;

        private bool Padding;

        public byte[] XOR(byte[] data)
		{
			byte[] keyBytes = ToBytes();
			Sha512Digest sha512 = new Sha512Digest();
			var generator = new Mgf1BytesGenerator(sha512);
			generator.Init(new MgfParameters(keyBytes));
			var keyHash = new byte[data.Length];
			generator.GenerateBytes(keyHash, 0, keyHash.Length);
			var encrypted = new byte[data.Length];
			for(int i = 0; i < encrypted.Length; i++)
			{
				encrypted[i] = (byte)(data[i] ^ keyHash[i]);
			}
			return encrypted;
		}

        private const int KeySize = 256;
		public byte[] ToBytes()
		{
			byte[] keyBytes = _Value.ToByteArrayUnsigned();
            if (Padding)
			    Utils.Pad(ref keyBytes, KeySize);
			return keyBytes;
		}
	}
}
