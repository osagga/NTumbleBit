using NTumbleBit.BouncyCastle.Math;
using System;

namespace NTumbleBit.PuzzlePromise
{
    public class XORKey
	{
		public XORKey(PuzzleSolution puzzleSolution) : this(puzzleSolution._Value)
		{

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

        public static byte[] XOR(byte[] data1, byte[] data2)
        {
            /*
             * Given how the "key" that XOR generates is not the same as the one
             * used in XOR anymore (check step 5), we can't use the "ToBytes()" function since
             * it assumes that the "key" in the XOR step has a size less than N (or "KeySize").
             * So I can either remove the call to the padding function in "ToBytes()" and use
             * the normal XOR function above, or use this independent function and not change
             * anything. 
             * 
             * If the second choice is better, then this function should move to "Utils" and 
             * XOR is no longer needed in PromiseClientSession\PromiseServerSession since the
             * key can be generated directly using "Utils.GenerateEncryptableInteger()".
            */
            var keyHash = PromiseUtils.SHA512(data1, 0, data1.Length);
            var encrypted = new byte[data2.Length];
            for (int i = 0; i < encrypted.Length; i++)
            {
                encrypted[i] = (byte)(data2[i] ^ keyHash[i % keyHash.Length]);
            }
            return encrypted;
        }


        private const int KeySize = 256;
		public byte[] ToBytes()
		{
			byte[] keyBytes = _Value.ToByteArrayUnsigned();
			Utils.Pad(ref keyBytes, KeySize);
			return keyBytes;
		}
	}
}
