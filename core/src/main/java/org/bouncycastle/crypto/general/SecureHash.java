package org.bouncycastle.crypto.general;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AuthenticationParameters;
import org.bouncycastle.crypto.OutputDigestCalculator;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.internal.CipherKeyGenerator;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.io.DigestOutputStream;
import org.bouncycastle.crypto.internal.macs.HMac;
import org.bouncycastle.crypto.internal.macs.TruncatingMac;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.internal.test.BasicKatTest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for implementations of non-FIPS secure hash algorithms.
 */
public final class SecureHash
{
    private static final Map<GeneralAlgorithm, Integer> defaultMacSize = new HashMap<GeneralAlgorithm, Integer>();

    private SecureHash()
    {

    }

    private enum Variations
    {
        MD5,
        MD5_HMAC,
        GOST3411,
        GOST3411_HMAC,
        RIPEMD128,
        RIPEMD128_HMAC,
        RIPEMD160,
        RIPEMD160_HMAC,
        RIPEMD256,
        RIPEMD256_HMAC,
        RIPEMD320,
        RIPEMD320_HMAC,
        TIGER,
        TIGER_HMAC,
        WHIRLPOOL,
        WHIRLPOOL_HMAC
    }

    public static final class Algorithm
    {
        private Algorithm()
        {

        }

        public static final GeneralDigestAlgorithm MD5 = new GeneralDigestAlgorithm("MD5", Variations.MD5);
        public static final GeneralDigestAlgorithm MD5_HMAC = new GeneralDigestAlgorithm("MD5/HMAC", Variations.MD5_HMAC);
        public static final GeneralDigestAlgorithm GOST3411 = new GeneralDigestAlgorithm("GOST3411", Variations.GOST3411);
        public static final GeneralDigestAlgorithm GOST3411_HMAC = new GeneralDigestAlgorithm("GOST3411/HMAC", Variations.GOST3411_HMAC);
        public static final GeneralDigestAlgorithm RIPEMD128 = new GeneralDigestAlgorithm("RIPEMD128", Variations.RIPEMD128);
        public static final GeneralDigestAlgorithm RIPEMD128_HMAC = new GeneralDigestAlgorithm("RIPEMD128/HMAC", Variations.RIPEMD128_HMAC);
        public static final GeneralDigestAlgorithm RIPEMD160 = new GeneralDigestAlgorithm("RIPEMD160", Variations.RIPEMD160);
        public static final GeneralDigestAlgorithm RIPEMD160_HMAC = new GeneralDigestAlgorithm("RIPEMD160/HMAC", Variations.RIPEMD160_HMAC);
        public static final GeneralDigestAlgorithm RIPEMD256 = new GeneralDigestAlgorithm("RIPEMD256", Variations.RIPEMD256);
        public static final GeneralDigestAlgorithm RIPEMD256_HMAC = new GeneralDigestAlgorithm("RIPEMD256/HMAC", Variations.RIPEMD256_HMAC);
        public static final GeneralDigestAlgorithm RIPEMD320 = new GeneralDigestAlgorithm("RIPEMD320", Variations.RIPEMD320);
        public static final GeneralDigestAlgorithm RIPEMD320_HMAC = new GeneralDigestAlgorithm("RIPEMD320/HMAC", Variations.RIPEMD320_HMAC);
        public static final GeneralDigestAlgorithm TIGER = new GeneralDigestAlgorithm("TIGER", Variations.TIGER);
        public static final GeneralDigestAlgorithm TIGER_HMAC = new GeneralDigestAlgorithm("TIGER/HMAC", Variations.TIGER_HMAC);
        public static final GeneralDigestAlgorithm WHIRLPOOL = new GeneralDigestAlgorithm("WHIRLPOOL", Variations.WHIRLPOOL);
        public static final GeneralDigestAlgorithm WHIRLPOOL_HMAC = new GeneralDigestAlgorithm("WHIRLPOOL/HMAC", Variations.WHIRLPOOL_HMAC);
    }

    static
    {
        defaultMacSize.put(Algorithm.MD5_HMAC, 128);
        defaultMacSize.put(Algorithm.GOST3411_HMAC, 256);
        defaultMacSize.put(Algorithm.RIPEMD128_HMAC, 128);
        defaultMacSize.put(Algorithm.RIPEMD160_HMAC, 160);
        defaultMacSize.put(Algorithm.RIPEMD256_HMAC, 256);
        defaultMacSize.put(Algorithm.RIPEMD320_HMAC, 320);
        defaultMacSize.put(Algorithm.TIGER_HMAC, 192);
        defaultMacSize.put(Algorithm.WHIRLPOOL_HMAC, 512);
    }

    public static final Parameters MD5 = new Parameters(Algorithm.MD5);
    public static final AuthParameters MD5_HMAC = new AuthParameters(Algorithm.MD5_HMAC);
    public static final Parameters GOST3411 = new Parameters(Algorithm.GOST3411);
    public static final AuthParameters GOST3411_HMAC = new AuthParameters(Algorithm.GOST3411_HMAC);
    public static final Parameters RIPEMD128 = new Parameters(Algorithm.RIPEMD128);
    public static final AuthParameters RIPEMD128_HMAC = new AuthParameters(Algorithm.RIPEMD128_HMAC);
    public static final Parameters RIPEMD160 = new Parameters(Algorithm.RIPEMD160);
    public static final AuthParameters RIPEMD160_HMAC = new AuthParameters(Algorithm.RIPEMD160_HMAC);
    public static final Parameters RIPEMD256 = new Parameters(Algorithm.RIPEMD256);
    public static final AuthParameters RIPEMD256_HMAC = new AuthParameters(Algorithm.RIPEMD256_HMAC);
    public static final Parameters RIPEMD320 = new Parameters(Algorithm.RIPEMD320);
    public static final AuthParameters RIPEMD320_HMAC = new AuthParameters(Algorithm.RIPEMD320_HMAC);
    public static final Parameters TIGER = new Parameters(Algorithm.TIGER);
    public static final AuthParameters TIGER_HMAC = new AuthParameters(Algorithm.TIGER_HMAC);
    public static final Parameters WHIRLPOOL = new Parameters(Algorithm.WHIRLPOOL);
    public static final AuthParameters WHIRLPOOL_HMAC = new AuthParameters(Algorithm.WHIRLPOOL_HMAC);

    /**
     * Generic digest parameters.
     */
    public static final class Parameters
        extends GeneralParameters<GeneralAlgorithm>
    {
        Parameters(GeneralAlgorithm algorithm)
        {
            super(algorithm);
        }
    }

    /**
     * Parameters for HMAC modes.
     */
    public static final class AuthParameters
        extends GeneralParameters<GeneralAlgorithm>
        implements AuthenticationParameters<AuthParameters>
    {
        private final int macSizeInBits;

        private AuthParameters(GeneralAlgorithm algorithm, int macSizeInBits)
        {
            super(algorithm);
            this.macSizeInBits = macSizeInBits;
        }

        AuthParameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, defaultMacSize.get(algorithm));
        }

        /**
         * Return the length of the MAC that will be made using these parameters in bits.
         *
         * @return the bit length of the MAC.
         */
        public int getMACSizeInBits()
        {
            return macSizeInBits;
        }

        /**
         * Return a new set of parameters specifying a specific mac size.
         *
         * @param macSizeInBits bit length of the MAC length.
         * @return a new set of AuthParameters for the MAC size.
         */
        public AuthParameters withMACSize(int macSizeInBits)
        {
            return new AuthParameters(this.getAlgorithm(), macSizeInBits);
        }
    }

    /**
     * Factory for producing digest calculators.
     */
    public static final class OperatorFactory
        extends GuardedDigestOperatorFactory<GeneralParameters>
    {
        @Override
        public OutputDigestCalculator<GeneralParameters> createOutputDigestCalculator(GeneralParameters parameter)
        {
            return new LocalOutputDigestCalculator<GeneralParameters>(parameter, createCloner((GeneralAlgorithm)parameter.getAlgorithm()));
        }
    }

    /**
     * HMAC key generator
     */
    public static final class KeyGenerator
        extends GuardedSymmetricKeyGenerator<Parameters>
    {
        private final GeneralAlgorithm algorithm;
        private final int keySizeInBits;
        private final SecureRandom random;

        public KeyGenerator(GeneralAlgorithm algorithm, int keySizeInBits, SecureRandom random)
        {
            this.algorithm = algorithm;
            this.keySizeInBits = keySizeInBits;
            this.random = random;
        }

        public SymmetricKey doGenerateKey()
        {
            CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();

            cipherKeyGenerator.init(new KeyGenerationParameters(random, keySizeInBits));

            return new SymmetricSecretKey(algorithm, cipherKeyGenerator.generateKey());
        }
    }

    /**
     * Factory for producing HMAC calculators.
     */
    public static final class MACOperatorFactory
        extends GuardedMACOperatorFactory<AuthParameters>
    {
        @Override
        protected int calculateMACSize(AuthParameters parameters)
        {
            return getMac(parameters.getAlgorithm()).getMacSize();
        }

        @Override
        protected Mac createMAC(SymmetricKey key, AuthParameters parameters)
        {
            Mac mac = getMac(parameters.getAlgorithm());
            if (mac.getMacSize() != (parameters.getMACSizeInBits() + 7) / 8)
            {
                mac = new TruncatingMac(mac, parameters.macSizeInBits);
            }

            ValidatedSymmetricKey vKey = PrivilegedUtils.getValidatedKey(key);

            mac.init(Utils.getKeyParameter(vKey));

            return mac;
        }
    }

    private static Mac getMac(GeneralAlgorithm algorithm)
    {
        Mac mac;
        switch ((Variations)algorithm.basicVariation())
        {
        case GOST3411_HMAC:
            mac = SelfTestExecutor.validate(algorithm, new HMac(new GOST3411Digest()), new HMacKatTest(Hex.decode("ec352aec8da53f0626fe22699243266ed40da2beff219dfd7dd2dcf3d86ebbc9")));
            break;
        case RIPEMD128_HMAC:
            mac = SelfTestExecutor.validate(algorithm, new HMac(new RIPEMD128Digest()), new HMacKatTest(Hex.decode("875f828862b6b334b427c55f9f7ff09b")));
            break;
        case RIPEMD160_HMAC:
            mac = SelfTestExecutor.validate(algorithm, new HMac(new RIPEMD160Digest()), new HMacKatTest(Hex.decode("dda6c0213a485a9e24f4742064a7f033b43c4069")));
            break;
        case RIPEMD256_HMAC:
            mac = SelfTestExecutor.validate(algorithm, new HMac(new RIPEMD256Digest()), new HMacKatTest(Hex.decode("932d3e799272765675dd63c33f8d2815ea38181494f43271dd52fde91392619f")));
            break;
        case RIPEMD320_HMAC:
            mac = SelfTestExecutor.validate(algorithm, new HMac(new RIPEMD320Digest()), new HMacKatTest(Hex.decode("e440b00b6326e4f7dad3a6591e8189e9708fc17e3cab306fc67efaf70947aad2ea89e28f79d03bd3")));
            break;
        case TIGER_HMAC:
            mac = SelfTestExecutor.validate(algorithm, new HMac(new TigerDigest()), new HMacKatTest(Hex.decode("3a351b1dec6075d6290e68b604e553821edc39041b82da83")));
            break;
        case MD5_HMAC:
            mac = SelfTestExecutor.validate(algorithm, new HMac(new MD5Digest()), new HMacKatTest(Hex.decode("750c783e6ab0b503eaa86e310a5db738")));
            break;
        case WHIRLPOOL_HMAC:
            mac = SelfTestExecutor.validate(algorithm, new HMac(new WhirlpoolDigest()), new HMacKatTest(Hex.decode("3d595ccd1d4f4cfd045af53ba7d5c8283fee6ded6eaf1269071b6b4ea64800056b5077c6a942cfa1221bd4e5aed791276e5dd46a407d2b8007163d3e7cd1de66")));
            break;
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to createMAC: " + algorithm.getName());
        }
        return mac;
    }

    private interface DigestCloner<D extends Digest>
    {
        D makeDigest(D original);
    }

    private static class LocalOutputDigestCalculator<T extends GeneralParameters>
        implements Cloneable, OutputDigestCalculator<T>
    {
        private final Digest digest;
        private final T parameter;
        private final DigestCloner<Digest> cloner;

        private LocalOutputDigestCalculator(T parameter, DigestCloner<Digest> cloner)
        {
            this(parameter, null, cloner);
        }

        private LocalOutputDigestCalculator(T parameter, Digest original, DigestCloner<Digest> cloner)
        {
            this.digest = cloner.makeDigest(original);
            this.parameter = parameter;
            this.cloner = cloner;
        }

        public T getParameters()
        {
            Utils.approveModeCheck(parameter.getAlgorithm());

            return parameter;
        }

        public int getDigestSize()
        {
            Utils.approveModeCheck(parameter.getAlgorithm());

            return digest.getDigestSize();
        }

        public int getDigestBlockSize()
        {
            Utils.approveModeCheck(parameter.getAlgorithm());

            return digest.getByteLength();
        }

        public UpdateOutputStream getDigestStream()
        {
            return new DigestOutputStream(digest);
        }

        public final byte[] getDigest()
        {
            byte[] rv = new byte[getDigestSize()];

            getDigest(rv, 0);

            return rv;
        }

        public final int getDigest(byte[] output, int offSet)
        {
            return digest.doFinal(output, offSet);
        }

        public void reset()
        {
            digest.reset();
        }

        public OutputDigestCalculator<T> clone()
            throws CloneNotSupportedException
        {
            super.clone();

            return new LocalOutputDigestCalculator<T>(parameter, digest, cloner);

        }
    }

    private static DigestCloner<Digest> createCloner(final GeneralAlgorithm algorithm)
    {
        switch ((Variations)algorithm.basicVariation())
        {
        case MD5:
            return new DigestCloner<Digest>()
            {
                public Digest makeDigest(Digest original)
                {
                    if (original != null)
                    {
                        return new MD5Digest((MD5Digest)original);
                    }

                    return SelfTestExecutor.validate(algorithm, new MD5Digest(), new DigestKatTest(Hex.decode("900150983cd24fb0d6963f7d28e17f72")));
                }
            };
        case GOST3411:
            return new DigestCloner<Digest>()
            {
                public Digest makeDigest(Digest original)
                {
                    if (original != null)
                    {
                        return new GOST3411Digest((GOST3411Digest)original);
                    }

                    return SelfTestExecutor.validate(algorithm, new GOST3411Digest(), new DigestKatTest(Hex.decode("b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c")));
                }
            };
        case RIPEMD128:
            return new DigestCloner<Digest>()
            {
                public Digest makeDigest(Digest original)
                {
                    if (original != null)
                    {
                        return new RIPEMD128Digest((RIPEMD128Digest)original);
                    }

                    return SelfTestExecutor.validate(algorithm, new RIPEMD128Digest(), new DigestKatTest(Hex.decode("c14a12199c66e4ba84636b0f69144c77")));
                }
            };
        case RIPEMD160:
            return new DigestCloner<Digest>()
            {
                public Digest makeDigest(Digest original)
                {
                    if (original != null)
                    {
                        return new RIPEMD160Digest((RIPEMD160Digest)original);
                    }

                    return SelfTestExecutor.validate(algorithm, new RIPEMD160Digest(), new DigestKatTest(Hex.decode("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")));
                }
            };
        case RIPEMD256:
            return new DigestCloner<Digest>()
            {
                public Digest makeDigest(Digest original)
                {
                    if (original != null)
                    {
                        return new RIPEMD256Digest((RIPEMD256Digest)original);
                    }

                    return SelfTestExecutor.validate(algorithm, new RIPEMD256Digest(), new DigestKatTest(Hex.decode("afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65")));
                }
            };
        case RIPEMD320:
            return new DigestCloner<Digest>()
            {
                public Digest makeDigest(Digest original)
                {
                    if (original != null)
                    {
                        return new RIPEMD320Digest((RIPEMD320Digest)original);
                    }

                    return SelfTestExecutor.validate(algorithm, new RIPEMD320Digest(), new DigestKatTest(Hex.decode("de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d")));
                }
            };
        case TIGER:
            return new DigestCloner<Digest>()
            {
                public Digest makeDigest(Digest original)
                {
                    if (original != null)
                    {
                        return new TigerDigest((TigerDigest)original);
                    }

                    return SelfTestExecutor.validate(algorithm, new TigerDigest(), new DigestKatTest(Hex.decode("2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93")));
                }
            };
        case WHIRLPOOL:
            return new DigestCloner<Digest>()
            {
                public Digest makeDigest(Digest original)
                {
                    if (original != null)
                    {
                        return new WhirlpoolDigest((WhirlpoolDigest)original);
                    }

                    return SelfTestExecutor.validate(algorithm, new WhirlpoolDigest(), new DigestKatTest(Hex.decode("4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5")));
                }
            };
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to SecureHash.OperatorFactory.createOutputDigestCalculator: " + algorithm.getName());
        }
    }

    static Digest createDigest(GeneralDigestAlgorithm algorithm)
    {
        return createCloner(algorithm).makeDigest(null);
    }

    static Mac createHMac(GeneralDigestAlgorithm algorithm)
    {
        return getMac(algorithm);
    }

    private static class DigestKatTest
        implements BasicKatTest<Digest>
    {
        private static final byte[] stdShaVector = Strings.toByteArray("abc");
        private final byte[] kat;

        DigestKatTest(byte[] kat)
        {
            this.kat = kat;
        }

        public boolean hasTestPassed(Digest digest)
        {
            digest.update(stdShaVector, 0, stdShaVector.length);

            byte[] result = new byte[digest.getDigestSize()];

            digest.doFinal(result, 0);

            return Arrays.areEqual(result, kat);
        }
    }

    private static class HMacKatTest
        implements BasicKatTest<Mac>
    {
        private static final byte[] stdHMacVector = Strings.toByteArray("what do ya want for nothing?");
        private static final byte[] key = Hex.decode("4a656665");

        private final byte[] kat;

        HMacKatTest(byte[] kat)
        {
            this.kat = kat;
        }

        public boolean hasTestPassed(Mac hMac)
        {
            hMac.init(new KeyParameterImpl(Arrays.clone(key)));

            hMac.update(stdHMacVector, 0, stdHMacVector.length);

            byte[] result = new byte[hMac.getMacSize()];

            hMac.doFinal(result, 0);

            return Arrays.areEqual(result, kat);
        }
    }
}
