package org.bouncycastle.crypto.fips;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EncapsulatingSecretGenerator;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.InvalidWrappingException;
import org.bouncycastle.crypto.Key;
import org.bouncycastle.crypto.KeyWrapperUsingSecureRandom;
import org.bouncycastle.crypto.PlainInputProcessingException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPublicKey;
import org.bouncycastle.crypto.general.FipsRegister;
import org.bouncycastle.crypto.internal.AsymmetricBlockCipher;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.CryptoException;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.Permissions;
import org.bouncycastle.crypto.internal.PrimeCertaintyCalculator;
import org.bouncycastle.crypto.internal.Signer;
import org.bouncycastle.crypto.internal.encodings.OAEPEncoding;
import org.bouncycastle.crypto.internal.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.internal.io.SignerOutputStream;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.crypto.internal.params.RsaKeyGenerationParameters;
import org.bouncycastle.crypto.internal.params.RsaKeyParameters;
import org.bouncycastle.crypto.internal.params.RsaPrivateCrtKeyParameters;
import org.bouncycastle.crypto.internal.signers.BaseRsaDigestSigner;
import org.bouncycastle.crypto.internal.test.ConsistencyTest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.TestRandomData;

/**
 * Source class for FIPS approved implementations of RSA algorithms.
 */
public final class FipsRSA
{
    public static final FipsAlgorithm ALGORITHM = new FipsAlgorithm("RSA");

    static final FipsEngineProvider<AsymmetricBlockCipher> ENGINE_PROVIDER;

    private FipsRSA()
    {

    }

    private enum Variations
    {
        PKCS1v1_5,
        PSS,
        X931,
        OAEP,
        SVE
    }

    private static final FipsAlgorithm ALGORITHM_PKCS1v1_5 = new FipsAlgorithm("RSA/PKCS1V1.5", Variations.PKCS1v1_5);
    private static final FipsAlgorithm ALGORITHM_PSS = new FipsAlgorithm("RSA/PSS", Variations.PSS);
    private static final FipsAlgorithm ALGORITHM_X931 = new FipsAlgorithm("RSA/X9.31", Variations.X931);
    private static final FipsAlgorithm ALGORITHM_OAEP = new FipsAlgorithm("RSA/OAEP", Variations.OAEP);
    private static final FipsAlgorithm ALGORITHM_SVE = new FipsAlgorithm("RSA/SVE", Variations.SVE);

    /**
     * RSA PKCS#1 v1.5 signature  algorithm parameter source - default is SHA-1
     */
    public static final PKCS1v15SignatureParameters PKCS1v1_5 = new PKCS1v15SignatureParameters();
    /**
     * RSA PSS signature  algorithm parameter source - default is SHA-1
     */
    public static final PSSSignatureParameters PSS = new PSSSignatureParameters();
    /**
     * RSA X9.31 signature algorithm parameter source - default is SHA-1
     */
    public static final X931SignatureParameters X931 = new X931SignatureParameters();

    /**
     * RSA PKCS#1 v1.5 key wrap algorithm parameter source - default is SHA-1
     */
    public static final PKCS1v15Parameters WRAP_PKCS1v1_5 = new PKCS1v15Parameters();
    /**
     * RSA OAEP key wrap algorithm parameter source - default is SHA-1
     */
    public static final OAEPParameters WRAP_OAEP = new OAEPParameters();

    /**
     * RSA KTS SVE key transport algorithm parameter source.
     */
    public static final SVEKTSParameters KTS_SVE = new SVEKTSParameters();

    /**
     * RSA KTS OAEP key transport algorithm parameter source - default is OAEP(SHA-1), keysize 128
     */
    public static final OAEPKTSParameters KTS_OAEP = new OAEPKTSParameters(WRAP_OAEP, 128);

    // Public exponent bounds
    private static final BigInteger MIN_PUB_EXP = BigInteger.valueOf(0x10001);
    private static final BigInteger MAX_PUB_EXP = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);

    // KAT parameters
    private static BigInteger katE = new BigInteger("10001", 16);
    private static BigInteger katM = new BigInteger("83ca29fa6f3da1a20a7d64c741c502def9dff5630c94ca0c674a7602aea3436d432c94e3fe9f8cea4a7975ffa5228cba39acb6d1262c3453280bd8352b0dc7fb0a343f62b2c1405baf44c0f6b37edc94f63de8f772dc30e3b5003ff9a35befa02540e08b128718870fab40dcd91575b6592bb143cc3f29aa82fce7ee72952601c0c815396a9ad382c0a79e494727478606bf92d7b1c445b73368b4d7480500091de498b365719ec9c9b76f37cc97d13d7ce830248f4df2cdc73433a9b5d3fe29122bfdb113be45444b15652059eb51085dfe354d0c87256e6a51c6902ce56d3967dcf32f3bc9464ab437ac4030d00c1e53b4da74b9e70c47a5842f3b4d4dd6c7", 16);
    private static BigInteger katD = new BigInteger("22b248d6fc0e77cd5781a7d4a5c61e7961c3cab0e7110d18b2e0f1acc7198898ed8481367d44b82ebea8b79e3475a2232d28018192d1347d681fa62e6945598f0822b54560d66c0137659c7fd6c5e180fe4b5258434f2137f1e13cf696419016d377ff25de1cdf223fc7d06dd46147fa58039ec9c0ae286411d44fa3815b2f040895344a413ba141b4228a704a75883caaa3e9d2ace0d28c179acb571ca8ce0d1c3a0cf9cda8b0088b919a4833f5b46ce556faa923ea5b852a48f153ca6fc26730496d7f06691e08edac984870517d2ef689a94ad23c16d471c9a477d82fd225382a4d1ae1b934bf79f2adf3353c557888e056822809dfb561bbef946c1404d1", 16);
    private static BigInteger katP = new BigInteger("df26154977b823cbee3e1861b239197310bc3115ee46e7e70bf6dd826aa834fcdafb8d940b77e43e63c073b2efceaa24805c232a3011fd8b2ac323442d89f246a024c843586174d28475fbf7eca079fae8bbe5263cdef074be0a9a07a37bdad3e72b4b44a39a70415db4b0f7f65515f6806ef88b97f935b8d6d5918feff69edd", 16);
    private static BigInteger katQ = new BigInteger("9730fcb5f8e93cb4df58b80ab3e9b7f014a87b90953c26a29277771965bf2720e1808adf55aa5ac4702ba813eb2643d03a89dad3a3767beddd3fa98148057c8398a0106b086caef10603977e69ffe3e513531c7b456bb7079c57761a7eacde4218c08897ac17d4de7a5b19d192b5706694cbb162c9f95b0154232fc7bd0107f3", 16);
    private static BigInteger katDP = new BigInteger("dba3666c6bb40937de85ac05ed201a9691304ab82552114bef10cb3264bcaf7afa278350e680d95d375de40389da46c9aab605beae95e6932641efe259585fe97812fc329d393f7d3df7cb4c59d2127e0eb97270d29534e41371e7ee00d215af60e7d22bfb44359d81182adfc5cc35d3ecd24d3d491677f43930f9174dbfd6d9", 16);
    private static BigInteger katDQ = new BigInteger("82d8a47ca054ca7306b07366dfd9af94996c4eb40c53a8641e3a41dabb11b9bd5d2bb00424d170087dc36a8d027f7544eac48f9b85e66ecea7220782996016289598415d40473f07dcda92eb96b51cf80dc769e8cd65b15b66d4d2a38f69f05867af89072aaadd5145b73e1affcb02e1e4787ca630821b5e850086c36831523d", 16);
    private static BigInteger katQInv = new BigInteger("c6ae6a9ff4614a08e1e501e3dd7586c7cd2e70b9e2581185194b7984452325558f576b54b177df38f6d98e2ffce835608d1d3c81fab9f3696796bd5faacf9870b5ad12868eebccb2f55cc398d70ad6197eaeb4ead5cb0415913f18306bc0327f31db0f04910aea237a657634f1ac82b03bd5b2bc30b5f89077677bd3cab0d255", 16);

    private static byte[] msg = Hex.decode("48656c6c6f20776f726c6421");
    private static byte[] pkcs15Sig = Hex.decode("1669b752b409a66ca38ba7e34ae2d5da4303c091255989a4369885ecbb25db3ec05b06fdb4b1be46f6ab347bad9dbbbc9facf0beb4be70bd5f2ee2760c76f0a55932dd7fb4fe5c7b18226796f955215ec6354da9b3808a0df8c2a328abdd67d537f967ea5147bb85dcd80fdcee250b9bc7cec84a08afcde82afa4e62d80bbaf00bcdaf6bbac2b4a4bd394ee223ea3ee100fd233dd40514ea7a9717bfb52370eb4157e7bd25396e9dd3e3782ec2c64db71cf8380c05d3941481af3a08003737456a00cb265efc1d0987acae40776fa497681cb987a508419cbe1e4601a5e5aef66329288453003101a375ad3ec6e4b9a82f49a0748eb024fe1ce2de910d823938");

    private static final RsaKeyParameters testPubKey = new RsaKeyParameters(false, katM, katE);
    private static final RsaPrivateCrtKeyParameters testPrivKey = new RsaPrivateCrtKeyParameters(katM, katE, katD, katP, katQ, katDP, katDQ, katQInv);

    static
    {
        EngineProvider provider = new EngineProvider();

        // FSM_STATE:3.RSA.0,"RSA SIGN VERIFY KAT", "The module is performing RSA sign and verify KAT self-test"
        // FSM_TRANS:3.RSA.0,"POWER ON SELF-TEST","RSA SIGN VERIFY KAT", "Invoke RSA Sign/Verify KAT self-test"
        rsaSignTest(provider);
        // FSM_TRANS:3.RSA.1,"RSA SIGN VERIFY KAT","POWER ON SELF-TEST", "RSA Sign/Verify KAT self-test successful completion"

        // FSM_STATE:3.RSA.1,"KEY AGREEMENT USING RSA VERIFY KAT", "The module is performing RSA Key Agreement verify KAT self-test"
        // FSM_TRANS:3.RSA.2,"POWER ON SELF-TEST","KEY AGREEMENT USING RSA VERIFY KAT", "Invoke Key Agreement Using RSA, Specific SP 800-56B KAT self-test"
        rsaKasTest(provider);
        // FSM_TRANS:3.RSA.3, "KEY AGREEMENT USING RSA VERIFY KAT", "POWER ON SELF-TEST", "Key Agreement Using RSA, Specific SP 800-56B KAT self-test successful completion"

        // FSM_STATE:3.RSA.2, "KEY TRANSPORT USING RSA VERIFY KAT", "The module is performing RSA Key Transport verify KAT self-test"
        // FSM_TRANS:3.RSA.4,"POWER ON SELF-TEST","KEY TRANSPORT USING RSA VERIFY KAT", "Invoke Key Transport Using RSA, Specific SP 800-56B KAT self-test"
        rsaKeyTransportTest(provider);
        // FSM_TRANS:3.RSA.5,"KEY TRANSPORT USING RSA VERIFY KAT", "POWER ON SELF-TEST", "Key Transport Using RSA, Specific SP 800-56B KAT self-test successful completion"

        ENGINE_PROVIDER = provider;

        FipsRegister.registerEngineProvider(ALGORITHM, provider);
    }

    /**
     * Parameters for RSA key pair generation.
     */
    public static final class KeyGenParameters
        extends FipsParameters
    {
        private BigInteger publicExponent;
        private int keySize;
        private int certainty;

        /**
         * Base constructor.
         *
         * @param publicExponent the public exponent to use.
         * @param keySize the key size (in bits).
         */
        public KeyGenParameters(BigInteger publicExponent, int keySize)
        {
            this(ALGORITHM, publicExponent, keySize, PrimeCertaintyCalculator.getDefaultCertainty(keySize));
        }

        /**
         * Base constructor with certainty.
         *
         * @param publicExponent the public exponent to use.
         * @param keySize the key size (in bits).
         * @param certainty certainty to use for prime number calculation.
         */
        public KeyGenParameters(BigInteger publicExponent, int keySize, int certainty)
        {
            this(ALGORITHM, publicExponent, keySize, certainty);
        }

        /**
         * Constructor for a key targeted to a specific signature algorithm.
         *
         * @param parameters the signature parameter set containing the algorithm.
         * @param publicExponent the public exponent to use.
         * @param keySize the key size (in bits).
         */
        public KeyGenParameters(SignatureParameters parameters, BigInteger publicExponent, int keySize)
        {
            this(parameters.getAlgorithm(), publicExponent, keySize, PrimeCertaintyCalculator.getDefaultCertainty(keySize));
        }

        /**
         * Constructor for a key targeted to a specific wrap algorithm.
         *
         * @param parameters the wrap parameter set containing the algorithm.
         * @param publicExponent the public exponent to use.
         * @param keySize the key size (in bits).
         */
        public KeyGenParameters(WrapParameters parameters, BigInteger publicExponent, int keySize)
        {
            this(parameters.getAlgorithm(), publicExponent, keySize, PrimeCertaintyCalculator.getDefaultCertainty(keySize));
        }

        /**
         * Constructor for a key targeted to a specific KTS algorithm.
         *
         * @param parameters the KTS parameter set containing the algorithm.
         * @param publicExponent the public exponent to use.
         * @param keySize the key size (in bits).
         */
        public KeyGenParameters(KTSParameters parameters, BigInteger publicExponent, int keySize)
        {
            this(parameters.getAlgorithm(), publicExponent, keySize, PrimeCertaintyCalculator.getDefaultCertainty(keySize));
        }

        private KeyGenParameters(FipsAlgorithm algorithm, BigInteger publicExponent, int keySize, int certainty)
        {
            super(algorithm);

            this.publicExponent = publicExponent;
            this.keySize = keySize;
            this.certainty = certainty;

            validate();
        }

        private void validate()
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (this.keySize != 2048 && this.keySize != 3072)
                {
                    throw new FipsUnapprovedOperationError("Attempt to use RSA key size outside of accepted range - requested keySize " + keySize + " bits", getAlgorithm());
                }

                if (this.publicExponent.compareTo(MIN_PUB_EXP) < 0)
                {
                    throw new FipsUnapprovedOperationError("Public exponent too small", getAlgorithm());
                }

                if (this.publicExponent.compareTo(MAX_PUB_EXP) > 0)
                {
                    throw new FipsUnapprovedOperationError("Public exponent too large", getAlgorithm());
                }

                if (!this.publicExponent.testBit(0))
                {
                    throw new FipsUnapprovedOperationError("Public exponent must be an odd number", getAlgorithm());
                }

                if (this.certainty < PrimeCertaintyCalculator.getDefaultCertainty(keySize))
                {
                    throw new FipsUnapprovedOperationError("Prime generation certainty " + certainty + " inadequate for key of  " + keySize + " bits", getAlgorithm());
                }
            }
            else
            {
                if (!this.publicExponent.testBit(0))
                {
                    throw new IllegalArgumentException("Public exponent must be an odd number: " + getAlgorithm().getName());
                }
            }
        }

        public BigInteger getPublicExponent()
        {
            return publicExponent;
        }

        public int getKeySize()
        {
            return keySize;
        }

        public int getCertainty()
        {
            return certainty;
        }
    }

    /**
     * Base class for RSA digest based signature algorithm parameters.
     */
    public static class SignatureParameters
        extends FipsParameters
    {
        private final FipsDigestAlgorithm digestAlgorithm;

        SignatureParameters(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm)
        {
            super(algorithm);

            if (digestAlgorithm == null && CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                PrivilegedUtils.checkPermission(Permissions.TlsNullDigestEnabled);
            }

            this.digestAlgorithm = digestAlgorithm;
        }

        public FipsDigestAlgorithm getDigestAlgorithm()
        {
            return digestAlgorithm;
        }
    }

    /**
     * Parameters for PKCS#1 v1.5 digest signatures.
     */
    public static final class PKCS1v15SignatureParameters
        extends SignatureParameters
    {
        PKCS1v15SignatureParameters()
        {
            super(ALGORITHM_PKCS1v1_5, FipsSHS.Algorithm.SHA1);
        }

        private PKCS1v15SignatureParameters(FipsDigestAlgorithm digestAlgorithm)
        {
            super(ALGORITHM_PKCS1v1_5, digestAlgorithm);
        }

        /**
         * Return a new parameter set with for the passed in digest algorithm.
         *
         * @param digestAlgorithm the digest to use for signature generation.
         * @return a new parameter for signature generation.
         */
        public PKCS1v15SignatureParameters withDigestAlgorithm(FipsDigestAlgorithm digestAlgorithm)
        {
            return new PKCS1v15SignatureParameters(digestAlgorithm);
        }
    }

    /**
     * Parameters for RSA PSS digest signatures.
     */
    public static final class PSSSignatureParameters
        extends SignatureParameters
    {
        private final int saltLength;
        private final FipsDigestAlgorithm mgfDigest;
        private final int trailer;
        private final byte[] salt;

        PSSSignatureParameters()
        {
            this(FipsSHS.Algorithm.SHA1, FipsSHS.Algorithm.SHA1, 20, null, PSSSigner.TRAILER_IMPLICIT);
        }

        private PSSSignatureParameters(FipsDigestAlgorithm digestAlgorithm, FipsDigestAlgorithm mgfDigest, int saltLength, byte[] salt, int trailer)
        {
            super(ALGORITHM_PSS, digestAlgorithm);

            this.mgfDigest = mgfDigest;
            this.saltLength = saltLength;
            this.salt = salt;
            this.trailer = trailer;
        }

        /**
         * Specify the digest algorithm to use. This also sets the MGF digest, salt, and the salt length.
         *
         * @param digestAlgorithm a digest algorithm.
         * @return a new parameter set.
         */
        public PSSSignatureParameters withDigestAlgorithm(FipsDigestAlgorithm digestAlgorithm)
        {
            return new PSSSignatureParameters(digestAlgorithm, digestAlgorithm, FipsSHS.createDigest(digestAlgorithm).getDigestSize(), null, trailer);
        }

        /**
         * Specify the digest algorithm to use for the MGF.
         *
         * @param mgfDigest a digest algorithm for the MGF.
         * @return a new parameter set.
         */
        public PSSSignatureParameters withMGFDigest(FipsDigestAlgorithm mgfDigest)
        {
            return new PSSSignatureParameters(this.getDigestAlgorithm(), mgfDigest, saltLength, salt, trailer);
        }

        /**
         * Specify the saltLength for the signature.
         *
         * @param saltLength the salt length.
         * @return a new parameter set.
         */
        public PSSSignatureParameters withSaltLength(int saltLength)
        {
            return new PSSSignatureParameters(this.getDigestAlgorithm(), mgfDigest, saltLength, null, trailer);
        }

        /**
         * Specify the trailer for the signature.
         *
         * @param trailer the trailer for the signature.
         * @return a new parameter set.
         */
        public PSSSignatureParameters withTrailer(int trailer)
        {
            return new PSSSignatureParameters(this.getDigestAlgorithm(), mgfDigest, saltLength, salt, trailer);
        }

        /**
         * Specify a fixed salt for the signature.
         *
         * @param salt the salt to use.
         * @return a new parameter set.
         */
        public PSSSignatureParameters withSalt(byte[] salt)
        {
            return new PSSSignatureParameters(this.getDigestAlgorithm(), mgfDigest, salt.length, Arrays.clone(salt), trailer);
        }

        public byte[] getSalt()
        {
            return Arrays.clone(salt);
        }

        public int getSaltLength()
        {
            return saltLength;
        }

        public FipsDigestAlgorithm getMGFDigest()
        {
            return mgfDigest;
        }

        public int getTrailer()
        {
            return trailer;
        }
    }

    /**
     * Parameters for RSA X9.31 digest signatures.
     */
    public static final class X931SignatureParameters
        extends SignatureParameters
    {
        X931SignatureParameters()
        {
            super(ALGORITHM_X931, FipsSHS.Algorithm.SHA1);
        }

        private X931SignatureParameters(FipsDigestAlgorithm digestAlgorithm)
        {
            super(ALGORITHM_X931, digestAlgorithm);
        }

        /**
         * Return a new parameter set with for the passed in digest algorithm.
         *
         * @param digestAlgorithm the digest to use for signature generation.
         * @return a new parameter for signature generation.
         */
        public X931SignatureParameters withDigestAlgorithm(FipsDigestAlgorithm digestAlgorithm)
        {
            return new X931SignatureParameters(digestAlgorithm);
        }
    }

    /**
     * Base class for RSA key wrapping/unwrapping parameters.
     */
    public static class WrapParameters
        extends FipsParameters
    {
        WrapParameters(FipsAlgorithm algorithm)
        {
            super(algorithm);
        }
    }

    /**
     * Parameters for use with PKCS#1 v1.5 format key wrapping/unwrapping.
     */
    public static final class PKCS1v15Parameters
        extends WrapParameters
    {
        PKCS1v15Parameters()
        {
            super(ALGORITHM_PKCS1v1_5);
        }
    }

    /**
     * Parameters for use with OAEP formatted key wrapping/unwrapping and encryption/decryption.
     */
    public static final class OAEPParameters
        extends WrapParameters
    {
        private final FipsDigestAlgorithm digestAlgorithm;
        private final FipsDigestAlgorithm mgfDigestAlgorithm;
        private final byte[] encodingParams;

        OAEPParameters()
        {
            this(FipsSHS.Algorithm.SHA1, FipsSHS.Algorithm.SHA1, null);
        }

        private OAEPParameters(FipsDigestAlgorithm digestAlgorithm, FipsDigestAlgorithm mgfDigestAlgorithm, byte[] encodingParams)
        {
            super(ALGORITHM_OAEP);

            this.digestAlgorithm = digestAlgorithm;
            this.mgfDigestAlgorithm = mgfDigestAlgorithm;
            this.encodingParams = Arrays.clone(encodingParams);
        }

        /**
         * Specify the digest algorithm to use. This also sets the MGF digest.
         *
         * @param digestAlgorithm a digest algorithm.
         * @return a new parameter set.
         */
        public OAEPParameters withDigest(FipsDigestAlgorithm digestAlgorithm)
        {
            return new OAEPParameters(digestAlgorithm, digestAlgorithm, encodingParams);
        }

        /**
         * Specify the digest algorithm to use for the MGF.
         *
         * @param mgfDigestAlgorithm a digest algorithm for the MGF.
         * @return a new parameter set.
         */
        public OAEPParameters withMGFDigest(FipsDigestAlgorithm mgfDigestAlgorithm)
        {
            return new OAEPParameters(digestAlgorithm, mgfDigestAlgorithm, encodingParams);
        }

        /**
         * Set the encoding parameters.
         *
         * @param encodingParams encoding params to include.
         * @return a new parameter set.
         */
        public OAEPParameters withEncodingParams(byte[] encodingParams)
        {
            return new OAEPParameters(digestAlgorithm, mgfDigestAlgorithm, Arrays.clone(encodingParams));
        }

        public FipsDigestAlgorithm getDigest()
        {
            return digestAlgorithm;
        }

        public FipsDigestAlgorithm getMGFDigest()
        {
            return mgfDigestAlgorithm;
        }

        public byte[] getEncodingParams()
        {
            return Arrays.clone(encodingParams);
        }
    }


    /**
     * RSA key pair generator class.
     */
    public static final class KeyPairGenerator
        extends FipsAsymmetricKeyPairGenerator<KeyGenParameters, AsymmetricRSAPublicKey, AsymmetricRSAPrivateKey>
    {
        private final RsaKeyPairGenerator engine = new RsaKeyPairGenerator();
        private final RsaKeyGenerationParameters param;

        public KeyPairGenerator(KeyGenParameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            int keySize = keyGenParameters.getKeySize();

            keyGenParameters.validate();

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                Utils.validateKeyPairGenRandom(random, Utils.getAsymmetricSecurityStrength(keySize), ALGORITHM);
            }

            this.param = new RsaKeyGenerationParameters(keyGenParameters.getPublicExponent(), random, keySize, keyGenParameters.getCertainty());
            this.engine.init(param);
        }

        @Override
        public AsymmetricKeyPair<AsymmetricRSAPublicKey, AsymmetricRSAPrivateKey> generateKeyPair()
        {
            AsymmetricCipherKeyPair kp = engine.generateKeyPair();

            RsaKeyParameters pubKey = (RsaKeyParameters)kp.getPublic();
            RsaPrivateCrtKeyParameters prvKey = (RsaPrivateCrtKeyParameters)kp.getPrivate();

            FipsAlgorithm algorithm = this.getParameters().getAlgorithm();

            // FSM_STATE:5.5, "RSA PAIRWISE CONSISTENCY TEST", "The module is performing RSA Pairwise Consistency self-test"
            // FSM_TRANS:5.RSA.0,"CONDITIONAL TEST", "RSA PAIRWISE CONSISTENCY TEST", "Invoke RSA Pairwise Consistency test"
            validateKeyPair(kp);
            // FSM_TRANS:5.RSA.1,"RSA PAIRWISE CONSISTENCY TEST", "CONDITIONAL TEST", "RSA Pairwise Consistency test successful"
            // FSM_TRANS:5.RSA.2,"RSA PAIRWISE CONSISTENCY TEST", "SOFT ERROR", "RSA Pairwise Consistency test failed"

            // we set the private key up so that the modulus value is introduced into the validated modulus cache
            AsymmetricRSAPrivateKey privateKey = new AsymmetricRSAPrivateKey(algorithm, prvKey.getModulus(), prvKey.getPublicExponent(), prvKey.getExponent(),
                prvKey.getP(), prvKey.getQ(), prvKey.getDP(), prvKey.getDQ(), prvKey.getQInv());

            return new AsymmetricKeyPair<AsymmetricRSAPublicKey, AsymmetricRSAPrivateKey>(new AsymmetricRSAPublicKey(algorithm, pubKey.getModulus(), pubKey.getExponent()),
                privateKey);
        }
    }

    /**
     * Operator factory for creating RSA based signing and verification operators.
     *
     * @param <T> the parameters type for the algorithm the factory is for.
     */
    public static final class SignatureOperatorFactory<T extends SignatureParameters>
        extends FipsSignatureOperatorFactory<T>
    {
        /**
         * Return an RSA based signer.
         * <p>
         * Note that while this method returns a FipsOutputSignerUsingSecureRandom, an attempt calls to withSecureRandom()
         * for algorithms that do not require it will result in an error.
         * </p>
         *
         * @param key        the signing key.
         * @param parameters parameters for the algorithm required.
         * @return an OutputSigner.
         */
        @Override
        public FipsOutputSignerUsingSecureRandom<T> createSigner(AsymmetricPrivateKey key, final T parameters)
        {
            AsymmetricRSAPrivateKey k = (AsymmetricRSAPrivateKey)key;

            // FSM_STATE:5.13,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
            // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
            if (!k.canBeUsed(AsymmetricRSAKey.Usage.SIGN_OR_VERIFY))
            {
                // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
                throw new IllegalKeyException("Attempt to sign/verify with RSA modulus already used for encrypt/decrypt.");
            }
            // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                int bitLength = k.getModulus().bitLength();
                if (bitLength != 2048 && bitLength != 3072)
                {
                    throw new FipsUnapprovedOperationError("Attempt to use RSA key with non-approved size: " + bitLength, key.getAlgorithm());
                }
            }

            return new RSASigner<T>(parameters, getPrivateKeyParameters(k), null);
        }

        @Override
        public FipsOutputVerifier<T> createVerifier(AsymmetricPublicKey key, final T parameters)
        {
            final Signer signer;
            if (parameters instanceof PKCS1v15SignatureParameters)
            {
                if (parameters.getDigestAlgorithm() == null)
                {
                    signer = new NullSigner();
                }
                else
                {
                    signer = new RsaDigestSigner(ENGINE_PROVIDER.createEngine(), FipsSHS.createDigest(parameters.getDigestAlgorithm()));
                }
            }
            else if (parameters instanceof PSSSignatureParameters)
            {
                signer = getPSSSigner((PSSSignatureParameters)parameters);
            }
            else
            {
                signer = new X931Signer(new RsaBlindedEngine(), FipsSHS.createDigest(parameters.getDigestAlgorithm()));
            }

            AsymmetricRSAPublicKey k = (AsymmetricRSAPublicKey)key;

            // FSM_STATE:5.13,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
            // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
            if (!k.canBeUsed(AsymmetricRSAKey.Usage.SIGN_OR_VERIFY))
            {
                // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
                throw new IllegalKeyException("Attempt to sign/verify with RSA modulus already used for encrypt/decrypt.");
            }
            // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                int bitLength = k.getModulus().bitLength();
                // 186-4 key sizes                             // 186-2 legacy key sizes
                if (bitLength != 2048 && bitLength != 3072 && bitLength != 1024 && bitLength != 4096 && bitLength != 1536)
                {
                    throw new FipsUnapprovedOperationError("Attempt to use RSA key with non-approved size: " + bitLength, key.getAlgorithm());
                }
            }

            RsaKeyParameters publicKeyParameters = new RsaKeyParameters(false, k.getModulus(), k.getPublicExponent());

            signer.init(false, publicKeyParameters);

            return new FipsOutputVerifier<T>()
            {
                @Override
                public T getParameters()
                {
                    return parameters;
                }

                @Override
                public org.bouncycastle.crypto.UpdateOutputStream getVerifyingStream()
                {
                    return new SignerOutputStream(parameters.getAlgorithm().getName(), signer);
                }

                @Override
                public boolean isVerified(byte[] signature)
                    throws InvalidSignatureException
                {
                    try
                    {
                        return signer.verifySignature(signature);
                    }
                    catch (Exception e)
                    {
                        return false;
                    }
                }
            };
        }

        private class RSASigner<P extends SignatureParameters>
            extends FipsOutputSignerUsingSecureRandom<P>
        {
            final Signer signer;
            private final CipherParameters keyParameters;
            private final P parameters;
            private final SecureRandom random;

            RSASigner(P parameters, CipherParameters keyParameters, SecureRandom random)
            {
                this.parameters = parameters;
                this.keyParameters = keyParameters;
                this.random = random;

                if (parameters instanceof PKCS1v15SignatureParameters)
                {
                    if (parameters.getDigestAlgorithm() == null)
                    {
                        signer = new NullSigner();
                    }
                    else
                    {
                        signer = new RsaDigestSigner(ENGINE_PROVIDER.createEngine(), FipsSHS.createDigest(parameters.getDigestAlgorithm()));
                    }
                }
                else if (parameters instanceof PSSSignatureParameters)
                {
                    signer = getPSSSigner((PSSSignatureParameters)parameters);
                }
                else
                {
                    signer = new X931Signer(ENGINE_PROVIDER.createEngine(), FipsSHS.createDigest(parameters.getDigestAlgorithm()));
                }
            }

            @Override
            public P getParameters()
            {
                return parameters;
            }

            @Override
            public UpdateOutputStream getSigningStream()
            {
                if (random != null)
                {
                    signer.init(true, new ParametersWithRandom(keyParameters, random));
                }
                else
                {
                    signer.init(true, new ParametersWithRandom(keyParameters, CryptoServicesRegistrar.getSecureRandom()));
                }

                return new SignerOutputStream(parameters.getAlgorithm().getName(), signer);
            }

            @Override
            public byte[] getSignature()
                throws PlainInputProcessingException
            {
                try
                {
                    return signer.generateSignature();
                }
                catch (Exception e)
                {
                    throw new PlainInputProcessingException("Unable to create signature: " + e.getMessage(), e);
                }
            }

            @Override
            public FipsOutputSignerUsingSecureRandom<P> withSecureRandom(SecureRandom random)
            {
                return new RSASigner<P>(parameters, keyParameters, random);
            }

            @Override
            public int getSignature(byte[] output, int off)
                throws PlainInputProcessingException
            {
                byte[] signature = getSignature();

                System.arraycopy(signature, 0, output, off, signature.length);

                return signature.length;
            }
        }
    }

    private static Signer getPSSSigner(PSSSignatureParameters pssParams)
    {
        byte[] fixedSalt = pssParams.getSalt();

        if (fixedSalt != null)
        {
            return new PSSSigner(new RsaBlindedEngine(), FipsSHS.createDigest(pssParams.getDigestAlgorithm()), FipsSHS.createDigest(pssParams.getMGFDigest()), fixedSalt, pssParams.getTrailer());
        }
        else
        {
            return new PSSSigner(new RsaBlindedEngine(), FipsSHS.createDigest(pssParams.getDigestAlgorithm()), FipsSHS.createDigest(pssParams.getMGFDigest()), pssParams.getSaltLength(), pssParams.getTrailer());
        }
    }

    /**
     * Factory for creating RSA key wrap/unwrap operators.
     */
    public static final class KeyWrapOperatorFactory
        extends FipsKeyWrapOperatorFactory<WrapParameters, AsymmetricRSAKey>
    {
        @Override
        public FipsKeyWrapperUsingSecureRandom<WrapParameters> createKeyWrapper(AsymmetricRSAKey key, WrapParameters parameters)
        {
            return new KeyWrapper(key, parameters, null);
        }

        @Override
        public FipsKeyUnwrapperUsingSecureRandom<WrapParameters> createKeyUnwrapper(AsymmetricRSAKey key, WrapParameters parameters)
        {
            return new KeyUnwrapper(key, parameters, null);
        }

        private class KeyWrapper
            extends FipsKeyWrapperUsingSecureRandom<WrapParameters>
        {
            private final AsymmetricBlockCipher keyWrapper;
            private final AsymmetricRSAKey key;
            private final WrapParameters parameters;

            public KeyWrapper(AsymmetricRSAKey key, WrapParameters parameters, SecureRandom random)
            {
                // FSM_STATE:5.13,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
                // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
                if (!key.canBeUsed(AsymmetricRSAKey.Usage.ENCRYPT_OR_DECRYPT))
                {
                    // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
                    throw new IllegalKeyException("Attempt to encrypt/decrypt with RSA modulus already used for sign/verify.");
                }
                // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

                this.key = key;
                this.parameters = parameters;

                if (random != null)
                {
                    keyWrapper = createCipher(true, key, parameters, random);
                }
                else
                {
                    keyWrapper = null;
                }
            }

            public WrapParameters getParameters()
            {
                return parameters;
            }

            public byte[] wrap(byte[] in, int inOff, int inLen)
                throws PlainInputProcessingException
            {
                if (keyWrapper == null)
                {
                    throw new IllegalStateException("KeyWrapper requires a SecureRandom");
                }

                try
                {
                    return keyWrapper.processBlock(in, inOff, inLen);
                }
                catch (Exception e)
                {
                    throw new PlainInputProcessingException("Unable to wrap key: " + e.getMessage(), e);
                }
            }

            public KeyWrapperUsingSecureRandom<WrapParameters> withSecureRandom(SecureRandom random)
            {
                return new KeyWrapper(this.key, this.parameters, random);
            }
        }

        private class KeyUnwrapper
            extends FipsKeyUnwrapperUsingSecureRandom<WrapParameters>
        {
            private final AsymmetricBlockCipher keyWrapper;
            private final AsymmetricRSAKey key;
            private final WrapParameters parameters;

            public KeyUnwrapper(AsymmetricRSAKey key, WrapParameters parameters, SecureRandom random)
            {
                // FSM_STATE:5.14,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
                // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
                if (!key.canBeUsed(AsymmetricRSAKey.Usage.ENCRYPT_OR_DECRYPT))
                {
                    // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
                    throw new IllegalKeyException("Attempt to encrypt/decrypt with RSA modulus already used for sign/verify.");
                }
                // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

                this.key = key;
                this.parameters = parameters;

                if (random != null)
                {
                    keyWrapper = createCipher(false, key, parameters, random);
                }
                else
                {
                    keyWrapper = null;
                }
            }

            public WrapParameters getParameters()
            {
                return parameters;
            }

            public byte[] unwrap(byte[] in, int inOff, int inLen)
                throws InvalidWrappingException
            {
                if (keyWrapper == null)
                {
                    throw new IllegalStateException("KeyUnwrapper requires a SecureRandom");
                }

                try
                {
                    return keyWrapper.processBlock(in, inOff, inLen);
                }
                catch (Exception e)
                {
                    throw new InvalidWrappingException("Unable to unwrap key: " + e.getMessage(), e);
                }
            }

            public FipsKeyUnwrapperUsingSecureRandom<WrapParameters> withSecureRandom(SecureRandom random)
            {
                return new KeyUnwrapper(this.key, this.parameters, random);
            }
        }
    }

    /**
     * Base class for parameters used with RSA based key transport algorithms.
     */
    public static class KTSParameters
        extends FipsParameters
    {
        KTSParameters(FipsAlgorithm algorithm)
        {
            super(algorithm);
        }
    }

    /**
     * Parameters for RSA based key transport using SVE.
     */
    public static final class SVEKTSParameters
        extends KTSParameters
    {
        public SVEKTSParameters()
        {
            super(ALGORITHM_SVE);
        }
    }

    /**
     * Parameters for RSA based key transport using OAEP.
     */
    public static final class OAEPKTSParameters
        extends KTSParameters
    {
        private final OAEPParameters oaepParameters;
        private final int keySizeInBits;
        private final int macKeySizeInBits;

        OAEPKTSParameters(OAEPParameters oaepParameters, int keySizeInBits)
        {
            this(oaepParameters, keySizeInBits, 0);
        }

        private OAEPKTSParameters(OAEPParameters oaepParameters, int keySizeInBits, int macKeySizeInBits)
        {
            super(ALGORITHM_OAEP);
            this.oaepParameters = oaepParameters;
            this.keySizeInBits = keySizeInBits;
            this.macKeySizeInBits = macKeySizeInBits;
        }

        /**
         * Specify the OAEP parameters to use during the transport step.
         *
         * @param oaepParameters the OAEP parameters to use.
         * @return a new parameter set.
         */
        public OAEPKTSParameters withOAEPParameters(OAEPParameters oaepParameters)
        {
            return new OAEPKTSParameters(oaepParameters, keySizeInBits, macKeySizeInBits);
        }

        /**
         * Specify a size for the key material to be transported.
         *
         * @param keySizeInBits the size of the key to be transported.
         * @return a new parameter set.
         */
        public OAEPKTSParameters withKeySizeInBits(int keySizeInBits)
        {
            return new OAEPKTSParameters(oaepParameters, keySizeInBits, macKeySizeInBits);
        }

        /**
         * Specify a size for a MAC key to be used for the key confirmation step.
         *
         * @param macKeySizeInBits the size of the MAC key to use.
         * @return a new parameter set.
         */
        public OAEPKTSParameters withMacKeySizeInBits(int macKeySizeInBits)
        {
            return new OAEPKTSParameters(oaepParameters, keySizeInBits, macKeySizeInBits);
        }

        public OAEPParameters getOAEPParameters()
        {
            return oaepParameters;
        }

        public int getKeySizeInBits()
        {
            return keySizeInBits;
        }

        public int getMacKeySizeInBits()
        {
            return macKeySizeInBits;
        }
    }

    /**
     * Factory for producing key transport operators based on RSA.
     */
    public static class KTSOperatorFactory
        extends FipsKTSOperatorFactory<KTSParameters>
    {
        private final SecureRandom random;

        public KTSOperatorFactory(SecureRandom random)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                Utils.validateRandom(random, "Attempt to create KTSOperatorFactory with unapproved RNG");
            }

            this.random = random;
        }

        public FipsEncapsulatingSecretGenerator<KTSParameters> createGenerator(Key key, KTSParameters parameters)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                Utils.validateRandom(random, parameters.getAlgorithm(), "Attempt to create generator with unapproved RNG");
            }

            return new GeneratorImpl((AsymmetricRSAPublicKey)key, parameters, random);
        }

        public FipsEncapsulatedSecretExtractor<KTSParameters> createExtractor(Key key, final KTSParameters parameters)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                Utils.validateRandom(random, parameters.getAlgorithm(), "Attempt to create extractor with unapproved RNG");
            }

            final AsymmetricRSAPrivateKey privKey = (AsymmetricRSAPrivateKey)key;

            return new ExtractorImpl(privKey, parameters, random);
        }
    }

    private static class GeneratorImpl
        extends FipsEncapsulatingSecretGenerator<KTSParameters>
    {
        private static final BigInteger TWO = BigInteger.valueOf(2);

        private final RsaKeyParameters pubKey;
        private final KTSParameters parameters;
        private final SecureRandom random;

        GeneratorImpl(AsymmetricRSAPublicKey pubKey, KTSParameters parameters, SecureRandom random)
        {
            // FSM_STATE:5.13,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
            // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
            if (!pubKey.canBeUsed(AsymmetricRSAKey.Usage.ENCRYPT_OR_DECRYPT))
            {
                // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
                throw new IllegalKeyException("Attempt to encrypt/decrypt with RSA modulus already used for sign/verify.");
            }
            // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

            this.pubKey = new RsaKeyParameters(false, pubKey.getModulus(), pubKey.getPublicExponent());
            this.parameters = parameters;
            this.random = random;
        }

        // only used for KAT.
        GeneratorImpl(RsaKeyParameters pubKey, KTSParameters parameters, SecureRandom random)
        {
            this.pubKey = pubKey;
            this.parameters = parameters;
            this.random = random;
        }

        public EncapsulatingSecretGenerator<KTSParameters> withSecureRandom(SecureRandom random)
        {
            return new GeneratorImpl(this.pubKey, this.parameters, random);
        }

        public KTSParameters getParameters()
        {
            return parameters;
        }

        public SecretWithEncapsulation generate()
            throws PlainInputProcessingException
        {
            return doGeneration(ENGINE_PROVIDER.createEngine());
        }

        SecretWithEncapsulation doGeneration(AsymmetricBlockCipher rsaEngine)
            throws PlainInputProcessingException
        {
            AsymmetricBlockCipher ktsEngine;
            byte[] secret;

            if (parameters.getAlgorithm() == ALGORITHM_SVE)
            {
                ktsEngine = rsaEngine;

                int nLen = (pubKey.getModulus().bitLength() + 7) / 8;
                BigInteger z = BigIntegers.createRandomInRange(TWO, pubKey.getModulus().subtract(TWO), random);
                secret = BigIntegers.asUnsignedByteArray(nLen, z);

                ktsEngine.init(true, new ParametersWithRandom(pubKey, random));
            }
            else
            {
                OAEPKTSParameters oeapKtsParams = (OAEPKTSParameters)parameters;
                OAEPParameters oeapParams = oeapKtsParams.oaepParameters;
                ktsEngine = new OAEPEncoding(rsaEngine, FipsSHS.createDigest(oeapParams.digestAlgorithm), FipsSHS.createDigest(oeapParams.mgfDigestAlgorithm), oeapParams.encodingParams);

                ktsEngine.init(true, new ParametersWithRandom(pubKey, random));

                int keyDataSize = ((oeapKtsParams.getKeySizeInBits() + 7) / 8) + ((oeapKtsParams.getMacKeySizeInBits() + 7) / 8);
                if (keyDataSize > ktsEngine.getInputBlockSize())
                {
                    throw new IllegalArgumentException("Key material size too large for cipher");
                }

                secret = new byte[keyDataSize];
                random.nextBytes(secret);
            }

            try
            {
                return new SecretWithEncapsulationImpl(secret, ktsEngine.processBlock(secret, 0, secret.length));
            }
            catch (Exception e)
            {
                throw new PlainInputProcessingException("Unable to wrap secret: " + e.getMessage(), e);
            }
        }
    }

    private static class ExtractorImpl
        extends FipsEncapsulatedSecretExtractor<KTSParameters>
    {
        private final AsymmetricRSAPrivateKey privKey;
        private final KTSParameters parameters;
        private final SecureRandom random;

        ExtractorImpl(AsymmetricRSAPrivateKey privKey, KTSParameters parameters, SecureRandom random)
        {
            // FSM_STATE:5.13,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
            // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
            if (!privKey.canBeUsed(AsymmetricRSAKey.Usage.ENCRYPT_OR_DECRYPT))
            {
                // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
                throw new IllegalKeyException("Attempt to encrypt/decrypt with RSA modulus already used for sign/verify.");
            }
            // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

            this.privKey = privKey;
            this.parameters = parameters;
            this.random = random;
        }

        public KTSParameters getParameters()
        {
            return parameters;
        }

        public SecretWithEncapsulation extractSecret(byte[] encapsulation, int offset, int length)
            throws InvalidCipherTextException
        {
            return doExtraction(getPrivateKeyParameters(privKey), ENGINE_PROVIDER.createEngine(), encapsulation, offset, length);
        }

        private SecretWithEncapsulation doExtraction(RsaKeyParameters privKeyParams, AsymmetricBlockCipher rsaEngine, byte[] encapsulation, int offset, int length)
            throws InvalidCipherTextException
        {
            AsymmetricBlockCipher ktsEngine;

            if (parameters.getAlgorithm() == ALGORITHM_SVE)
            {
                ktsEngine = rsaEngine;
            }
            else
            {
                OAEPKTSParameters oeapKtsParams = (OAEPKTSParameters)parameters;
                OAEPParameters oeapParams = oeapKtsParams.oaepParameters;
                ktsEngine = new OAEPEncoding(rsaEngine, FipsSHS.createDigest(oeapParams.digestAlgorithm), FipsSHS.createDigest(oeapParams.mgfDigestAlgorithm), oeapParams.encodingParams);
            }

            ktsEngine.init(false, new ParametersWithRandom(privKeyParams, random));

            try
            {
                byte[] secret = ktsEngine.processBlock(encapsulation, offset, length);
                if (parameters.getAlgorithm() == ALGORITHM_SVE)
                {
                    int nLen = (privKey.getModulus().bitLength() + 7) / 8;

                    secret = correctedExtract(nLen, secret);
                }

                return new SecretWithEncapsulationImpl(secret, Arrays.copyOfRange(encapsulation, offset, offset + length));
            }
            catch (org.bouncycastle.crypto.internal.InvalidCipherTextException e)
            {
                throw new InvalidCipherTextException("Unable to extract secret: " + e.getMessage(), e);
            }
        }

        private byte[] correctedExtract(int nLen, byte[] value)
        {
            if (value.length < nLen)
            {
                byte[] tmp = new byte[nLen];

                System.arraycopy(value, 0, tmp, tmp.length - value.length, value.length);

                Arrays.fill(value, (byte)0);

                return tmp;
            }

            return value;
        }
    }

    private static AsymmetricBlockCipher createCipher(boolean forEncryption, AsymmetricRSAKey key, WrapParameters parameters, SecureRandom random)
    {
        AsymmetricBlockCipher engine = ENGINE_PROVIDER.createEngine();

        CipherParameters params;

        // FSM_STATE:5.13,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
        // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
        if (!key.canBeUsed(AsymmetricRSAKey.Usage.ENCRYPT_OR_DECRYPT))
        {
            // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
            throw new IllegalKeyException("Attempt to encrypt/decrypt with RSA modulus already used for sign/verify.");
        }
        // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

        if (key instanceof AsymmetricRSAPublicKey)
        {
            AsymmetricRSAPublicKey k = (AsymmetricRSAPublicKey)key;

            params = new RsaKeyParameters(false, k.getModulus(), k.getPublicExponent());
        }
        else
        {
            AsymmetricRSAPrivateKey k = (AsymmetricRSAPrivateKey)key;

            params = getPrivateKeyParameters(k);
        }

        if (parameters.getAlgorithm().equals(ALGORITHM_OAEP))
        {
            OAEPParameters oeapParams = (OAEPParameters)parameters;
            engine = new OAEPEncoding(engine, FipsSHS.createDigest(oeapParams.digestAlgorithm), FipsSHS.createDigest(oeapParams.mgfDigestAlgorithm), oeapParams.encodingParams);
        }
        else if (parameters.getAlgorithm().equals(ALGORITHM_PKCS1v1_5))
        {
            final AsymmetricBlockCipher baseEngine = engine;
            engine = AccessController.doPrivileged(new PrivilegedAction<PKCS1Encoding>()
            {
                public PKCS1Encoding run()
                {
                    if (CryptoServicesRegistrar.isInApprovedOnlyMode())
                    {
                        Utils.checkPermission(Permissions.TlsPKCS15KeyWrapEnabled);
                    }

                    return new PKCS1Encoding(baseEngine);
                }
            });
        }

        params = new ParametersWithRandom(params, random);

        engine.init(forEncryption, params);

        return engine;
    }

    private static RsaKeyParameters getPrivateKeyParameters(final AsymmetricRSAPrivateKey k)
    {
        return AccessController.doPrivileged(new PrivilegedAction<RsaKeyParameters>()
        {
            public RsaKeyParameters run()
            {
                if (k.getPublicExponent().equals(BigInteger.ZERO))
                {
                    return new RsaKeyParameters(true, k.getModulus(), k.getPrivateExponent());
                }
                else
                {
                    return new RsaPrivateCrtKeyParameters(k.getModulus(), k.getPublicExponent(), k.getPrivateExponent(), k.getP(), k.getQ(), k.getDP(), k.getDQ(), k.getQInv());
                }
            }
        });
    }


    private static void validateKeyPair(AsymmetricCipherKeyPair kp)
    {
        //
        // we do an encryption rather than a signing test as it covers both options and includes the encryption check.
        //
        SelfTestExecutor.validate(ALGORITHM, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
        {
            public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
            {
                final byte[] data = Hex.decode("576a1f885e3420128c8a656097ba7d8bb4c6f1b1853348cf2ba976971dbdbefc");

                RsaBlindedEngine rsaEngine = new RsaBlindedEngine();

                rsaEngine.init(true, kp.getPublic());

                byte[] encrypted = rsaEngine.processBlock(data, 0, data.length);

                if (Arrays.areEqual(data, encrypted))
                {
                    return false;
                }

                rsaEngine.init(false, new ParametersWithRandom(kp.getPrivate(), Utils.testRandom));

                byte[] decrypted = rsaEngine.processBlock(data, 0, data.length);

                if (Arrays.areEqual(decrypted, data))
                {
                    return false;
                }

                // correct decryption check.
                decrypted = rsaEngine.processBlock(encrypted, 0, encrypted.length);

                return Arrays.areEqual(data, decrypted);
            }
        });
    }

    private static void rsaSignTest(final EngineProvider provider)
    {
        SelfTestExecutor.validate(ALGORITHM, new VariantInternalKatTest(ALGORITHM)
        {
            @Override
            void evaluate()
                throws Exception
            {
                RsaDigestSigner signer = new RsaDigestSigner(provider.createEngine(), FipsSHS.createDigest(FipsSHS.Algorithm.SHA256));

                signer.init(false, new RsaKeyParameters(false, katM, katE));

                signer.update(msg, 0, msg.length);

                if (!signer.verifySignature(pkcs15Sig))
                {
                    fail("Self test signature verify failed.");
                }

                signer.init(true, new ParametersWithRandom(testPrivKey, Utils.testRandom));

                signer.update(msg, 0, msg.length);

                byte[] sig = signer.generateSignature();

                if (!Arrays.areEqual(pkcs15Sig, sig))
                {
                    fail("Self test signature generate failed.");
                }
            }
        });
    }

    private static void rsaKasTest(final EngineProvider provider)
    {
        SelfTestExecutor.validate(ALGORITHM_SVE, new VariantInternalKatTest(ALGORITHM_SVE)
        {
            @Override
            void evaluate()
                throws Exception
            {
                byte[] rngData1 = Hex.decode(
                    "ce4cf74c1caef7e0455f4210" +
                        "e13fde6847f56c939aedfed9d24c2e6a7c661c461b436ade0a9afd6457be92af33c2626b319e060e943561221509" +
                        "9f9369aaca72351dad4dc14a4c418dbe7fd3b273e91d45fa615c15be8d5e0b97b6aca713cbc549ed4ef2d82f5f8e" +
                        "03b0d0d95d6ce7c7695f8bba938746eff19b70d2c2d56fab");

                byte[] rngData2 = Hex.decode(
                    "0051aa809e02ec73545c336b709903f01478e2c6bafde09dda4f6fd2401f64accf95df631b65488724223cb03cb30add" +
                        "f7a5385c7282090fe3a171d915dde703e384b0b9de529ae3a45d8db4f5c2ddb74b550f1b8efc9bb99a6c2c07ff51" +
                        "2a66f307b6ba3e6db67daa2eb7440683b994e67ae574ec8b2e1253cb8b7f6241de19");

                byte[] zVal = Hex.decode(
                    "697140a15ddcb8dc01b7f97d929c20c99f9b1348fa80d67350183e44ca9a90d958758d0299b95fb442338e7c3d359507" +
                        "6f05c51b0152bc8a68a1d0b9eb4077ad716a357f72b10130669eeeb4c7454afe742c14dbcfd469c1f2171b59d2c5" +
                        "b3ebb704157b7df5b8bd68ab15b003355dd3ec033bee5e3d418a8b3dd357d14914143b40b0a6e1900bd1f1bf238f" +
                        "75cbba9a93144bd9ec6ddfe500de2318730d0f55e4ee05cd58201c1993500ff1396a4e66fe868f3eaa8cf09752d4" +
                        "8426da24186e7870e610efecc9dc02f959c258d8bbdbc354d652c68e778bb6e523fcd08677d48afbed4f15af72f8" +
                        "2b870e4d4b658456dea6f581deb9e6d19a9baa0e30f46023");

                GeneratorImpl genImp = new GeneratorImpl(new RsaKeyParameters(false, katM, katE), new KTSParameters(ALGORITHM_SVE),
                    new FixedSecureRandom(
                        new FixedSecureRandom.BigInteger(2048, zVal),
                        new FixedSecureRandom.Data(rngData1)));

                SecretWithEncapsulation secWithEnc = genImp.doGeneration(provider.createEngine());

                byte[] encapsulation = secWithEnc.getEncapsulation();

                if (!Arrays.areEqual(Hex.decode("2dc23f549cedbc83b5efa8c0c666010ea8d59d8c860a473f6f32347b53a7a62b47a6" +
                    "3b3f306f03b648aec8defa00414d3a24f422384decd3f147967789f5e7e79a927ec59398f3397d3e930489adbd3f213c" +
                    "ebfc29715771f30f38335c4ac6dc8632e0be5649a881d551f9a883925be2f5aed67a09ea8257ca832f9240fc345d64b9" +
                    "d3d0522f533fd2f230803516f359376bdd1df899d8fa793cacae1d84c68a974fa554e88e8d182496c502babf4306c055" +
                    "c05b4f6ff4c9af8b74d20bc564bb9b238b9d16309ed20bc290b615d0cfab69dbf49d594fe256e44ad29025c0d811a63e" +
                    "1fe361ea3d106461069d00981a9c013aded45277ef19e1dba7d18a2249b9"), encapsulation))
                {
                    fail("Self test SVE encryption KAT failed.");
                }

                ExtractorImpl extractImp = new ExtractorImpl(new AsymmetricRSAPrivateKey(ALGORITHM_SVE, testPrivKey.getModulus(), testPrivKey.getExponent()), new KTSParameters(ALGORITHM_SVE), Utils.testRandom);
                // use testPrivKey to avoid permissions issue if SecurityManager involved.
                byte[] agreedValue = extractImp.doExtraction(testPrivKey, provider.createEngine(), encapsulation, 0, encapsulation.length).getSecret();
                if (!Arrays.areEqual(zVal, agreedValue))
                {
                    fail("Self test SVE decryption KAT failed.");
                }

                if (!Arrays.areEqual(secWithEnc.getSecret(), agreedValue))
                {
                    fail("Self test SVE failed.");
                }
            }
        });
    }

    private static void rsaKeyTransportTest(final EngineProvider provider)
    {
        SelfTestExecutor.validate(ALGORITHM_OAEP, new VariantInternalKatTest(ALGORITHM_OAEP)
        {
            @Override
            void evaluate()
                throws Exception
            {
                byte[] oaepOut = Hex.decode(
                    "4458cce0f94ebd79d275a134d224f95ef4126034e5d979359703b466096fcc15b71b78df4d4a68033112dfcfad7611cc" +
                        "0458475ab4a66b815f87fcb16a8aa1133441b9d61ed846c4856c5d42059fab7505bd8ffa5281a2bb187c6c853f298c98" +
                        "d5752a40be905f85e5ccb27d59415f09ac12a1788d654c675d98f412e6481e6f1159f1736dd96b29c99b411b4e5420b5" +
                        "6b07be2885dbc397fa091f66877c41e502cb4afeba460a2ebcdec7d09d933e630b98a4510ad6f32ca7ffc1bdb43e46ff" +
                        "f709819d3a69d9b62b774cb12c9dc176a6911bf370ab5029719dc1b4c13e23e57e46a7cd8ba5ee54c954ed460835ddab" +
                        "0086fa36ac110a5790e82c929bc7ca86");

                AsymmetricBlockCipher cipher = new OAEPEncoding(provider.createEngine(), new SHA1Digest());

                cipher.init(true, new ParametersWithRandom(testPubKey, new TestRandomData("18b776ea21069d69776a33e96bad48e1dda0a5ef")));

                byte[] out;

                out = cipher.processBlock(msg, 0, msg.length);

                if (!Arrays.areEqual(oaepOut, out))
                {
                    fail("Self test OAEP transport encrypt failed.");
                }

                cipher.init(false, new ParametersWithRandom(testPrivKey, Utils.testRandom));

                out = cipher.processBlock(oaepOut, 0, oaepOut.length);

                if (!Arrays.areEqual(msg, out))
                {
                    fail("Self test OAEP transport decrypt failed.");
                }
            }
        });
        SelfTestExecutor.validate(ALGORITHM_PKCS1v1_5, new VariantInternalKatTest(ALGORITHM_PKCS1v1_5)
        {
            @Override
            void evaluate()
                throws Exception
            {
                byte[] pkcsOut = Hex.decode(
                    "300603e8d5fdb52e4f9d1dea9cac60ef3500700f03f53b1437fee040ef2713ddd0419b69f5ffe927039998" +
                        "95ea4a111f9bb1333c8d5e115f70a41eb9e4a4ee4d20d7781e0c0765b1b3eb51bd96e9a1715c9be703" +
                        "e3dfa9c4195c001a64239709dfb135921ae6de5960d3e13abdf7cb54580db9922e969a9c4f3a35ac1d" +
                        "5c14958159a0e9259556c19daa793892151370012a215fb7a3d2f8daed098e47e9674edbebeba4bbb6" +
                        "c6b9f37d2bdaa218d0cbc1a70030ccb47f72a25168b0e1ef5a5570920db23f092db0be3dbfbee4babf" +
                        "4bd0e4a1355f45bc9e2a3947ed530d0fc66f77ba4167f16ea12f7ace82950de600ef555fb54bea15be" +
                        "1ec3d93e61af1e97");

                AsymmetricBlockCipher cipher = new PKCS1Encoding(provider.createEngine());

                cipher.init(true, new ParametersWithRandom(testPubKey, new RepeatingRandom()));

                byte[] out = cipher.processBlock(msg, 0, msg.length);

                if (!Arrays.areEqual(pkcsOut, out))
                {
                    fail("Self test PKCS#1.5 transport encrypt failed.");
                }

                cipher.init(false, new ParametersWithRandom(testPrivKey, Utils.testRandom));

                out = cipher.processBlock(pkcsOut, 0, pkcsOut.length);

                if (!Arrays.areEqual(msg, out))
                {
                    fail("Self test PKCS#1.5 transport decrypt failed.");
                }
            }
        });
    }

    private static final class RepeatingRandom
        extends SecureRandom
    {
        RepeatingRandom()
        {
            super(null, new DummyProvider());       // to prevent recursion in provider creation
        }

        public void nextBytes(byte[] bytes)
        {
            for (int i = 0; i != bytes.length; i++)
            {
                bytes[i] = (byte)(i % 255);
            }
        }
    }

    private static class DummyProvider
        extends Provider
    {
        DummyProvider()
        {
            super("FipsRSA_TEST_RNG", 1.0, "BCFIPS FipsRSA Test Provider");
        }
    }

    private static class SecretWithEncapsulationImpl
        implements SecretWithEncapsulation
    {
        private final byte[] secret;
        private final byte[] encapsulation;

        public SecretWithEncapsulationImpl(byte[] secret, byte[] encapsulation)
        {
            this.secret = Arrays.clone(secret);
            this.encapsulation = Arrays.clone(encapsulation);
        }

        public final byte[] getSecret()
        {
            return Arrays.clone(secret);
        }

        public final byte[] getEncapsulation()
        {
            return Arrays.clone(encapsulation);
        }
    }

    private static final class EngineProvider
        extends FipsEngineProvider<AsymmetricBlockCipher>
    {
        private static final BigInteger mod = new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16);
        private static final BigInteger pubExp = new BigInteger("11", 16);
        private static final BigInteger privExp = new BigInteger("92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619", 16);
        private static final BigInteger p = new BigInteger("f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03", 16);
        private static final BigInteger q = new BigInteger("b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947", 16);
        private static final BigInteger pExp = new BigInteger("1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5", 16);
        private static final BigInteger qExp = new BigInteger("6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded", 16);
        private static final BigInteger crtCoef = new BigInteger("dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926d070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339", 16);

        //
        // to check that we handling byte extension by big number correctly.
        //
        private static final byte[] edgeInput = Hex.decode("ff6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e");
        private static final byte[] edgeOutput = Hex.decode("576a1f885e3420128c8a656097ba7d8bb4c6f1b1853348cf2ba976971dbdbefc3497a9fb17ba03d95f28fad91247d6f8ebc463fa8ada974f0f4e28961565a73a46a465369e0798ccbf7893cb9afaa7c426cc4fea6f429e67b6205b682a9831337f2548fd165c2dd7bf5b54be5894403d6e9f6283e65fb134cd4687bf86f95e7a");

        public AsymmetricBlockCipher createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new RsaBlindedEngine(), new VariantKatTest<RsaBlindedEngine>()
            {
                @Override
                void evaluate(RsaBlindedEngine rsaEngine)
                    throws Exception
                {
                    RsaKeyParameters pubParameters = new RsaKeyParameters(false, mod, pubExp);
                    RsaKeyParameters privParameters = new RsaPrivateCrtKeyParameters(mod, pubExp, privExp, p, q, pExp, qExp, crtCoef);
                    byte[] data = edgeInput;

                    rsaEngine.init(true, new ParametersWithRandom(pubParameters, Utils.testRandom));

                    try
                    {
                        data = rsaEngine.processBlock(data, 0, data.length);
                    }
                    catch (Exception e)
                    {
                        fail("Self test failed: exception " + e.toString());
                    }

                    if (!Arrays.areEqual(edgeOutput, data))
                    {
                        fail("Self test failed: input does not match decrypted output");
                    }

                    rsaEngine.init(false, new ParametersWithRandom(privParameters, Utils.testRandom));

                    try
                    {
                        data = rsaEngine.processBlock(data, 0, data.length);
                    }
                    catch (Exception e)
                    {
                        fail("Self test failed: exception " + e.toString());
                    }

                    if (!Arrays.areEqual(edgeInput, data))
                    {
                        fail("Self test failed: input does not match decrypted output");
                    }
                }
            });
        }
    }

    private static class NullSigner
        implements Signer
    {
        AsymmetricBlockCipher engine = new PKCS1Encoding(ENGINE_PROVIDER.createEngine());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        public void init(boolean forSigning, CipherParameters param)
        {
            engine.init(forSigning, param);
        }

        public void update(byte b)
        {
            bOut.write(b);
        }

        public void update(byte[] in, int off, int len)
        {
            bOut.write(in, off, len);
        }

        public byte[] generateSignature()
            throws CryptoException, DataLengthException
        {
            byte[] data = bOut.toByteArray();

            bOut.reset();

            return engine.processBlock(data, 0, data.length);
        }

        public boolean verifySignature(byte[] signature)
            throws InvalidSignatureException
        {
            byte[] input = bOut.toByteArray();

            bOut.reset();

            try
            {
                byte[] sig = engine.processBlock(signature, 0, signature.length);
 
                return BaseRsaDigestSigner.checkPKCS1Sig(input, sig);
            }
            catch (org.bouncycastle.crypto.internal.InvalidCipherTextException e)
            {
                throw new InvalidSignatureException("Unable to process signature: " + e.getMessage(), e);
            }
        }

        public void reset()
        {
            bOut = new ByteArrayOutputStream();
        }
    }
}
