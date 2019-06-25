package org.bouncycastle.crypto.general;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.OutputSignerUsingSecureRandom;
import org.bouncycastle.crypto.OutputVerifier;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSTU4145PrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSTU4145PublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.DSTU4145Parameters;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.NamedECDomainParameters;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.params.EcDomainParameters;
import org.bouncycastle.crypto.internal.params.EcNamedDomainParameters;
import org.bouncycastle.crypto.internal.params.EcPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.EcPublicKeyParameters;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.crypto.internal.test.ConsistencyTest;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for implementations of DSTU4145 based algorithms.
 */
public final class DSTU4145
{
    private DSTU4145()
    {

    }

    private enum Variations
    {
        DSTU4145
    }

    private static byte[] DEFAULT_SBOX = {
        0xa, 0x9, 0xd, 0x6, 0xe, 0xb, 0x4, 0x5, 0xf, 0x1, 0x3, 0xc, 0x7, 0x0, 0x8, 0x2,
        0x8, 0x0, 0xc, 0x4, 0x9, 0x6, 0x7, 0xb, 0x2, 0x3, 0x1, 0xf, 0x5, 0xe, 0xa, 0xd,
        0xf, 0x6, 0x5, 0x8, 0xe, 0xb, 0xa, 0x4, 0xc, 0x0, 0x3, 0x7, 0x2, 0x9, 0x1, 0xd,
        0x3, 0x8, 0xd, 0x9, 0x6, 0xb, 0xf, 0x0, 0x2, 0x5, 0xc, 0xa, 0x4, 0xe, 0x1, 0x7,
        0xf, 0x8, 0xe, 0x9, 0x7, 0x2, 0x0, 0xd, 0xc, 0x6, 0x1, 0x5, 0xb, 0x4, 0x3, 0xa,
        0x2, 0x8, 0x9, 0x7, 0x5, 0xf, 0x0, 0xb, 0xc, 0x1, 0xd, 0xe, 0xa, 0x3, 0x6, 0x4,
        0x3, 0x8, 0xb, 0x5, 0x6, 0x4, 0xe, 0xa, 0x2, 0xc, 0x1, 0x7, 0x9, 0xf, 0xd, 0x0,
        0x1, 0x2, 0x3, 0xe, 0x6, 0xd, 0xb, 0x8, 0xf, 0xa, 0xc, 0x5, 0x7, 0x9, 0x0, 0x4
    };

    /**
     * Basic DSTU-4145 key marker, can be used for creating general purpose DSTU-4145 keys.
     */
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("DSTU4145", Variations.DSTU4145);

    /**
     * DSTU-4145 algorithm parameter source - default is GOST-3411
     */
    public static final SignatureParameters DSTU4145 = new SignatureParameters();

    /**
     * DSTU4145 key pair generation parameters.
     */
    public static final class KeyGenParameters
        extends GeneralParameters
    {
        private final DSTU4145Parameters domainParameters;

        public KeyGenParameters(DSTU4145Parameters domainParameters)
        {
            super(ALGORITHM);
            this.domainParameters = domainParameters;
        }

        public DSTU4145Parameters getDomainParameters()
        {
            return domainParameters;
        }
    }

    /**
     * DSTU4145 key pair generator class.
     */
    public static final class KeyPairGenerator
        extends GuardedAsymmetricKeyPairGenerator<KeyGenParameters, AsymmetricDSTU4145PublicKey, AsymmetricDSTU4145PrivateKey>
    {
        private final EcKeyPairGenerator engine = new DSTU4145KeyPairGenerator();
        private final DSTU4145Parameters parameters;
        private final EcKeyGenerationParameters param;

        public KeyPairGenerator(KeyGenParameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            this.parameters = keyGenParameters.getDomainParameters();

            this.param = new EcKeyGenerationParameters(getDomainParams(this.parameters.getDomainParameters()), random);
            this.engine.init(param);
        }

        @Override
        protected AsymmetricKeyPair<AsymmetricDSTU4145PublicKey, AsymmetricDSTU4145PrivateKey> doGenerateKeyPair()
        {
            AsymmetricCipherKeyPair kp = engine.generateKeyPair();

            validateKeyPair(kp);

            EcPublicKeyParameters pubKey = (EcPublicKeyParameters)kp.getPublic();
            EcPrivateKeyParameters prvKey = (EcPrivateKeyParameters)kp.getPrivate();

            Algorithm algorithm = this.getParameters().getAlgorithm();

            return new AsymmetricKeyPair<AsymmetricDSTU4145PublicKey, AsymmetricDSTU4145PrivateKey>(new AsymmetricDSTU4145PublicKey(algorithm, parameters, pubKey.getQ()), new AsymmetricDSTU4145PrivateKey(algorithm, parameters, prvKey.getD()));
        }
    }

    /**
     * Parameters for DSTU4145 signatures.
     */
    public static final class SignatureParameters
        extends GeneralParameters
    {
        private final DigestAlgorithm digestAlgorithm;

        SignatureParameters()
        {
            this(SecureHash.Algorithm.GOST3411);
        }

        private SignatureParameters(DigestAlgorithm digestAlgorithm)
        {
            super(ALGORITHM);
            this.digestAlgorithm = digestAlgorithm;
        }

        /**
         * Return the algorithm for the underlying digest these parameters will use.
         *
         * @return the digest algorithm
         */
        public DigestAlgorithm getDigestAlgorithm()
        {
            return digestAlgorithm;
        }

        /**
         * Return a new parameter set with for the passed in digest algorithm.
         *
         * @param digestAlgorithm the digest to use for signature generation.
         * @return a new parameter for signature generation.
         */
        public SignatureParameters withDigestAlgorithm(DigestAlgorithm digestAlgorithm)
        {
            return new SignatureParameters(digestAlgorithm);
        }
    }

    /**
     * Operator factory for creating DSTU4145 based signing and verification operators.
     */
    public static final class SignatureOperatorFactory
        extends GuardedSignatureOperatorFactory<SignatureParameters>
    {
        @Override
        public OutputSignerUsingSecureRandom<SignatureParameters> doCreateSigner(AsymmetricPrivateKey key, final SignatureParameters parameters)
        {
            final org.bouncycastle.crypto.internal.DSA dstu4145Signer = new DSTU4145Signer();
            final Digest digest = parameters.digestAlgorithm == SecureHash.Algorithm.GOST3411 ? new GOST3411Digest(DEFAULT_SBOX) : Register.createDigest(parameters.getDigestAlgorithm());

            AsymmetricDSTU4145PrivateKey k = (AsymmetricDSTU4145PrivateKey)key;

            final EcPrivateKeyParameters privateKeyParameters = new EcPrivateKeyParameters(k.getS(), getDomainParams(k.getParameters().getDomainParameters()));

            return new DSAOutputSigner<SignatureParameters>(dstu4145Signer, digest, parameters, new DSAOutputSigner.Initializer()
            {
                public void initialize(org.bouncycastle.crypto.internal.DSA signer, SecureRandom random)
                {
                    signer.init(true, new ParametersWithRandom(privateKeyParameters, random));
                }
            });
        }

        @Override
        public OutputVerifier<SignatureParameters> doCreateVerifier(AsymmetricPublicKey key, final SignatureParameters parameters)
        {
            final org.bouncycastle.crypto.internal.DSA dstu4145Signer = new DSTU4145Signer();
            final Digest digest = parameters.digestAlgorithm == SecureHash.Algorithm.GOST3411 ? new GOST3411Digest(DEFAULT_SBOX) : Register.createDigest(parameters.getDigestAlgorithm());

            AsymmetricDSTU4145PublicKey k = (AsymmetricDSTU4145PublicKey)key;

            EcPublicKeyParameters publicKeyParameters = new EcPublicKeyParameters(k.getW(), getDomainParams(k.getParameters().getDomainParameters()));

            dstu4145Signer.init(false, publicKeyParameters);

            return new DSAOutputVerifier<SignatureParameters>(dstu4145Signer, digest, parameters);
        }
    }

    /**
     * Operator factory for creating little-endian format DSTU4145 based signing and verification operators.
     */
    public static final class LittleEndianSignatureOperatorFactory
        extends GuardedSignatureOperatorFactory<SignatureParameters>
    {
        @Override
        public OutputSignerUsingSecureRandom<SignatureParameters> doCreateSigner(AsymmetricPrivateKey key, final SignatureParameters parameters)
        {
            final org.bouncycastle.crypto.internal.DSA dstu4145Signer = new DSTU4145Signer();
            final Digest digest = parameters.digestAlgorithm == SecureHash.Algorithm.GOST3411 ? new GOST3411Digest(DEFAULT_SBOX) : Register.createDigest(parameters.getDigestAlgorithm());

            AsymmetricDSTU4145PrivateKey k = (AsymmetricDSTU4145PrivateKey)key;

            final EcPrivateKeyParameters privateKeyParameters = getLwKey(k);

            return new DSAOutputSigner<SignatureParameters>(dstu4145Signer, digest, parameters, new DSAOutputSigner.Initializer()
            {
                public void initialize(org.bouncycastle.crypto.internal.DSA signer, SecureRandom random)
                {
                    signer.init(true, new ParametersWithRandom(privateKeyParameters, random));
                }
            }, true);
        }

        @Override
        public OutputVerifier<SignatureParameters> doCreateVerifier(AsymmetricPublicKey key, final SignatureParameters parameters)
        {
            final org.bouncycastle.crypto.internal.DSA dstu4145Signer = new DSTU4145Signer();
            final Digest digest = parameters.digestAlgorithm == SecureHash.Algorithm.GOST3411 ? new GOST3411Digest(DEFAULT_SBOX) : Register.createDigest(parameters.getDigestAlgorithm());

            AsymmetricDSTU4145PublicKey k = (AsymmetricDSTU4145PublicKey)key;

            EcPublicKeyParameters publicKeyParameters = new EcPublicKeyParameters(k.getW(), getDomainParams(k.getParameters().getDomainParameters()));

            dstu4145Signer.init(false, publicKeyParameters);

            return new DSAOutputVerifier<SignatureParameters>(dstu4145Signer, digest, parameters, true);
        }
    }

    private static EcDomainParameters getDomainParams(ECDomainParameters curveParams)
    {
        if (curveParams instanceof NamedECDomainParameters)
        {
            return new EcNamedDomainParameters(((NamedECDomainParameters)curveParams).getID(), curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH(), curveParams.getSeed());
        }
        return new EcDomainParameters(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH(), curveParams.getSeed());
    }

    private static EcPrivateKeyParameters getLwKey(final AsymmetricDSTU4145PrivateKey privKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<EcPrivateKeyParameters>()
        {
            public EcPrivateKeyParameters run()
            {
                return new EcPrivateKeyParameters(privKey.getS(), getDomainParams(privKey.getParameters().getDomainParameters()));
            }
        });
    }

    private static void validateKeyPair(AsymmetricCipherKeyPair kp)
    {
        SelfTestExecutor.validate(ALGORITHM, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
        {
            public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
            {
                final byte[] data = Hex.decode("576a1f885e3420128c8a656097ba7d8bb4c6f1b1853348cf2ba976971dbdbefc");

                DSTU4145Signer signer = new DSTU4145Signer();

                signer.init(true, new ParametersWithRandom(kp.getPrivate(), Utils.testRandom));

                BigInteger[] rv = signer.generateSignature(data);

                signer.init(false, kp.getPublic());

                signer.verifySignature(data, rv[0], rv[1]);

                return signer.verifySignature(data, rv[0], rv[1]);
            }
        });
    }
}
