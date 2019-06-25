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
import org.bouncycastle.crypto.asymmetric.AsymmetricECGOST3410PrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricECGOST3410PublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.GOST3410Parameters;
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
 * Source class for implementations of ECGOST3410 based algorithms.
 */
public final class ECGOST3410
{
    private ECGOST3410()
    {
    }

    private enum Variations
    {
        ECGOST3410
    }

    /**
     * Basic EC GOST 3410 key marker, can be used for creating general purpose EC GOST 3410 keys.
     */
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("ECGOST3410", Variations.ECGOST3410);

    /**
     * EC GOST GOST3410 algorithm parameter source - default is GOST-3411
     */
    public static final SignatureParameters GOST3410 = new SignatureParameters();

    /**
     * ECGOST3410 key pair generation parameters.
     */
    public static final class KeyGenParameters
        extends GeneralParameters
    {
        private final GOST3410Parameters<ECDomainParameters> domainParameters;

        public KeyGenParameters(GOST3410Parameters<ECDomainParameters> domainParameters)
        {
            super(ALGORITHM);
            this.domainParameters = domainParameters;
        }


        public GOST3410Parameters<ECDomainParameters> getDomainParameters()
        {
            return domainParameters;
        }
    }

    /**
     * ECGOST3410 key pair generator class.
     */
    public static final class KeyPairGenerator
        extends GuardedAsymmetricKeyPairGenerator<KeyGenParameters, AsymmetricECGOST3410PublicKey, AsymmetricECGOST3410PrivateKey>
    {
        private final EcKeyPairGenerator engine = new EcKeyPairGenerator();
        private final GOST3410Parameters<ECDomainParameters> parameters;
        private final EcKeyGenerationParameters param;

        public KeyPairGenerator(KeyGenParameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            this.parameters = keyGenParameters.getDomainParameters();

            this.param = new EcKeyGenerationParameters(getDomainParams(this.parameters.getDomainParameters()), random);
            this.engine.init(param);
        }

        @Override
        protected AsymmetricKeyPair<AsymmetricECGOST3410PublicKey, AsymmetricECGOST3410PrivateKey> doGenerateKeyPair()
        {
            AsymmetricCipherKeyPair kp = engine.generateKeyPair();

            validateKeyPair(kp);

            EcPublicKeyParameters pubKey = (EcPublicKeyParameters)kp.getPublic();
            EcPrivateKeyParameters prvKey = (EcPrivateKeyParameters)kp.getPrivate();

            Algorithm algorithm = this.getParameters().getAlgorithm();

            return new AsymmetricKeyPair<AsymmetricECGOST3410PublicKey, AsymmetricECGOST3410PrivateKey>(new AsymmetricECGOST3410PublicKey(algorithm, parameters, pubKey.getQ()), new AsymmetricECGOST3410PrivateKey(algorithm, parameters, prvKey.getD()));
        }
    }

    /**
     * Parameters for ECGOST3410 signatures.
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
     * Operator factory for creating ECGOST3410 based signing and verification operators.
     */
    public static final class SignatureOperatorFactory
        extends GuardedSignatureOperatorFactory<SignatureParameters>
    {
        @Override
        public OutputSignerUsingSecureRandom<SignatureParameters> doCreateSigner(AsymmetricPrivateKey key, final SignatureParameters parameters)
        {
            final org.bouncycastle.crypto.internal.DSA gost3410Signer = new EcGost3410Signer();
            final Digest digest = Register.createDigest(parameters.getDigestAlgorithm());

            AsymmetricECGOST3410PrivateKey k = (AsymmetricECGOST3410PrivateKey)key;

            final EcPrivateKeyParameters privateKeyParameters = getLwKey(k);

            return new DSAOutputSigner<SignatureParameters>(gost3410Signer, digest, parameters, new DSAOutputSigner.Initializer()
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
            final org.bouncycastle.crypto.internal.DSA gost3410Signer = new EcGost3410Signer();
            final Digest digest = Register.createDigest(parameters.getDigestAlgorithm());

            AsymmetricECGOST3410PublicKey k = (AsymmetricECGOST3410PublicKey)key;

            EcPublicKeyParameters publicKeyParameters = new EcPublicKeyParameters(k.getW(), getDomainParams(k.getParameters().getDomainParameters()));

            gost3410Signer.init(false, publicKeyParameters);

            return new DSAOutputVerifier<SignatureParameters>(gost3410Signer, digest, parameters);
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

    private static EcPrivateKeyParameters getLwKey(final AsymmetricECGOST3410PrivateKey privKey)
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

                EcGost3410Signer signer = new EcGost3410Signer();

                signer.init(true, new ParametersWithRandom(kp.getPrivate(), Utils.testRandom));

                BigInteger[] rv = signer.generateSignature(data);

                signer.init(false, kp.getPublic());

                signer.verifySignature(data, rv[0], rv[1]);

                return signer.verifySignature(data, rv[0], rv[1]);
            }
        });
    }
}
