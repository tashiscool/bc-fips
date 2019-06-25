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
import org.bouncycastle.crypto.asymmetric.AsymmetricGOST3410PrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricGOST3410PublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.GOST3410DomainParameters;
import org.bouncycastle.crypto.asymmetric.GOST3410Parameters;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.DSA;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.crypto.internal.test.ConsistencyTest;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for implementations of GOST3410 based algorithms.
 */
public final class GOST3410
{
    private GOST3410()
    {

    }

    private enum Variations
    {
        GOST3410
    }

    /**
     * Basic GOST-3410 key marker, can be used for creating general purpose GOST-3410 keys.
     */
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("GOST3410", Variations.GOST3410);

    /**
     * EC GOST GOST3410 algorithm parameter source - default is GOST-3411
     */
    public static final SignatureParameters GOST3410 = new SignatureParameters();

    /**
     * GOST3410 key pair generation parameters.
     */
    public static final class KeyGenParameters
         extends GeneralParameters
    {
        private final GOST3410Parameters<GOST3410DomainParameters> domainParameters;

        public KeyGenParameters(GOST3410Parameters<GOST3410DomainParameters> domainParameters)
        {
            super(ALGORITHM);
            this.domainParameters = domainParameters;
        }


        public GOST3410Parameters<GOST3410DomainParameters> getDomainParameters()
        {
            return domainParameters;
        }
    }

    /**
     * Parameters for GOST3410 signatures.
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
     * GOST3410 key pair generator class.
     */
    public static final class KeyPairGenerator
       extends GuardedAsymmetricKeyPairGenerator<KeyGenParameters, AsymmetricGOST3410PublicKey, AsymmetricGOST3410PrivateKey>
    {
        private final Gost3410KeyPairGenerator engine = new Gost3410KeyPairGenerator();
        private final GOST3410Parameters<GOST3410DomainParameters> parameters;
        private final Gost3410KeyGenerationParameters param;

        public KeyPairGenerator(KeyGenParameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            this.parameters = keyGenParameters.getDomainParameters();

            this.param = new Gost3410KeyGenerationParameters(random, getDomainParams(this.parameters));
            this.engine.init(param);
        }

        @Override
        protected AsymmetricKeyPair<AsymmetricGOST3410PublicKey, AsymmetricGOST3410PrivateKey> doGenerateKeyPair()
        {
            AsymmetricCipherKeyPair kp = engine.generateKeyPair();

            validateKeyPair(kp);

            Gost3410PublicKeyParameters pubKey = (Gost3410PublicKeyParameters)kp.getPublic();
            Gost3410PrivateKeyParameters prvKey = (Gost3410PrivateKeyParameters)kp.getPrivate();

            Algorithm algorithm = this.getParameters().getAlgorithm();

            return new AsymmetricKeyPair<AsymmetricGOST3410PublicKey, AsymmetricGOST3410PrivateKey>(new AsymmetricGOST3410PublicKey(algorithm, parameters, pubKey.getY()), new AsymmetricGOST3410PrivateKey(algorithm, parameters, prvKey.getX()));
        }
    }

    /**
     * Operator factory for creating GOST3410 based signing and verification operators.
     */
    public static final class SignatureOperatorFactory
        extends GuardedSignatureOperatorFactory<SignatureParameters>
    {
        @Override
        public OutputSignerUsingSecureRandom<SignatureParameters> doCreateSigner(AsymmetricPrivateKey key, final SignatureParameters parameters)
        {
            final DSA gost3410Signer = new Gost3410Signer();
            final Digest digest = Register.createDigest(parameters.getDigestAlgorithm());

            AsymmetricGOST3410PrivateKey k = (AsymmetricGOST3410PrivateKey)key;

            final Gost3410PrivateKeyParameters privateKeyParameters = getLwKey(k);

            return new DSAOutputSigner<SignatureParameters>(gost3410Signer, digest, parameters, new DSAOutputSigner.Initializer()
            {
                  public void initialize(DSA signer, SecureRandom random)
                  {
                       signer.init(true, new ParametersWithRandom(privateKeyParameters, random));
                  }
            });
        }

        @Override
        public OutputVerifier<SignatureParameters> doCreateVerifier(AsymmetricPublicKey key, final SignatureParameters parameters)
        {
            final DSA gost3410Signer = new Gost3410Signer();
            final Digest digest = Register.createDigest(parameters.getDigestAlgorithm());

            AsymmetricGOST3410PublicKey k = (AsymmetricGOST3410PublicKey)key;

            Gost3410PublicKeyParameters publicKeyParameters = new Gost3410PublicKeyParameters(k.getY(), getDomainParams(k.getParameters()));

            gost3410Signer.init(false, publicKeyParameters);

            return new DSAOutputVerifier<SignatureParameters>(gost3410Signer, digest, parameters);
        }
    }

    private static Gost3410Parameters getDomainParams(GOST3410Parameters<GOST3410DomainParameters> gostParameters)
    {
        GOST3410DomainParameters domainParameters = gostParameters.getDomainParameters();

        return new Gost3410Parameters(domainParameters.getP(), domainParameters.getQ(), domainParameters.getA());
    }

    private static void validateKeyPair(AsymmetricCipherKeyPair kp)
    {
        SelfTestExecutor.validate(ALGORITHM, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
        {
            public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
            {
                final byte[] data = Hex.decode("576a1f885e3420128c8a656097ba7d8bb4c6f1b1853348cf2ba976971dbdbefc");

                Gost3410Signer signer = new Gost3410Signer();

                signer.init(true, new ParametersWithRandom(kp.getPrivate(), Utils.testRandom));

                BigInteger[] rv = signer.generateSignature(data);

                signer.init(false, kp.getPublic());

                signer.verifySignature(data, rv[0], rv[1]);

                return signer.verifySignature(data, rv[0], rv[1]);
            }
        });
    }

    private static Gost3410PrivateKeyParameters getLwKey(final AsymmetricGOST3410PrivateKey privKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<Gost3410PrivateKeyParameters>()
        {
            public Gost3410PrivateKeyParameters run()
            {
                return new Gost3410PrivateKeyParameters(privKey.getX(), getDomainParams(privKey.getParameters()));
            }
        });
    }
}
