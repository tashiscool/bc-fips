package org.bouncycastle.crypto.general;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.OutputSigner;
import org.bouncycastle.crypto.OutputVerifier;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.NamedECDomainParameters;
import org.bouncycastle.crypto.fips.FipsEC;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.params.EcDomainParameters;
import org.bouncycastle.crypto.internal.params.EcNamedDomainParameters;
import org.bouncycastle.crypto.internal.params.EcPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.EcPublicKeyParameters;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;

/**
 * Source class for non-FIPS implementations of Elliptic Curve based algorithms.
 */
public final class EC
{
    private EC()
    {

    }

    /**
     * Basic Elliptic Curve key marker, can be used for creating general purpose Elliptic Curve keys.
     */
    public static final Algorithm ALGORITHM = FipsEC.ALGORITHM;

    private enum Variations
    {
        ECDSA,
        ECDDSA
    }

    /**
     * Elliptic Curve DSA algorithm parameter source - default is SHA-1
     */
    public static final DSAParameters DSA = new DSAParameters(new GeneralAlgorithm(ALGORITHM.getName(), Variations.ECDSA), FipsSHS.Algorithm.SHA1);

    /**
     * Elliptic Curve Deterministic DSA algorithm parameter source - default is SHA-1
     */
    public static final DSAParameters DDSA = new DSAParameters(new GeneralAlgorithm(ALGORITHM.getName(), Variations.ECDDSA), FipsSHS.Algorithm.SHA1);

    /**
     * EC key pair generation parameters for non-FIPS usages.
     */
    public static final class KeyGenParameters
        extends GeneralParameters
    {
        private final ECDomainParameters domainParameters;

        /**
         * Base constructor for specific domain parameters.
         *
         * @param domainParameters the EC domain parameters.
         */
        public KeyGenParameters(ECDomainParameters domainParameters)
        {
            this(ALGORITHM, domainParameters);
        }

        /**
         * Key Generation parameters for a specific algorithm set.
         *
         * @param parameters parameter set representing the algorithm involved.
         * @param domainParameters the EC domain parameters.
         */
        public KeyGenParameters(DSAParameters parameters, ECDomainParameters domainParameters)
        {
            this(parameters.getAlgorithm(), domainParameters);
        }

        private KeyGenParameters(Algorithm algorithm, ECDomainParameters domainParameters)
        {
            super(algorithm);
            this.domainParameters = domainParameters;
        }

        public ECDomainParameters getDomainParameters()
        {
            return domainParameters;
        }
    }

    /**
     * EC DSA signature parameters for non-FIPS algorithms.
     */
    public static final class DSAParameters
        extends GeneralParameters
    {
        private final DigestAlgorithm digestAlgorithm;

        DSAParameters(GeneralAlgorithm type, DigestAlgorithm digestAlgorithm)
        {
            super(type);

            if (type.basicVariation() == Variations.ECDDSA && digestAlgorithm == null)
            {
                throw new IllegalArgumentException("ECDDSA cannot be used with a NULL digest");
            }

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
        public DSAParameters withDigestAlgorithm(DigestAlgorithm digestAlgorithm)
        {
            return new DSAParameters((GeneralAlgorithm)getAlgorithm(), digestAlgorithm);
        }
    }

    /**
     * EC key pair generator class for non-FIPS usages.
     */
    public static final class KeyPairGenerator
        extends GuardedAsymmetricKeyPairGenerator
    {
        private final FipsEC.KeyPairGenerator kpGen;

        public KeyPairGenerator(KeyGenParameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            this.kpGen = new FipsEC.KeyPairGenerator(new FipsEC.KeyGenParameters(keyGenParameters.domainParameters), random);
        }

        @Override
        protected AsymmetricKeyPair doGenerateKeyPair()
        {
            AsymmetricKeyPair kp = kpGen.generateKeyPair();
            final Algorithm algorithm = this.getParameters().getAlgorithm();

            final AsymmetricECPublicKey pubK = (AsymmetricECPublicKey)kp.getPublicKey();
            final AsymmetricECPrivateKey priK = (AsymmetricECPrivateKey)kp.getPrivateKey();

            return AccessController.doPrivileged(new PrivilegedAction<AsymmetricKeyPair>()
            {
                public AsymmetricKeyPair run()
                {
                    return new AsymmetricKeyPair(new AsymmetricECPublicKey(algorithm, pubK.getDomainParameters(), pubK.getW()), new AsymmetricECPrivateKey(algorithm, priK.getDomainParameters(), priK.getS(), pubK.getW()));
                }
            });
        }
    }

    /**
     * Operator factory for creating non-FIPS EC DSA based signing and verification operators.
     */
    public static final class DSAOperatorFactory
        extends GuardedSignatureOperatorFactory<DSAParameters>
    {
        @Override
        protected OutputSigner<DSAParameters> doCreateSigner(AsymmetricPrivateKey key, DSAParameters parameters)
        {
            AsymmetricECPrivateKey k = (AsymmetricECPrivateKey)key;

            Digest digest = (parameters.digestAlgorithm != null) ? Register.createDigest(parameters.digestAlgorithm) : new NullDigest();

            EcDsaSigner ecdsaSigner;
            if (parameters.getAlgorithm() == DSA.getDigestAlgorithm())
            {
                ecdsaSigner = new EcDsaSigner(new RandomDsaKCalculator());
            }
            else
            {
                ecdsaSigner = new EcDsaSigner(new HMacDsaKCalculator(Register.createDigest(parameters.digestAlgorithm)));
            }

            final EcPrivateKeyParameters privateKeyParameters = getLwKey(k);

            return new DSAOutputSigner<DSAParameters>(ecdsaSigner, digest, parameters, new DSAOutputSigner.Initializer()
            {
                public void initialize(org.bouncycastle.crypto.internal.DSA signer, SecureRandom random)
                {
                    signer.init(true, new ParametersWithRandom(privateKeyParameters, random));
                }
            });
        }

        @Override
        protected OutputVerifier<DSAParameters> doCreateVerifier(AsymmetricPublicKey key, DSAParameters parameters)
        {
            EcDsaSigner ecdsaSigner = new EcDsaSigner();
            Digest digest = (parameters.digestAlgorithm != null) ? Register.createDigest(parameters.digestAlgorithm) : new NullDigest();

            AsymmetricECPublicKey k = (AsymmetricECPublicKey)key;

            EcPublicKeyParameters publicKeyParameters = new EcPublicKeyParameters(k.getW(), getDomainParams(k.getDomainParameters()));

            ecdsaSigner.init(false, publicKeyParameters);

            return new DSAOutputVerifier<DSAParameters>(ecdsaSigner, digest, parameters);
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

    private static EcPrivateKeyParameters getLwKey(final AsymmetricECPrivateKey privKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<EcPrivateKeyParameters>()
        {
            public EcPrivateKeyParameters run()
            {
                return new EcPrivateKeyParameters(privKey.getS(), getDomainParams(privKey.getDomainParameters()));
            }
        });
    }
}
