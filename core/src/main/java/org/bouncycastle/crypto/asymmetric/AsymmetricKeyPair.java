package org.bouncycastle.crypto.asymmetric;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.PrivilegedAction;

import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;

/**
 * Carrier class for a public key and its associated private key. This class will check the key
 * pair on construction.
 */
public final class AsymmetricKeyPair<P extends AsymmetricPublicKey, S extends AsymmetricPrivateKey>
{
    private final P publicKey;
    private final S privateKey;

    /**
     * Create a public/private key pair.
     *
     * @param publicKey the public key component.
     * @param privateKey the private key component.
     * @throws IllegalArgumentException if the public and private key arguments are inconsistent.
     */
    public AsymmetricKeyPair(final P publicKey, final S privateKey)
    {
        AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {

                // FSM_STATE:5.11,"IMPORTED KEY PAIR CONSISTENCY TEST", "The module is verifying the consistency of an imported key pair"
                // FSM_TRANS:5.IKP.0,"CONDITIONAL TEST", "IMPORTED KEY PAIR CONSISTENCY TEST", "Invoke public/private key Consistency test on imported key pair"
                checkKeyPairForConsistency(publicKey, privateKey);

                return null;
            }
        });

        this.publicKey=publicKey;
        this.privateKey=privateKey;
    }

    private void checkKeyPairForConsistency(P publicKey, S privateKey)
    {
        if (publicKey instanceof AsymmetricECKey && privateKey instanceof AsymmetricECKey)
        {
            AsymmetricECPrivateKey priv = (AsymmetricECPrivateKey)privateKey;
            AsymmetricECPublicKey pub = (AsymmetricECPublicKey)publicKey;

            if (!priv.getDomainParameters().equals(pub.getDomainParameters()))
            {
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                throw new IllegalArgumentException("EC keys do not have the same domain parameters");
            }
            if (!priv.getDomainParameters().getG().multiply(priv.getS()).normalize().equals(pub.getW()))
            {
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                throw new IllegalArgumentException("EC public key not consistent with EC private key");
            }
        }
        else if (publicKey instanceof AsymmetricDHKey && privateKey instanceof AsymmetricDHKey)
        {
            AsymmetricDHPrivateKey priv = (AsymmetricDHPrivateKey)privateKey;
            AsymmetricDHPublicKey pub = (AsymmetricDHPublicKey)publicKey;

            DHDomainParameters dhParameters = priv.getDomainParameters();
            if (!dhParameters.equals(pub.getDomainParameters()))
            {
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                throw new IllegalArgumentException("DH keys do not have the same domain parameters");
            }
            if (!dhParameters.getG().modPow(priv.getX(), dhParameters.getP()).equals(pub.getY()))
            {
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                throw new IllegalArgumentException("DH public key not consistent with DH private key");
            }
        }
        else if (publicKey instanceof AsymmetricDSAKey && privateKey instanceof AsymmetricDSAKey)
        {
            AsymmetricDSAPrivateKey priv = (AsymmetricDSAPrivateKey)privateKey;
            AsymmetricDSAPublicKey pub = (AsymmetricDSAPublicKey)publicKey;

            DSADomainParameters dsaParameters = priv.getDomainParameters();
            if (!dsaParameters.equals(pub.getDomainParameters()))
            {
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                throw new IllegalArgumentException("DSA keys do not have the same domain parameters");
            }
            if (!dsaParameters.getG().modPow(priv.getX(), dsaParameters.getP()).equals(pub.getY()))
            {
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                throw new IllegalArgumentException("DSA public key not consistent with DSA private key");
            }
        }
        else if (publicKey instanceof AsymmetricRSAKey && privateKey instanceof AsymmetricRSAKey)
        {
            AsymmetricRSAPrivateKey priv = (AsymmetricRSAPrivateKey)privateKey;
            AsymmetricRSAPublicKey pub = (AsymmetricRSAPublicKey)publicKey;

            if (!priv.getModulus().equals(pub.getModulus()))
            {
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                throw new IllegalArgumentException("RSA keys do not have the same modulus");
            }
            BigInteger val = BigInteger.valueOf(2);
            if (!val.modPow(priv.getPrivateExponent(), priv.getModulus()).modPow(pub.getPublicExponent(), priv.getModulus()).equals(val))
            {
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                throw new IllegalArgumentException("RSA public key not consistent with RSA private key");
            }
        }
        else if (publicKey instanceof AsymmetricGOST3410Key && privateKey instanceof AsymmetricGOST3410Key)
        {
            if (!((AsymmetricGOST3410Key)publicKey).getParameters().equals(((AsymmetricGOST3410Key)privateKey).getParameters()))
            {
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                throw new IllegalArgumentException("GOST3410 parameters mismatch");
            }
            if (publicKey instanceof AsymmetricGOST3410PublicKey && privateKey instanceof AsymmetricGOST3410PrivateKey)
            {
                AsymmetricGOST3410PrivateKey priv = (AsymmetricGOST3410PrivateKey)privateKey;
                AsymmetricGOST3410PublicKey pub = (AsymmetricGOST3410PublicKey)publicKey;

                GOST3410Parameters<GOST3410DomainParameters> gostParameters = priv.getParameters();
                GOST3410DomainParameters gParams = gostParameters.getDomainParameters();

                if (!gParams.getA().modPow(priv.getX(), gParams.getP()).equals(pub.getY()))
                {
                    // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                    throw new IllegalArgumentException("GOST3410 public key not consistent with GOST3410 private key");
                }
            }
            else if (publicKey instanceof AsymmetricECGOST3410PublicKey && privateKey instanceof AsymmetricECGOST3410PrivateKey)
            {
                AsymmetricECGOST3410PrivateKey priv = (AsymmetricECGOST3410PrivateKey)privateKey;
                AsymmetricECGOST3410PublicKey pub = (AsymmetricECGOST3410PublicKey)publicKey;

                GOST3410Parameters<ECDomainParameters>  gostParameters = priv.getParameters();
                ECDomainParameters gParams = gostParameters.getDomainParameters();

                if (!gParams.getG().multiply(priv.getS()).normalize().equals(pub.getW()))
                {
                    // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                    throw new IllegalArgumentException("ECGOST3410 public key not consistent with ECGOST3410 private key");
                }
            }
            else
            {
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                throw new IllegalArgumentException("GOST3410 key pair inconsistent");
            }
        }
        else if (publicKey instanceof AsymmetricDSTU4145Key && privateKey instanceof AsymmetricDSTU4145Key)
        {
            AsymmetricDSTU4145PrivateKey priv = (AsymmetricDSTU4145PrivateKey)privateKey;
            AsymmetricDSTU4145PublicKey pub = (AsymmetricDSTU4145PublicKey)publicKey;

            if (!priv.getParameters().equals(pub.getParameters()))
            {
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                throw new IllegalArgumentException("DSTU4145 keys do not have the same domain parameters");
            }
            if (!priv.getParameters().getDomainParameters().getG().multiply(priv.getS()).negate().normalize().equals(pub.getW()))
            {
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                throw new IllegalArgumentException("DSTU4145 public key not consistent with DSTU4145 private key");
            }
        }
        else
        {
            // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
            throw new IllegalArgumentException("Key pair inconsistent");
        }
        // FSM_TRANS:5.IKP.1, "IMPORTED KEY PAIR CONSISTENCY TEST", "CONDITIONAL TEST", "Consistency test on imported key pair successful"
    }

    /**
     * Return the public key of the pair.
     *
     * @return the public key.
     */
    public P getPublicKey()
    {
        return publicKey;
    }

    /**
     * Return the private key of the pair.
     *
     * @return the private key.
     */
    public S getPrivateKey()
    {
        return privateKey;
    }
}
