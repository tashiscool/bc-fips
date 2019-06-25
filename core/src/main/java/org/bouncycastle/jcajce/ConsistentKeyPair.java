package org.bouncycastle.jcajce;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jcajce.interfaces.DSTU4145Key;
import org.bouncycastle.jcajce.interfaces.DSTU4145PrivateKey;
import org.bouncycastle.jcajce.interfaces.DSTU4145PublicKey;
import org.bouncycastle.jcajce.interfaces.ECGOST3410PrivateKey;
import org.bouncycastle.jcajce.interfaces.ECGOST3410PublicKey;
import org.bouncycastle.jcajce.interfaces.GOST3410Key;
import org.bouncycastle.jcajce.interfaces.GOST3410PrivateKey;
import org.bouncycastle.jcajce.interfaces.GOST3410PublicKey;
import org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;
import org.bouncycastle.jcajce.spec.ECDomainParameterSpec;
import org.bouncycastle.jcajce.spec.GOST3410DomainParameterSpec;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;

/**
 * Carrier class for a key pair which validates the consistency of the keys at construction time.
 */
public class ConsistentKeyPair
{
    private PrivateKey privateKey;
    private PublicKey publicKey;

    /**
     * Create a public/private key pair.
     *
     * @param publicKey the public key component.
     * @param privateKey the private key component.
     * @throws IllegalArgumentException if the public and private key arguments are inconsistent.
     */
    public ConsistentKeyPair(final PublicKey publicKey, final PrivateKey privateKey)
    {
        AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                checkKeyPairForConsistency(publicKey, privateKey);

                return null;
            }
        });

        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    private void checkKeyPairForConsistency(PublicKey publicKey, PrivateKey privateKey)
    {
        if (publicKey instanceof ECKey && privateKey instanceof ECKey)
        {
            ECPrivateKey priv = (ECPrivateKey)privateKey;
            ECPublicKey pub = (ECPublicKey)publicKey;
            if (!priv.getParams().getCurve().equals(pub.getParams().getCurve())
                || !priv.getParams().getGenerator().equals(pub.getParams().getGenerator())
                || !priv.getParams().getOrder().equals(pub.getParams().getOrder())
                || priv.getParams().getCofactor() != pub.getParams().getCofactor())
            {
                throw new IllegalArgumentException("EC keys do not have the same domain parameters");
            }
            ECDomainParameterSpec spec = new ECDomainParameterSpec(priv.getParams());
            if (!spec.getDomainParameters().getG().multiply(priv.getS()).normalize().equals(
                spec.getDomainParameters().getCurve().createPoint(pub.getW().getAffineX(), pub.getW().getAffineY())))
            {
                throw new IllegalArgumentException("EC public key not consistent with EC private key");
            }
        }
        else if (publicKey instanceof DHKey && privateKey instanceof DHKey)
        {
            DHPrivateKey priv = (DHPrivateKey)privateKey;
            DHPublicKey pub = (DHPublicKey)publicKey;

            DHParameterSpec dhParameters = priv.getParams();
            if (!dhParameters.getG().equals(pub.getParams().getG())
                  && !dhParameters.getP().equals(pub.getParams().getP()))
            {
                throw new IllegalArgumentException("DH keys do not have the same domain parameters");
            }
            if (!dhParameters.getG().modPow(priv.getX(), dhParameters.getP()).equals(pub.getY()))
            {
                throw new IllegalArgumentException("DH public key not consistent with DH private key");
            }
        }
        else if (publicKey instanceof DSAKey && privateKey instanceof DSAKey)
        {
            DSAPrivateKey priv = (DSAPrivateKey)privateKey;
            DSAPublicKey pub = (DSAPublicKey)publicKey;

            DSAParams dsaParameters = priv.getParams();
            if (!dsaParameters.getG().equals(pub.getParams().getG())
                && !dsaParameters.getP().equals(pub.getParams().getP())
                && !dsaParameters.getQ().equals(pub.getParams().getQ()))
            {
                throw new IllegalArgumentException("DSA keys do not have the same domain parameters");
            }
            if (!dsaParameters.getG().modPow(priv.getX(), dsaParameters.getP()).equals(pub.getY()))
            {
                throw new IllegalArgumentException("DSA public key not consistent with DSA private key");
            }
        }
        else if (publicKey instanceof RSAKey && privateKey instanceof RSAKey)
        {
            RSAPrivateKey priv = (RSAPrivateKey)privateKey;
            RSAPublicKey pub = (RSAPublicKey)publicKey;

            if (!priv.getModulus().equals(pub.getModulus()))
            {
                throw new IllegalArgumentException("RSA keys do not have the same modulus");
            }
            BigInteger val = BigInteger.valueOf(2);
            if (!val.modPow(priv.getPrivateExponent(), priv.getModulus()).modPow(pub.getPublicExponent(), priv.getModulus()).equals(val))
            {
                throw new IllegalArgumentException("RSA public key not consistent with RSA private key");
            }
        }
        else if (publicKey instanceof GOST3410Key && privateKey instanceof GOST3410Key)
        {
            if (!((GOST3410Key)publicKey).getParams().equals(((GOST3410Key)privateKey).getParams()))
            {
                throw new IllegalArgumentException("GOST3410 parameters mismatch");
            }
            if (publicKey instanceof GOST3410PublicKey && privateKey instanceof GOST3410PrivateKey)
            {
                GOST3410PrivateKey priv = (GOST3410PrivateKey)privateKey;
                GOST3410PublicKey pub = (GOST3410PublicKey)publicKey;

                GOST3410ParameterSpec gostParameters = priv.getParams();
                GOST3410DomainParameterSpec gParams = (GOST3410DomainParameterSpec)gostParameters.getDomainParametersSpec();

                if (!gParams.getA().modPow(priv.getX(), gParams.getP()).equals(pub.getY()))
                {
                    throw new IllegalArgumentException("GOST3410 public key not consistent with GOST3410 private key");
                }
            }
            else if (publicKey instanceof ECGOST3410PublicKey && privateKey instanceof ECGOST3410PrivateKey)
            {
                ECGOST3410PrivateKey priv = (ECGOST3410PrivateKey)privateKey;
                ECGOST3410PublicKey pub = (ECGOST3410PublicKey)publicKey;

                GOST3410ParameterSpec gostParameters = priv.getParams();
                ECDomainParameterSpec gParams = (ECDomainParameterSpec)gostParameters.getDomainParametersSpec();
                ECDomainParameterSpec spec = new ECDomainParameterSpec(gParams);

                if (!spec.getDomainParameters().getG().multiply(priv.getS()).normalize().equals(
                    spec.getDomainParameters().getCurve().createPoint(pub.getW().getAffineX(), pub.getW().getAffineY())))
                {
                    throw new IllegalArgumentException("ECGOST3410 public key not consistent with ECGOST3410 private key");
                }
            }
            else
            {
                throw new IllegalArgumentException("GOST3410 key pair inconsistent");
            }
        }
        else if (publicKey instanceof DSTU4145Key && privateKey instanceof DSTU4145Key)
        {
            DSTU4145PrivateKey priv = (DSTU4145PrivateKey)privateKey;
            DSTU4145PublicKey pub = (DSTU4145PublicKey)publicKey;

            if (!priv.getParams().equals(pub.getParams()))
            {
                throw new IllegalArgumentException("DSTU4145 keys do not have the same domain parameters");
            }

            DSTU4145ParameterSpec dstu4145Parameters = priv.getParams();
            ECDomainParameterSpec spec = new ECDomainParameterSpec(dstu4145Parameters);

            if (!spec.getDomainParameters().getG().multiply(priv.getS()).negate().normalize().equals(
                spec.getDomainParameters().getCurve().createPoint(pub.getW().getAffineX(), pub.getW().getAffineY())))
            {
                throw new IllegalArgumentException("DSTU4145 public key not consistent with DSTU4145 private key");
            }
        }
        else
        {
            throw new IllegalArgumentException("Key pair inconsistent");
        }
    }

    /**
     * Return the public key component.
     *
     * @return the public key in the pair.
     */
    public PublicKey getPublic()
    {
        return this.publicKey;
    }

    /**
     * Return the private key component.
     *
     * @return the private key in the pair.
     */
    public PrivateKey getPrivate()
    {
        return this.privateKey;
    }
}
