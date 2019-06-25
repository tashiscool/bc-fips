package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;
import java.security.spec.ECPoint;

import org.bouncycastle.jcajce.spec.ECDomainParameterSpec;

/**
 * Interface that a ECGOST-3410 public key needs to conform to.
 */
public interface ECGOST3410PublicKey
    extends GOST3410Key<ECDomainParameterSpec>, PublicKey
{
    /**
     * Return W - the public point for the key.
     *
     * @return the public point.
     */
    ECPoint getW();
}
