package org.bouncycastle.jcajce.interfaces;

import java.math.BigInteger;

import org.bouncycastle.jcajce.spec.GOST3410DomainParameterSpec;

/**
 * Interface that a GOST-3410 private key needs to conform to.
 */
public interface GOST3410PrivateKey
    extends GOST3410Key<GOST3410DomainParameterSpec>, java.security.PrivateKey
{
    /**
     * Return X - the private value.
     *
     * @return the private value for the key.
     */
    BigInteger getX();
}
