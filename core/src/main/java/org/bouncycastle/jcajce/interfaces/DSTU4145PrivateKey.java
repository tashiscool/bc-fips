package org.bouncycastle.jcajce.interfaces;

import java.math.BigInteger;

/**
 * Interface that a DSTU-4145 private key needs to conform to.
 */
public interface DSTU4145PrivateKey
    extends DSTU4145Key, java.security.PrivateKey
{
    /**
     * Return S - the private value.
     *
     * @return the private value for the key.
     */
    BigInteger getS();
}
