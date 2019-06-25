package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;
import java.security.spec.ECPoint;

/**
 * Interface that a DSTU-4145 public key needs to conform to.
 */
public interface DSTU4145PublicKey
    extends DSTU4145Key, PublicKey
{
    /**
     * Return W - the public point for the key.
     *
     * @return the public point.
     */
    ECPoint getW();
}
