package org.bouncycastle.jcajce.interfaces;

import java.math.BigInteger;
import java.security.PublicKey;

import org.bouncycastle.jcajce.spec.GOST3410DomainParameterSpec;

/**
 * Interface that a GOST-3410 public key needs to conform to.
 */
public interface GOST3410PublicKey
    extends GOST3410Key<GOST3410DomainParameterSpec>, PublicKey
{
    /**
     * Return Y - the public value.
     *
     * @return the public value Y.
     */
    BigInteger getY();
}
