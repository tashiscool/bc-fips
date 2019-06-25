package org.bouncycastle.crypto.asymmetric;

/**
 * Base interface for an EC domain parameters ID.
 */
public interface ECDomainParametersID
{
    /**
     * Return the string version of the curve name.
     *
     * @return the name of the curve.
     */
    String getCurveName();
}
