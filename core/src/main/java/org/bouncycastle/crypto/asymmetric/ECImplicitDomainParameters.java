package org.bouncycastle.crypto.asymmetric;

/**
 * Extension class that identifies this domain parameter set as being the ImplicitlyCa domain
 * parameters for this JVM.
 */
public final class ECImplicitDomainParameters
    extends ECDomainParameters
{
    /**
     * Base constructor.
     *
     * @param domainParameters the ImplicitlyCa domain parameters.
     */
    public ECImplicitDomainParameters(ECDomainParameters domainParameters)
    {
        super(domainParameters.getCurve(), domainParameters.getG(), domainParameters.getN(), domainParameters.getH(), domainParameters.getSeed());
    }
}
