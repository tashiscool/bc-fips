package org.bouncycastle.jcajce.provider;

import java.security.NoSuchAlgorithmException;

import org.bouncycastle.crypto.CryptoServicesRegistrar;

class GuardedEngineCreator
    implements EngineCreator
{
    private final EngineCreator creator;

    GuardedEngineCreator(EngineCreator creator)
    {
        this.creator = creator;
    }

    public Object createInstance(Object constructorParameter)
        throws NoSuchAlgorithmException
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        return creator.createInstance(constructorParameter);
    }
}
