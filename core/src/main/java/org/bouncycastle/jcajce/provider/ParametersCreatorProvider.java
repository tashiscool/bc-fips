package org.bouncycastle.jcajce.provider;

import org.bouncycastle.crypto.Parameters;

interface ParametersCreatorProvider<T extends Parameters>
{
    ParametersCreator get(T parameters);
}
