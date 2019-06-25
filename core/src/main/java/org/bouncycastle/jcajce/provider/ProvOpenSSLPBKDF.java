package org.bouncycastle.jcajce.provider;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.general.PBKD;
import org.bouncycastle.util.Strings;

class ProvOpenSSLPBKDF
    extends AlgorithmProvider
{
    private static final String PREFIX = ProvOpenSSLPBKDF.class.getName();

    @Override
    void configure(BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory.PBKDF-OPENSSL", PREFIX + "$PBKDF", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new PBKDF();
            }
        }));
    }

    static class PBKDF
        extends BaseKDFSecretKeyFactory
    {
        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof PBEKeySpec)
            {
                PBEKeySpec pbeSpec = (PBEKeySpec)keySpec;

                if (pbeSpec.getSalt() == null)
                {
                    throw new InvalidKeySpecException("Missing required salt");
                }

                if (pbeSpec.getKeyLength() <= 0)
                {
                    throw new InvalidKeySpecException("Positive key length required: "
                        + pbeSpec.getKeyLength());
                }

                PasswordBasedDeriver deriver = new PBKD.DeriverFactory().createDeriver(PBKD.OpenSSL.using(Strings.toByteArray(pbeSpec.getPassword())).withSalt(pbeSpec.getSalt()));

                return new PBKDFPBEKey(deriver.deriveKey(PasswordBasedDeriver.KeyType.CIPHER, pbeSpec.getKeyLength() / 8), "PBKDF-OpenSSL", pbeSpec);
            }

            throw new InvalidKeySpecException("Invalid KeySpec: " + keySpec.getClass().getName());
        }
    }
}
