package org.bouncycastle.jcajce.provider;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.util.Integers;

class GcmSpecUtil
{
    static final Class gcmSpecClass = lookup("javax.crypto.spec.GCMParameterSpec");

    static boolean gcmSpecExists()
    {
        return gcmSpecClass != null;
    }

    static boolean isGcmSpec(AlgorithmParameterSpec paramSpec)
    {
        return gcmSpecClass != null && gcmSpecClass.isInstance(paramSpec);
    }

    static boolean isGcmSpec(Class paramSpecClass)
    {
        return gcmSpecClass == paramSpecClass;
    }

    static Class[] getCipherSpecClasses()
    {
        if (gcmSpecExists())
        {
            return new Class[]{GcmSpecUtil.gcmSpecClass, IvParameterSpec.class};
        }
        else
        {
            return new Class[]{AEADParameterSpec.class,IvParameterSpec.class};
        }
    }

    static AlgorithmParameterSpec extractGcmSpec(final ASN1Primitive spec)
        throws InvalidParameterSpecException
    {
        Object rv = AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                try
                {
                    GCMParameters gcmParams = GCMParameters.getInstance(spec);
                    Constructor constructor = gcmSpecClass.getConstructor(new Class[]{Integer.TYPE, byte[].class});

                    return constructor.newInstance(new Object[]{Integers.valueOf(gcmParams.getIcvLen() * 8), gcmParams.getNonce()});
                }
                catch (NoSuchMethodException e)
                {
                    return new InvalidParameterSpecException("no constructor found!");   // should never happen
                }
                catch (Exception e)
                {
                    return new InvalidParameterSpecException("construction failed: " + e.getMessage());   // should never happen
                }
            }
        });
        if (rv instanceof AlgorithmParameterSpec)
        {
            return (AlgorithmParameterSpec)rv;
        }
        else
        {
            throw (InvalidParameterSpecException)rv;
        }
    }

    static GCMParameters extractGcmParameters(final AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        Object rv = AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                try
                {
                    Method tLen = gcmSpecClass.getDeclaredMethod("getTLen", new Class[0]);
                    Method iv = gcmSpecClass.getDeclaredMethod("getIV", new Class[0]);

                    return new GCMParameters((byte[])iv.invoke(paramSpec, new Object[0]), ((Integer)tLen.invoke(paramSpec, new Object[0])).intValue() / 8);
                }
                catch (Exception e)
                {
                    return new InvalidParameterSpecException("cannot process GCMParameterSpec: " + e.getMessage());
                }
            }
        });
        if (rv instanceof GCMParameters)
        {
            return (GCMParameters)rv;
        }
        else
        {
            throw (InvalidParameterSpecException)rv;
        }
    }

    private static Class lookup(String className)
    {
        try
        {
            return GcmSpecUtil.class.getClassLoader().loadClass(className);
        }
        catch (Exception e)
        {
            return null;
        }
    }
}
