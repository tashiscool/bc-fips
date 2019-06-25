package org.bouncycastle.jcajce.provider;

import java.lang.reflect.Constructor;

import javax.crypto.BadPaddingException;

/**
 * Holder for things that are not always available...
 */
class ClassUtil
{
    private static final Constructor aeadBadTagConstructor;

    static
    {
        Class aeadBadTagClass = lookup("javax.crypto.AEADBadTagException");
        if (aeadBadTagClass != null)
        {
            aeadBadTagConstructor = findExceptionConstructor(aeadBadTagClass);
        }
        else
        {
            aeadBadTagConstructor = null;
        }
    }


    private static Constructor findConstructor(Class clazz)
    {
        try
        {
            return clazz.getConstructor();
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private static Constructor findExceptionConstructor(Class clazz)
    {
        try
        {
            return clazz.getConstructor(new Class[]{String.class});
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private static Class lookup(String className)
    {
        try
        {
            Class def = ClassUtil.class.getClassLoader().loadClass(className);

            return def;
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public static void throwBadTagException(String message)
        throws BadPaddingException
    {
        if (aeadBadTagConstructor != null)
        {
            BadPaddingException aeadBadTag = null;
            try
            {
                aeadBadTag = (BadPaddingException)aeadBadTagConstructor
                        .newInstance(new Object[]{message});
            }
            catch (Exception i)
            {
                // Shouldn't happen, but fall through to BadPaddingException
            }
            if (aeadBadTag != null)
            {
                throw aeadBadTag;
            }
        }

        throw new BadPaddingException(message);
    }
}
