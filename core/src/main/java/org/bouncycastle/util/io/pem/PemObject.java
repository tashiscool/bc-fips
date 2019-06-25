/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.util.io.pem;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.util.Arrays;

/**
 * A generic PEM object - type, header properties, and byte content.
 */
public class PemObject
    implements PemObjectGenerator
{
    private static final List EMPTY_LIST = Collections.unmodifiableList(new ArrayList());

    private String type;
    private List   headers;
    private byte[] content;

    /**
     * Generic constructor for object without headers.
     *
     * @param type pem object type.
     * @param content the binary content of the object.
     */
    public PemObject(String type, byte[] content)
    {
        this(type, EMPTY_LIST, content);
    }

    /**
     * Generic constructor for object with headers.
     *
     * @param type pem object type.
     * @param headers a list of PemHeader objects.
     * @param content the binary content of the object.
     */
    public PemObject(String type, List headers, byte[] content)
    {
        this.type = type;
        this.headers = Collections.unmodifiableList(headers);
        this.content = Arrays.clone(content);
    }

    public String getType()
    {
        return type;
    }

    public List getHeaders()
    {
        return headers;
    }

    public byte[] getContent()
    {
        return Arrays.clone(content);
    }

    public PemObject generate()
        throws PemGenerationException
    {
        return this;
    }
}
