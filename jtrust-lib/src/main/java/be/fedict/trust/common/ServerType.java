package be.fedict.trust.common;

/**
 * Used by {@link ServerNotAvailableException} to indicate which server is unavailable.
 *
 * @author <a href="mailto:alexander.van.ravestyn@healthconnect.be">Alexander van Ravestyn</a>
 *
 */
public enum ServerType {

    /**
     * OCSP server is unavailable.
     */
    OCSP,

    /**
     * CRL server is unavailable.
     */
    CRL

}
