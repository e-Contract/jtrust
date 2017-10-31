package be.fedict.trust;

/**
 * Used by {@link be.fedict.trust.crl.CrlRepository}'s and {@link be.fedict.trust.ocsp.OcspRepository}'s to when the
 * server is not responding.
 *
 * @author <a href="mailto:alexander.van.ravestyn@healthconnect.be">Alexander van Ravestyn</a>
 *
 */
public class ServerNotAvailableException extends Exception {

    private final ServerType serverType;

    public ServerNotAvailableException(String message, ServerType serverType) {
        super(message);
        this.serverType = serverType;
    }

}
