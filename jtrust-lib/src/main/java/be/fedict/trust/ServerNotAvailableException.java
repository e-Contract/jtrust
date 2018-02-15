/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2014 e-Contract.be BVBA.
 * Copyright (C) 2017 HealthConnect NV.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package be.fedict.trust;

/**
 * Used by {@link be.fedict.trust.crl.CrlRepository}'s and {@link be.fedict.trust.ocsp.OcspRepository}'s to when the server is not
 * responding.
 *
 * @author <a href="mailto:alexander.van.ravestyn@healthconnect.be">Alexander van Ravestyn</a>
 * @author <a href="mailto:dennis.wagelaar@healthconnect.be">Dennis Wagelaar</a>
 */
public class ServerNotAvailableException extends Exception {

	private static final long serialVersionUID = -9132793739935537607L;

	private final ServerType serverType;

	/**
	 * Creates a new {@link ServerNotAvailableException}.
	 * 
	 * @param message
	 *            the error message
	 * @param serverType
	 *            the {@link ServerType} that this exception pertains to
	 */
    public ServerNotAvailableException(final String message, final ServerType serverType) {
        super(message);
        this.serverType = serverType;
    }

	/**
	 * Creates a new {@link ServerNotAvailableException}.
	 *
	 * @param message
	 * 			  the error message
	 * @param serverType
	 *            the {@link ServerType} that this exception pertains to
	 * @param cause
	 *            the cause
	 */
	public ServerNotAvailableException(final String message, final ServerType serverType, final Throwable cause) {
		super(message, cause);
		this.serverType = serverType;
	}

	/**
	 * Returns the {@link ServerType} that this exception pertains to.
	 * 
	 * @return the serverType the {@link ServerType} that this exception pertains to
	 */
	public ServerType getServerType() {
		return serverType;
	}

}
