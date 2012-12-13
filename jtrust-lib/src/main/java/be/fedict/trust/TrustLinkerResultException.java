/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
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
 * Used by {@link TrustLinker}'s to return the result of trust validation with
 * additional info.
 * 
 * @author Frank Cornelis
 * 
 */
public class TrustLinkerResultException extends Exception {

	private final TrustLinkerResultReason reason;

	/**
	 * Main constructor
	 */
	public TrustLinkerResultException() {
		super();
        this.reason = null;
	}

    public TrustLinkerResultException(String message) {
        super(message);
        this.reason = null;
    }

    public TrustLinkerResultException(String message, Throwable cause) {
        super(message, cause);
        this.reason = null;
    }

	/**
	 * Main constructor
	 *
	 * @param reason
	 *            the reason for being invalid
	 * @param message
	 *            additional info
	 */
	public TrustLinkerResultException(TrustLinkerResultReason reason,
			String message) {
        super(message);
		this.reason = reason;
	}

    public TrustLinkerResultException(TrustLinkerResultReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public TrustLinkerResultException(TrustLinkerResultReason reason) {
        this.reason = reason;
    }

	/**
	 * Returns the optional reason. Returns <code>null</code> if no reason set.
	 */
	public TrustLinkerResultReason getReason() {
		return this.reason;
	}
}
