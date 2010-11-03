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
 * additional info if failed.
 * 
 * @author wvdhaute
 * 
 */
public class TrustLinkerResult {

	private final boolean valid;
	private final TrustLinkerResultReason reason;
	private final String message;

	/**
	 * Main constructor
	 */
	public TrustLinkerResult(boolean valid) {

		this.valid = valid;
		this.reason = null;
		this.message = null;
	}

	/**
	 * Main constructor
	 * 
	 * @param valid
	 *            valid or not
	 * @param reason
	 *            the reason for being valid or not
	 * @param message
	 *            additional info
	 */
	public TrustLinkerResult(boolean valid, TrustLinkerResultReason reason,
			String message) {

		this.valid = valid;
		this.reason = reason;
		this.message = message;
	}

	/**
	 * Whether or not the trust validation was valid or not.
	 */
	public boolean isValid() {

		return this.valid;
	}

	/**
	 * Returns the optional reason. Returns <code>null</code> if no reason set.
	 */
	public TrustLinkerResultReason getReason() {

		return this.reason;
	}

	/**
	 * Returns an additional information message why the validation failed.
	 * Returns <code>null</code> if no additional info was specified by the
	 * {@link TrustLinker}.
	 */
	public String getMessage() {

		return this.message;
	}
}
