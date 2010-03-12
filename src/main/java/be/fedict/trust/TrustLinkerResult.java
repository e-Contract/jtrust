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

public class TrustLinkerResult {

	private final boolean valid;
	private final TrustLinkerResultReason reason;
	private String message;

	public TrustLinkerResult(boolean valid) {

		this.valid = valid;
		this.reason = null;
		this.message = null;
	}

	public TrustLinkerResult(boolean valid, TrustLinkerResultReason reason) {

		this.valid = valid;
		this.reason = reason;
		this.message = null;
	}

	public TrustLinkerResult(boolean valid, TrustLinkerResultReason reason,
			String message) {

		this.valid = valid;
		this.reason = reason;
		this.message = null;
	}

	public boolean isValid() {

		return this.valid;
	}

	public TrustLinkerResultReason getReason() {

		return this.reason;
	}

	public String getMessage() {

		return this.message;
	}
}
