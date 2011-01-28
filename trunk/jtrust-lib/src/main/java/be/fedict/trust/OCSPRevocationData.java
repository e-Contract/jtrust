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

import org.bouncycastle.ocsp.OCSPResp;

import be.fedict.trust.ocsp.OcspTrustLinker;

/**
 * Used by {@link OcspTrustLinker} to return, if requested, used revocation
 * data. Contains the encoded {@link OCSPResp}.
 * 
 * @author wvdhaute
 * 
 */
public class OCSPRevocationData {

	private final byte[] data;

	/**
	 * Main constructor
	 * 
	 * @param data
	 *            the encoded {@link OCSPResp}
	 */
	public OCSPRevocationData(byte[] data) {

		this.data = data;
	}

	/**
	 * Gives back the encoded OCSP response.
	 * 
	 * @return the encoded {@link OCSPResp}.
	 */
	public byte[] getData() {

		return this.data;
	}
}
