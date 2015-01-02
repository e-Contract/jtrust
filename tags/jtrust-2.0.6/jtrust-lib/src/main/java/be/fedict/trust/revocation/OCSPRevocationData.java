/*
 * Java Trust Project.
 * Copyright (C) 2009-2012 FedICT.
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

package be.fedict.trust.revocation;

/**
 * Data object for OCSP revocation data.
 * 
 * @author Frank Cornelis
 * 
 */
public class OCSPRevocationData {

	private final byte[] ocsp;

	private final String uri;

	public OCSPRevocationData(byte[] ocsp, String uri) {
		this.ocsp = ocsp;
		this.uri = uri;
	}

	public byte[] getOCSP() {
		return this.ocsp;
	}

	public String getURI() {
		return this.uri;
	}
}
