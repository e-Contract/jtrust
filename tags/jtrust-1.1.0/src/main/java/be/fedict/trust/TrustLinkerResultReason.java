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
 * The reason codes returned by an XKMS2 ValidateRequest, specifying a reason
 * for a particular key binding status of that request.
 * 
 * @see <a href="http://www.w3.org/TR/xkms2/#XKMS_2_0_Section_5_1">XKMS 2.0</a>
 * 
 * @author wvdhaute
 */
public enum TrustLinkerResultReason {

	/**
	 * Certificate path could not be constructed to a trusted root
	 */
	INVALID_TRUST,
	/**
	 * Certificate Signature verification failed
	 */
	INVALID_SIGNATURE,
	/**
	 * The requested time instant was before or after the certificate chain
	 * validity interval
	 */
	INVALID_VALIDITY_INTERVAL,
	/**
	 * Certificate status returned revoked or suspended.
	 */
	INVALID_REVOCATION_STATUS
}
