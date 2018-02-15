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

package be.fedict.trust.linker;

/**
 * The reason codes returned by a trust linker.
 * 
 * @author wvdhaute
 */
public enum TrustLinkerResultReason {

	/**
	 * The exact reason is unspecified, or further specified in the exception
	 * message.
	 */
	UNSPECIFIED,

	/**
	 * The root certificate was not trusted.
	 */
	ROOT,

	/**
	 * Used to indicate that no trust between two certificates could be
	 * established.
	 */
	NO_TRUST,

	/**
	 * Used to indicate that the end-entity certificate violated some
	 * constraint.
	 */
	CONSTRAINT_VIOLATION,

	/**
	 * Certificate Signature verification failed
	 */
	INVALID_SIGNATURE,

	/**
	 * An invalid algorithm was used.
	 */
	INVALID_ALGORITHM,

	/**
	 * The requested time instant was before or after the certificate chain
	 * validity interval
	 */
	INVALID_VALIDITY_INTERVAL,

	/**
	 * Certificate status returned revoked or suspended.
	 */
	INVALID_REVOCATION_STATUS,

	/**
	 * Indicates that the CRL server is unavailable.
	 */
	CRL_UNAVAILABLE,

	/**
	 * Indicates that the OCSP server is unavailable.
	 */
	OCSP_UNAVAILABLE
}
