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

import java.security.cert.X509Certificate;

/**
 * Interface for X509 certificate constraint components.
 * 
 * @author Frank Cornelis
 * 
 */
public interface CertificateConstraint {

	/**
	 * Checks the given X509 certificate against this constraint.
	 * 
	 * @param certificate
	 *            the X509 certificate.
	 * @return <code>true</code> if the certificate is OK according to this
	 *         constraint, otherwise <code>false</code>.
	 */
	boolean check(X509Certificate certificate);
}
