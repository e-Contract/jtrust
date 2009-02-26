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
import java.util.HashSet;
import java.util.Set;

/**
 * In-Memory Certificate Repository implementation.
 * 
 * @author fcorneli
 * 
 */
public class MemoryCertificateRepository implements CertificateRepository {

	private final Set<X509Certificate> trustPoints;

	/**
	 * Default constructor.
	 */
	public MemoryCertificateRepository() {
		this.trustPoints = new HashSet<X509Certificate>();
	}

	/**
	 * Adds a trust point to this certificate repository.
	 * 
	 * @param certificate
	 *            the X509 trust point certificate.
	 */
	public void addTrustPoint(X509Certificate certificate) {
		this.trustPoints.add(certificate);
	}

	public boolean isTrustPoint(X509Certificate certificate) {
		return this.trustPoints.contains(certificate);
	}
}
