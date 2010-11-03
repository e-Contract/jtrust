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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.digest.DigestUtils;

/**
 * In-Memory Certificate Repository implementation.
 * 
 * @author Frank Cornelis
 * 
 */
public class MemoryCertificateRepository implements CertificateRepository {

	private final Map<String, X509Certificate> trustPoints;

	/**
	 * Default constructor.
	 */
	public MemoryCertificateRepository() {
		this.trustPoints = new HashMap<String, X509Certificate>();
	}

	/**
	 * Adds a trust point to this certificate repository.
	 * 
	 * @param certificate
	 *            the X509 trust point certificate.
	 */
	public void addTrustPoint(X509Certificate certificate) {
		String fingerprint = getFingerprint(certificate);
		this.trustPoints.put(fingerprint, certificate);
	}

	public boolean isTrustPoint(X509Certificate certificate) {
		String fingerprint = getFingerprint(certificate);
		X509Certificate trustPoint = this.trustPoints.get(fingerprint);
		if (null == trustPoint) {
			return false;
		}
		try {
			/*
			 * We cannot used certificate.equals(trustPoint) here as the
			 * certificates might be loaded by different security providers.
			 */
			return Arrays.equals(certificate.getEncoded(),
					trustPoint.getEncoded());
		} catch (CertificateEncodingException e) {
			throw new IllegalArgumentException("certificate encoding error: "
					+ e.getMessage(), e);
		}
	}

	private String getFingerprint(X509Certificate certificate) {
		byte[] encodedCertificate;
		try {
			encodedCertificate = certificate.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new IllegalArgumentException("certificate encoding error: "
					+ e.getMessage(), e);
		}
		String fingerprint = DigestUtils.shaHex(encodedCertificate);
		return fingerprint;
	}
}
