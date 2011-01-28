/*
 * Java Trust Project.
 * Copyright (C) 2009-2010 FedICT.
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

package be.fedict.trust.constraints;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import be.fedict.trust.CertificateConstraint;
import be.fedict.trust.TrustValidator;

/**
 * End-Entity Certificate Constraint implementation. This CertificateConstraint
 * implementation can filter the end-entity certificates against a given set of
 * (issuer name, serial number).
 * 
 * This CertificateConstraint can be used to define for example a trust domain
 * for authorization of a given set of Service Providers.
 * 
 * @author Frank Cornelis
 * 
 */
public class EndEntityCertificateConstraint implements CertificateConstraint {

	private Map<String, Set<BigInteger>> endEntities;

	/**
	 * Main constructor.
	 */
	public EndEntityCertificateConstraint() {
		this.endEntities = new HashMap<String, Set<BigInteger>>();
	}

	/**
	 * Adds an end-entity certificate to the set of allowed certificates.
	 * 
	 * @param certificate
	 *            the X509 end-entity certificate.
	 */
	public void addEndEntity(X509Certificate certificate) {
		String issuerName = certificate.getIssuerX500Principal().getName();
		BigInteger serialNumber = certificate.getSerialNumber();
		addEndEntity(issuerName, serialNumber);
	}

	/**
	 * Adds an end-entity certificate to the set of allowed certificates.
	 * 
	 * @param issuerName
	 *            the X.500 distinguished name of the issuer using the format
	 *            defined in RFC 2253.
	 * @param serialNumber
	 *            the serial number of the certificate.
	 */
	public void addEndEntity(String issuerName, BigInteger serialNumber) {
		Set<BigInteger> issuerSerials = this.endEntities.get(issuerName);
		if (null == issuerSerials) {
			issuerSerials = new HashSet<BigInteger>();
			this.endEntities.put(issuerName, issuerSerials);
		}
		issuerSerials.add(serialNumber);
	}

	public boolean check(X509Certificate certificate) {
		if (TrustValidator.getSelfSignedResult(certificate).isValid()) {
			return true;
		}
		String issuerName = certificate.getIssuerX500Principal().getName();
		Set<BigInteger> issuerSerials = this.endEntities.get(issuerName);
		if (null == issuerSerials) {
			return false;
		}
		BigInteger serialNumber = certificate.getSerialNumber();
		return issuerSerials.contains(serialNumber);
	}
}
