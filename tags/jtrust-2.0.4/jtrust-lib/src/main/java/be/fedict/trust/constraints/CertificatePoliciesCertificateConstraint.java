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

package be.fedict.trust.constraints;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.X509Extension;

import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;

/**
 * Certificate Policies certificate constraint implementation.
 * 
 * @author Frank Cornelis
 * 
 */
public class CertificatePoliciesCertificateConstraint implements
		CertificateConstraint {

	private static final Log LOG = LogFactory
			.getLog(CertificatePoliciesCertificateConstraint.class);

	private Set<String> certificatePolicies;

	/**
	 * Default constructor.
	 */
	public CertificatePoliciesCertificateConstraint() {
		this.certificatePolicies = new HashSet<String>();
	}

	/**
	 * Adds a certificate policy OID to this certificate constraint.
	 * 
	 * @param certificatePolicy
	 */
	public void addCertificatePolicy(String certificatePolicy) {
		this.certificatePolicies.add(certificatePolicy);
	}

	public void check(X509Certificate certificate)
			throws TrustLinkerResultException, Exception {
		byte[] extensionValue = certificate
				.getExtensionValue(X509Extension.certificatePolicies.getId());
		if (null == extensionValue) {
			throw new TrustLinkerResultException(
					TrustLinkerResultReason.CONSTRAINT_VIOLATION,
					"missing certificate policies X509 extension");
		}
		DEROctetString oct = (DEROctetString) (new ASN1InputStream(
				new ByteArrayInputStream(extensionValue)).readObject());
		ASN1Sequence certPolicies = (ASN1Sequence) new ASN1InputStream(
				oct.getOctets()).readObject();
		Enumeration<?> certPoliciesEnum = certPolicies.getObjects();
		while (certPoliciesEnum.hasMoreElements()) {
			PolicyInformation policyInfo = PolicyInformation
					.getInstance(certPoliciesEnum.nextElement());
			DERObjectIdentifier policyOid = policyInfo.getPolicyIdentifier();
			String policyId = policyOid.getId();
			LOG.debug("present policy OID: " + policyId);
			if (this.certificatePolicies.contains(policyId)) {
				LOG.debug("matching certificate policy OID: " + policyId);
				return;
			}
		}
		throw new TrustLinkerResultException(
				TrustLinkerResultReason.CONSTRAINT_VIOLATION,
				"required policy OID not present");
	}
}
