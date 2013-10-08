/*
 * Java Trust Project.
 * Copyright (C) 2012 FedICT.
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

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extension;

import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;

/**
 * Certificate constraint for code signing certificates.
 * 
 * @author Frank Cornelis
 */
public class CodeSigningCertificateConstraint implements CertificateConstraint {

	@Override
	public void check(X509Certificate certificate)
			throws TrustLinkerResultException, Exception {
		byte[] extension = certificate
				.getExtensionValue(X509Extension.extendedKeyUsage.getId());
		if (null == extension) {
			throw new TrustLinkerResultException(
					TrustLinkerResultReason.CONSTRAINT_VIOLATION,
					"missing ExtendedKeyUsage extension");
		}
		if (false == certificate.getCriticalExtensionOIDs().contains(
				X509Extension.extendedKeyUsage.getId())) {
			throw new TrustLinkerResultException(
					TrustLinkerResultReason.CONSTRAINT_VIOLATION,
					"ExtendedKeyUsage should be critical");
		}
		ASN1InputStream asn1InputStream = new ASN1InputStream(
				new ByteArrayInputStream(extension));
		asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(
				((ASN1OctetString) asn1InputStream.readObject()).getOctets()));
		ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage
				.getInstance(asn1InputStream.readObject());
		if (false == extendedKeyUsage
				.hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning)) {
			throw new TrustLinkerResultException(
					TrustLinkerResultReason.CONSTRAINT_VIOLATION,
					"missing codeSigning ExtendedKeyUsage");
		}
		if (1 != extendedKeyUsage.size()) {
			throw new TrustLinkerResultException(
					TrustLinkerResultReason.CONSTRAINT_VIOLATION,
					"ExtendedKeyUsage not solely codeSigning");
		}
	}
}
