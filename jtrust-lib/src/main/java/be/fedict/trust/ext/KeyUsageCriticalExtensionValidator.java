/*
 * Java Trust Project.
 * Copyright (C) 2022-2023 e-Contract.be BV.
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
package be.fedict.trust.ext;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;

public class KeyUsageCriticalExtensionValidator implements CriticalExtensionValidator {

	private static final Logger LOGGER = LoggerFactory.getLogger(KeyUsageCriticalExtensionValidator.class);

	@Override
	public void process(X509Certificate certificate) throws TrustLinkerResultException {
		Certificate bcCertificate;
		try {
			bcCertificate = Certificate.getInstance(ASN1Primitive.fromByteArray(certificate.getEncoded()));
		} catch (CertificateEncodingException | IOException ex) {
			LOGGER.error("error: " + ex.getMessage(), ex);
			throw new TrustLinkerResultException(TrustLinkerResultReason.UNSPECIFIED, "error");
		}
		X509CertificateHolder certificateHolder = new X509CertificateHolder(bcCertificate);
		KeyUsage keyUsage = KeyUsage.fromExtensions(certificateHolder.getExtensions());
		LOGGER.debug("key usage: {}", keyUsage);
		boolean usages = keyUsage.hasUsages(KeyUsage.cRLSign | KeyUsage.keyCertSign);
		if (!usages) {
			throw new TrustLinkerResultException(TrustLinkerResultReason.NO_TRUST,
					"incorrect key usage " + keyUsage + " for certificate " + certificate.getSubjectX500Principal());
		}
	}
}
