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

import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class TrustValidator {

	private final CertificateRepository certificateRepository;

	private final List<TrustLinker> trustLinkers;

	public TrustValidator(CertificateRepository certificateRepository,
			List<TrustLinker> trustLinkers) {
		this.certificateRepository = certificateRepository;
		this.trustLinkers = trustLinkers;
	}

	public TrustValidator(CertificateRepository certificateRepository) {
		this(certificateRepository, new LinkedList<TrustLinker>());
	}

	public void addTrustLinker(TrustLinker trustLinker) {
		this.trustLinkers.add(trustLinker);
	}

	public void isTrusted(List<X509Certificate> certificatePath)
			throws CertPathValidatorException {
		isTrusted(certificatePath, new Date());
	}

	private boolean isSelfSigned(X509Certificate certificate)
			throws CertPathValidatorException {
		if (false == certificate.getIssuerX500Principal().equals(
				certificate.getSubjectX500Principal())) {
			return false;
		}
		try {
			certificate.verify(certificate.getPublicKey());
		} catch (Exception e) {
			throw new CertPathValidatorException(
					"certificate signature error: " + e.getMessage(), e);
		}
		return true;
	}

	public void isTrusted(List<X509Certificate> certificatePath,
			Date validationDate) throws CertPathValidatorException {
		if (certificatePath.isEmpty()) {
			throw new CertPathValidatorException("certificate path is empty");
		}

		Iterator<X509Certificate> certIterator = certificatePath.iterator();
		X509Certificate childCertificate = null;
		while (certIterator.hasNext()) {
			X509Certificate certificate = certIterator.next();
			/*
			 * One of the disadvantages of a bottom-up validation approach is
			 * the risk for denial-of-service attack via the CRL distribution
			 * point extensions.
			 * 
			 * TODO: top-down validation
			 */
			checkTrustLink(childCertificate, certificate, validationDate);
			if (isSelfSigned(certificate)) {
				checkSelfSignedTrust(certificate, validationDate);
				return;
			}
			childCertificate = certificate;
		}

		throw new CertPathValidatorException("no trust");
	}

	private void checkTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate)
			throws CertPathValidatorException {
		if (null == childCertificate) {
			return;
		}
		boolean sometrustLinkerTrusts = false;
		for (TrustLinker trustLinker : this.trustLinkers) {
			Boolean trusted = trustLinker.hasTrustLink(childCertificate,
					certificate, validationDate);
			if (null != trusted) {
				if (trusted) {
					sometrustLinkerTrusts = true;
				} else {
					throw new CertPathValidatorException("no trust between "
							+ childCertificate.getSubjectX500Principal()
							+ " and " + certificate.getSubjectX500Principal());
				}
			}
		}
		if (false == sometrustLinkerTrusts) {
			throw new CertPathValidatorException("no trust between "
					+ childCertificate.getSubjectX500Principal() + " and "
					+ certificate.getSubjectX500Principal());
		}
	}

	private void checkSelfSignedTrust(X509Certificate certificate,
			Date validationDate) throws CertPathValidatorException {
		try {
			certificate.checkValidity(validationDate);
		} catch (Exception e) {
			throw new CertPathValidatorException("certificate validity error: "
					+ e.getMessage(), e);
		}
		if (this.certificateRepository.isTrustPoint(certificate)) {
			return;
		}
		throw new CertPathValidatorException(
				"self-signed certificate not in repository");
	}

}
