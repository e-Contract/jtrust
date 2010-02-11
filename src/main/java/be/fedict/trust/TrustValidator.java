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
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Trust Validator.
 * 
 * @author Frank Cornelis
 * 
 */
public class TrustValidator {

	private static final Log LOG = LogFactory.getLog(TrustValidator.class);

	private final CertificateRepository certificateRepository;

	private final List<TrustLinker> trustLinkers;

	private final List<CertificateConstraint> certificateConstraints;

	/**
	 * Main constructor.
	 * 
	 * @param certificateRepository
	 *            the certificate repository used by this trust validator.
	 */
	public TrustValidator(CertificateRepository certificateRepository) {
		this.certificateRepository = certificateRepository;
		this.trustLinkers = new LinkedList<TrustLinker>();
		this.certificateConstraints = new LinkedList<CertificateConstraint>();
	}

	/**
	 * Adds a trust linker to this trust validator. The order in which trust
	 * linkers are added determine the runtime behavior of the trust validator.
	 * 
	 * @param trustLinker
	 *            the trust linker component.
	 */
	public void addTrustLinker(TrustLinker trustLinker) {
		this.trustLinkers.add(trustLinker);
	}

	/**
	 * Adds a certificate constraint to this trust validator.
	 * 
	 * @param certificateConstraint
	 *            the certificate constraint component.
	 */
	public void addCertificateConstrain(
			CertificateConstraint certificateConstraint) {
		this.certificateConstraints.add(certificateConstraint);
	}

	/**
	 * Validates whether the given certificate path is valid according to the
	 * configured trust linkers.
	 * 
	 * @param certificatePath
	 *            the X509 certificate path to validate.
	 * @throws CertPathValidatorException
	 *             in case the certificate path is invalid.
	 * @see #isTrusted(List, Date)
	 */
	public void isTrusted(List<X509Certificate> certificatePath)
			throws CertPathValidatorException {
		isTrusted(certificatePath, new Date());
	}

	/**
	 * Checks whether the given certificate is self-signed.
	 * 
	 * @param certificate
	 *            the X509 certificate.
	 * @return <code>true</code> if self-signed, <code>false</code> otherwise.
	 * @throws CertPathValidatorException
	 */
	public static boolean isSelfSigned(X509Certificate certificate)
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

	/**
	 * Validates whether the certificate path was valid at the given validation
	 * date.
	 * 
	 * @param certificatePath
	 *            the X509 certificate path to be validated.
	 * @param validationDate
	 *            the date at which the certificate path validation should be
	 *            verified.
	 * @throws CertPathValidatorException
	 *             in case of an invalid certificate path.
	 * @see #isTrusted(List)
	 */
	public void isTrusted(List<X509Certificate> certificatePath,
			Date validationDate) throws CertPathValidatorException {
		if (certificatePath.isEmpty()) {
			throw new CertPathValidatorException("certificate path is empty");
		}

		int certIdx = certificatePath.size() - 1;
		X509Certificate certificate = certificatePath.get(certIdx);
		LOG.debug("verifying root certificate: "
				+ certificate.getSubjectX500Principal());
		if (false == isSelfSigned(certificate)) {
			throw new CertPathValidatorException(
					"root certificate should be self-signed: "
							+ certificate.getSubjectX500Principal());
		}
		checkSelfSignedTrust(certificate, validationDate);
		certIdx--;

		while (certIdx >= 0) {
			X509Certificate childCertificate = certificatePath.get(certIdx);
			LOG.debug("verifying certificate: "
					+ childCertificate.getSubjectX500Principal());
			certIdx--;
			checkTrustLink(childCertificate, certificate, validationDate);
			certificate = childCertificate;
		}

		for (CertificateConstraint certificateConstraint : this.certificateConstraints) {
			String certificateConstraintName = certificateConstraint.getClass()
					.getSimpleName();
			LOG.debug("certificate constraint check: "
					+ certificateConstraintName);
			if (false == certificateConstraint.check(certificate)) {
				throw new CertPathValidatorException(
						"certificate constraint failure: "
								+ certificateConstraintName);
			}
		}
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
			if (null == trusted) {
				continue;
			}
			if (trusted) {
				sometrustLinkerTrusts = true;
			} else {
				throw new CertPathValidatorException("untrusted between "
						+ childCertificate.getSubjectX500Principal() + " and "
						+ certificate.getSubjectX500Principal());
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
				"self-signed certificate not in repository: "
						+ certificate.getSubjectX500Principal());
	}
}
