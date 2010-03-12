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

	private RevocationData revocationData;

	/**
	 * Main constructor.
	 * 
	 * @param certificateRepository
	 *            the certificate repository used by this trust validator.
	 * @param revocationData
	 *            optional {@link RevocationData} object. If not
	 *            <code>null</code> the added {@link TrustLinker}'s should fill
	 *            it up with used revocation data.
	 */
	public TrustValidator(CertificateRepository certificateRepository) {
		this.certificateRepository = certificateRepository;
		this.trustLinkers = new LinkedList<TrustLinker>();
		this.certificateConstraints = new LinkedList<CertificateConstraint>();
		this.revocationData = null;
	}

	/**
	 * Main constructor.
	 * 
	 * @param certificateRepository
	 *            the certificate repository used by this trust validator.
	 * @param revocationData
	 *            The added {@link TrustLinker}'s should fill it up with used
	 *            revocation data.
	 */
	public TrustValidator(CertificateRepository certificateRepository,
			RevocationData revocationData) {
		this.certificateRepository = certificateRepository;
		this.trustLinkers = new LinkedList<TrustLinker>();
		this.certificateConstraints = new LinkedList<CertificateConstraint>();
		this.revocationData = revocationData;
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
	public TrustLinkerResult isTrusted(List<X509Certificate> certificatePath) {
		return isTrusted(certificatePath, new Date());
	}

	/**
	 * Returns the {@link RevocationData} returned by the configured
	 * {@link TrustLinker}'s.
	 * 
	 * @return {@link RevocationData}
	 */
	public RevocationData getRevocationData() {

		return this.revocationData;
	}

	/**
	 * Checks whether the given certificate is self-signed.
	 * 
	 * @param certificate
	 *            the X509 certificate.
	 * @return <code>true</code> if self-signed, <code>false</code> otherwise.
	 */
	public static TrustLinkerResult isSelfSigned(X509Certificate certificate) {
		if (false == certificate.getIssuerX500Principal().equals(
				certificate.getSubjectX500Principal())) {
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_TRUST,
					"root certificate should be self-signed: "
							+ certificate.getSubjectX500Principal());
		}
		try {
			certificate.verify(certificate.getPublicKey());
		} catch (Exception e) {
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_SIGNATURE,
					"certificate signature error: " + e.getMessage());
		}
		return new TrustLinkerResult(true);
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
	 * @see #isTrusted(List)
	 */
	public TrustLinkerResult isTrusted(List<X509Certificate> certificatePath,
			Date validationDate) {
		if (certificatePath.isEmpty()) {
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_TRUST,
					"certificate path is empty");
		}

		int certIdx = certificatePath.size() - 1;
		X509Certificate certificate = certificatePath.get(certIdx);
		LOG.debug("verifying root certificate: "
				+ certificate.getSubjectX500Principal());
		TrustLinkerResult result = isSelfSigned(certificate);
		if (!result.isValid()) {
			return result;
		}
		result = checkSelfSignedTrust(certificate, validationDate);
		if (!result.isValid()) {
			return result;
		}
		certIdx--;

		while (certIdx >= 0) {
			X509Certificate childCertificate = certificatePath.get(certIdx);
			LOG.debug("verifying certificate: "
					+ childCertificate.getSubjectX500Principal());
			certIdx--;
			result = checkTrustLink(childCertificate, certificate,
					validationDate);
			if (!result.isValid()) {
				return result;
			}
			certificate = childCertificate;
		}

		for (CertificateConstraint certificateConstraint : this.certificateConstraints) {
			String certificateConstraintName = certificateConstraint.getClass()
					.getSimpleName();
			LOG.debug("certificate constraint check: "
					+ certificateConstraintName);
			if (false == certificateConstraint.check(certificate)) {
				return new TrustLinkerResult(false,
						TrustLinkerResultReason.INVALID_TRUST,
						"certificate constraint failure: "
								+ certificateConstraintName);
			}
		}
		return new TrustLinkerResult(true);
	}

	private TrustLinkerResult checkTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate) {
		if (null == childCertificate) {
			return new TrustLinkerResult(true);
		}
		boolean sometrustLinkerTrusts = false;
		for (TrustLinker trustLinker : this.trustLinkers) {
			TrustLinkerResult trustResult = trustLinker.hasTrustLink(
					childCertificate, certificate, validationDate,
					this.revocationData);
			if (null == trustResult) {
				continue;
			}
			if (trustResult.isValid()) {
				sometrustLinkerTrusts = true;
			} else {
				return new TrustLinkerResult(false,
						TrustLinkerResultReason.INVALID_TRUST,
						"untrusted between "
								+ childCertificate.getSubjectX500Principal()
								+ " and "
								+ certificate.getSubjectX500Principal());
			}
		}
		if (false == sometrustLinkerTrusts) {
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_TRUST, "no trust between "
							+ childCertificate.getSubjectX500Principal()
							+ " and " + certificate.getSubjectX500Principal());
		}
		return new TrustLinkerResult(true);
	}

	private TrustLinkerResult checkSelfSignedTrust(X509Certificate certificate,
			Date validationDate) {
		try {
			certificate.checkValidity(validationDate);
		} catch (Exception e) {
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
					"certificate validity error: " + e.getMessage());
		}
		if (this.certificateRepository.isTrustPoint(certificate)) {
			return new TrustLinkerResult(true);
		}

		return new TrustLinkerResult(false,
				TrustLinkerResultReason.INVALID_TRUST,
				"self-signed certificate not in repository: "
						+ certificate.getSubjectX500Principal());
	}
}
