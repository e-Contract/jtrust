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

	private TrustLinkerResult result;

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
		this.revocationData = null;
		this.result = null;
	}

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
	public TrustValidator(CertificateRepository certificateRepository,
			RevocationData revocationData) {
		this.certificateRepository = certificateRepository;
		this.trustLinkers = new LinkedList<TrustLinker>();
		this.certificateConstraints = new LinkedList<CertificateConstraint>();
		this.revocationData = revocationData;
		this.result = null;
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
	 * Returns the {@link RevocationData} returned by the configured
	 * {@link TrustLinker}'s if a {@link RevocationData} object was specified in
	 * the constructor.
	 * 
	 * @return {@link RevocationData}
	 */
	public RevocationData getRevocationData() {

		return this.revocationData;
	}

	/**
	 * Returns the {@link TrustLinkerResult} of the last validation.
	 * 
	 * @return {@link TrustLinkerResult}
	 */
	public TrustLinkerResult getResult() {

		return this.result;
	}

	/**
	 * Checks whether the given certificate is self-signed.
	 * 
	 * @param certificate
	 *            the X509 certificate.
	 * @return <code>true</code> if self-signed, <code>false</code> otherwise.
	 */
	public static boolean isSelfSigned(X509Certificate certificate) {

		return getSelfSignedResult(certificate).isValid();
	}

	public static TrustLinkerResult getSelfSignedResult(
			X509Certificate certificate) {

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
	 * Checks whether given signature algorithm is allowed. MD5 for example is
	 * not
	 * 
	 * @param signatureAlgorithm
	 */
	public static TrustLinkerResult checkSignatureAlgorithm(
			String signatureAlgorithm) {

		LOG.debug("validate signature algorithm: " + signatureAlgorithm);
		// disallow MD5 certificate signatures
		if (signatureAlgorithm.contains("MD5")
				|| signatureAlgorithm.equals("1.2.840.113549.1.1.4")) {
			return new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_SIGNATURE,
					"Invalid signature algorithm: " + signatureAlgorithm);
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
	 * @throws CertPathValidatorException
	 *             in case of an invalid certificate path.
	 * @see #isTrusted(List)
	 */
	public void isTrusted(List<X509Certificate> certificatePath,
			Date validationDate) throws CertPathValidatorException {
		if (certificatePath.isEmpty()) {
			this.result = new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_TRUST,
					"certificate path is empty");
			throw new CertPathValidatorException(this.result.getMessage());
		}

		int certIdx = certificatePath.size() - 1;
		X509Certificate certificate = certificatePath.get(certIdx);
		LOG.debug("verifying root certificate: "
				+ certificate.getSubjectX500Principal());
		this.result = getSelfSignedResult(certificate);
		if (!this.result.isValid()) {
			LOG.debug("result: " + this.result.getMessage());
			throw new CertPathValidatorException(this.result.getMessage());
		}
		// check certificate signature
		this.result = checkSignatureAlgorithm(certificate.getSigAlgName());
		if (!this.result.isValid()) {
			LOG.debug("result: " + this.result.getMessage());
			throw new CertPathValidatorException(this.result.getMessage());
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
				this.result = new TrustLinkerResult(false,
						TrustLinkerResultReason.INVALID_TRUST,
						"certificate constraint failure: "
								+ certificateConstraintName);
				throw new CertPathValidatorException(this.result.getMessage());
			}
		}

		this.result = new TrustLinkerResult(true);
	}

	private void checkTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate)
			throws CertPathValidatorException {
		if (null == childCertificate) {
			return;
		}
		// check certificate signature
		this.result = checkSignatureAlgorithm(childCertificate.getSigAlgName());
		if (!this.result.isValid()) {
			throw new CertPathValidatorException(this.result.getMessage());
		}

		boolean sometrustLinkerTrusts = false;
		for (TrustLinker trustLinker : this.trustLinkers) {

			this.result = trustLinker.hasTrustLink(childCertificate,
					certificate, validationDate, this.revocationData);
			if (null == this.result) {
				continue;
			}
			if (this.result.isValid()) {
				sometrustLinkerTrusts = true;
			} else {
				throw new CertPathValidatorException(this.result.getMessage());
			}
		}
		if (false == sometrustLinkerTrusts) {
			this.result = new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_TRUST, "no trust between "
							+ childCertificate.getSubjectX500Principal()
							+ " and " + certificate.getSubjectX500Principal());
			throw new CertPathValidatorException(this.result.getMessage());
		}
	}

	private void checkSelfSignedTrust(X509Certificate certificate,
			Date validationDate) throws CertPathValidatorException {
		try {
			certificate.checkValidity(validationDate);
		} catch (Exception e) {
			this.result = new TrustLinkerResult(false,
					TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
					"certificate validity error: " + e.getMessage());
			throw new CertPathValidatorException(this.result.getMessage());
		}
		if (this.certificateRepository.isTrustPoint(certificate)) {
			return;
		}

		this.result = new TrustLinkerResult(false,
				TrustLinkerResultReason.INVALID_TRUST,
				"self-signed certificate not in repository: "
						+ certificate.getSubjectX500Principal());
		throw new CertPathValidatorException(this.result.getMessage());
	}
}
