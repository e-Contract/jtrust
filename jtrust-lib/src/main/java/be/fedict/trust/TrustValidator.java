/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import be.fedict.trust.linker.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.trust.constraints.CertificateConstraint;
import be.fedict.trust.policy.AlgorithmPolicy;
import be.fedict.trust.policy.DefaultAlgorithmPolicy;
import be.fedict.trust.repository.CertificateRepository;
import be.fedict.trust.revocation.RevocationData;

/**
 * Trust Validator.
 * <p>
 * Note that this component is not thread-safe as it is using internal state.
 * </p>
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

	private AlgorithmPolicy algorithmPolicy;

	/**
	 * Main constructor.
	 * 
	 * @param certificateRepository
	 *            the certificate repository used by this trust validator.
	 */
	public TrustValidator(CertificateRepository certificateRepository) {
		this(certificateRepository, null);
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
		this.trustLinkers = new LinkedList<>();
		this.certificateConstraints = new LinkedList<>();
		this.revocationData = revocationData;
		this.algorithmPolicy = new DefaultAlgorithmPolicy();
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
	 * Sets the algorithm policy to be used when validation used signature
	 * algorithms.
	 * 
	 * @param algorithmPolicy
	 *            the algorithm policy component.
	 */
	public void setAlgorithmPolicy(AlgorithmPolicy algorithmPolicy) {
		this.algorithmPolicy = algorithmPolicy;
	}

	/**
	 * Adds a certificate constraint to this trust validator.
	 * Keep this typo-version of addCertificateContrainT for downwards compatibility.
	 * 
	 * @param certificateConstraint
	 *            the certificate constraint component.
	 */
	public void addCertificateConstrain(
			CertificateConstraint certificateConstraint) {
		this.certificateConstraints.add(certificateConstraint);
	}

	/**
	 * Adds a certificate constraint to this trust validator.
	 *
	 * @param certificateConstraint
	 *            the certificate constraint component.
	 */
	public void addCertificateConstraint(
			CertificateConstraint certificateConstraint) {
		this.certificateConstraints.add(certificateConstraint);
	}

	/**
	 * Validates whether the given certificate path is valid according to the
	 * configured trust linkers.
	 * 
	 * @param certificatePath
	 *            the X509 certificate path to validate.
	 * @throws TrustLinkerResultException
	 *             in case the certificate path is invalid.
	 * @see #isTrusted(List, Date)
	 */
	public void isTrusted(List<X509Certificate> certificatePath)
			throws TrustLinkerResultException {
		isTrusted(certificatePath, new Date());
	}

	/**
	 * Validates whether the given certificate path is valid according to the
	 * configured trust linkers. Convenience method when loading a certificate
	 * chain directly from a JCA key store implementation.
	 * 
	 * @param certificates
	 * @throws be.fedict.trust.linker.TrustLinkerResultException
	 */
	public void isTrusted(Certificate[] certificates)
			throws TrustLinkerResultException {
		List<X509Certificate> certificateChain = new LinkedList<>();
		for (Certificate certificate : certificates) {
			X509Certificate x509Certificate = (X509Certificate) certificate;
			certificateChain.add(x509Certificate);
		}
		isTrusted(certificateChain);
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
	 * Checks whether the given certificate is self-signed.
	 * 
	 * @param certificate
	 *            the X509 certificate.
	 */
	public static void isSelfSigned(X509Certificate certificate)
			throws TrustLinkerResultException {
		checkSelfSigned(certificate);
	}

	/**
	 * Gives back the trust linker result of a verification of a self-signed
	 * X509 certificate.
	 * 
	 * @param certificate
	 *            the self-signed certificate to validate.
	 */
	public static void checkSelfSigned(X509Certificate certificate)
			throws TrustLinkerResultException {
		if (false == certificate.getIssuerX500Principal().equals(
				certificate.getSubjectX500Principal())) {
			throw new TrustLinkerResultException(
					TrustLinkerResultReason.NO_TRUST,
					"root certificate should be self-signed: "
							+ certificate.getSubjectX500Principal());
		}
		try {
			CustomCertSignValidator.verify(certificate);
		} catch (Exception e) {
			throw new TrustLinkerResultException(
					TrustLinkerResultReason.INVALID_SIGNATURE,
					"certificate signature error: " + e.getMessage());
		}
	}

	private void checkSignatureAlgorithm(String signatureAlgorithm,
			Date validationDate) throws TrustLinkerResultException {
		try {
			this.algorithmPolicy.checkSignatureAlgorithm(signatureAlgorithm,
					validationDate);
		} catch (TrustLinkerResultException e) {
			// re-wrapping this type of exception doesn't bring anything
			throw e;
		} catch (Exception e) {
			throw new TrustLinkerResultException(
					TrustLinkerResultReason.INVALID_ALGORITHM,
					"Invalid signature algorithm: " + signatureAlgorithm);
		}
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
	public void isTrusted(List<X509Certificate> certificatePath,
			Date validationDate) throws TrustLinkerResultException {
		if (certificatePath.isEmpty()) {
			throw new TrustLinkerResultException(
					TrustLinkerResultReason.UNSPECIFIED,
					"certificate path is empty");
		}
		for (X509Certificate certificate : certificatePath) {
			if (null == certificate) {
				throw new TrustLinkerResultException(
						TrustLinkerResultReason.UNSPECIFIED,
						"certificate path contains null certificate");
			}
		}

		int certIdx = certificatePath.size() - 1;
		X509Certificate certificate = certificatePath.get(certIdx);
		LOG.debug("verifying root certificate: "
				+ certificate.getSubjectX500Principal());
		checkSelfSigned(certificate);
		// check certificate signature
		checkSignatureAlgorithm(certificate.getSigAlgName(), validationDate);
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
			try {
				certificateConstraint.check(certificate);
			} catch (TrustLinkerResultException e) {
				// let this specific type of exception pass as is
				throw e;
			} catch (Exception e) {
				throw new TrustLinkerResultException(
						TrustLinkerResultReason.UNSPECIFIED,
						"certificate constraint error "
								+ certificateConstraintName + ": "
								+ e.getMessage(), e);
			}
		}
	}

	private void checkTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate)
			throws TrustLinkerResultException {
		if (null == childCertificate) {
			return;
		}
		// check certificate signature
		checkSignatureAlgorithm(childCertificate.getSigAlgName(),
				validationDate);

		boolean sometrustLinkerTrusts = false;
		for (TrustLinker trustLinker : this.trustLinkers) {
			LOG.debug("trying trust linker: "
					+ trustLinker.getClass().getSimpleName());
			TrustLinkerResult trustLinkerResult;
			try {
				trustLinkerResult = trustLinker.hasTrustLink(childCertificate,
						certificate, validationDate, this.revocationData,
						this.algorithmPolicy);
			} catch (TrustLinkerResultException e) {
				// we let this type of exception pass as is
				throw e;
			} catch (Exception e) {
				throw new TrustLinkerResultException(
						TrustLinkerResultReason.UNSPECIFIED,
						"trust linker error: " + e.getMessage(), e);
			}
			if (null == trustLinkerResult) {
				LOG.warn("trust linker result should not be NULL");
			}
			if (TrustLinkerResult.TRUSTED == trustLinkerResult) {
				// we don't break as there still might be a trust linker that
				// complains
				sometrustLinkerTrusts = true;
			}
		}
		if (false == sometrustLinkerTrusts) {
			throw new TrustLinkerResultException(
					TrustLinkerResultReason.NO_TRUST, "no trust between "
							+ childCertificate.getSubjectX500Principal()
							+ " and " + certificate.getSubjectX500Principal());
		}
	}

	private void checkSelfSignedTrust(X509Certificate certificate,
			Date validationDate) throws TrustLinkerResultException {
		try {
			certificate.checkValidity(validationDate);
		} catch (Exception e) {
			throw new TrustLinkerResultException(
					TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
					"certificate validity error: " + e.getMessage());
		}
		if (this.certificateRepository.isTrustPoint(certificate)) {
			return;
		}
		throw new TrustLinkerResultException(TrustLinkerResultReason.ROOT,
				"self-signed certificate not in repository: "
						+ certificate.getSubjectX500Principal());
	}

	/**
	 * Sets the revocation data container used by this trust validator while
	 * validating certificate chains.
	 * 
	 * @param revocationData
	 */
	public void setRevocationData(RevocationData revocationData) {
		this.revocationData = revocationData;
	}
}
