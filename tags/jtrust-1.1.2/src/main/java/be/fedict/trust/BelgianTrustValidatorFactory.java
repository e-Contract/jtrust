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

import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.trust.constraints.CertificatePoliciesCertificateConstraint;
import be.fedict.trust.constraints.DistinguishedNameCertificateConstraint;
import be.fedict.trust.constraints.KeyUsageCertificateConstraint;
import be.fedict.trust.constraints.QCStatementsCertificateConstraint;
import be.fedict.trust.constraints.TSACertificateConstraint;
import be.fedict.trust.crl.CachedCrlRepository;
import be.fedict.trust.crl.CrlTrustLinker;
import be.fedict.trust.crl.OnlineCrlRepository;
import be.fedict.trust.ocsp.OcspTrustLinker;
import be.fedict.trust.ocsp.OnlineOcspRepository;

/**
 * Trust Validator Factory for Belgian (eID) PKI.
 * 
 * @author Frank Cornelis
 * 
 */
public class BelgianTrustValidatorFactory {

	private static final Log LOG = LogFactory
			.getLog(BelgianTrustValidatorFactory.class);

	/**
	 * Creates a trust validator according to Belgian PKI rules for
	 * authentication certificates.
	 * 
	 * @return a trust validator instance.
	 */
	public static TrustValidator createTrustValidator() {
		return createTrustValidator(null);
	}

	/**
	 * Creates a trust validator according to Belgian PKI rules for
	 * authentication certificates.
	 * 
	 * @param networkConfig
	 *            the optional network configuration to be used.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createTrustValidator(
			NetworkConfig networkConfig) {
		TrustValidator trustValidator = createTrustValidator(networkConfig,
				null);
		return trustValidator;
	}

	private enum CertificateType {
		AUTHN, SIGN, NATIONAL_REGISTRY
	};

	/**
	 * Creates a trust validator according to Belgian PKI rules for
	 * authentication certificates.
	 * 
	 * <p>
	 * Via the external trust linker one can implement a CRL fetcher validation
	 * architecture based on Java EE.
	 * </p>
	 * 
	 * @param networkConfig
	 *            the optional network configuration to be used.
	 * @param externalTrustLinker
	 *            the optional external trust linker to be used.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createTrustValidator(
			NetworkConfig networkConfig, TrustLinker externalTrustLinker) {
		TrustValidator trustValidator = createTrustValidator(
				CertificateType.AUTHN, networkConfig, externalTrustLinker, null);

		return trustValidator;
	}

	/**
	 * Creates a trust validator according to Belgian PKI rules for
	 * non-repudiation certificates.
	 * 
	 * @param networkConfig
	 *            the optional network configuration to be used.
	 * @param externalTrustLinker
	 *            the optional external trust linker to be used.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createNonRepudiationTrustValidator(
			NetworkConfig networkConfig, TrustLinker externalTrustLinker) {
		TrustValidator trustValidator = createTrustValidator(
				CertificateType.SIGN, networkConfig, externalTrustLinker, null);

		return trustValidator;
	}

	/**
	 * Creates a trust validator according to Belgian PKI rules for
	 * non-repudiation certificates.
	 * 
	 * @param networkConfig
	 *            the optional network configuration to be used.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createNonRepudiationTrustValidator(
			NetworkConfig networkConfig) {
		TrustValidator trustValidator = createTrustValidator(
				CertificateType.SIGN, networkConfig, null, null);

		return trustValidator;
	}

	/**
	 * Creates a trust validator according to Belgian PKI rules for the national
	 * registry certificate.
	 * 
	 * @param networkConfig
	 *            the optional network configuration to be used.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createNationalRegistryTrustValidator(
			NetworkConfig networkConfig) {
		TrustValidator trustValidator = createTrustValidator(
				CertificateType.NATIONAL_REGISTRY, networkConfig, null, null);

		return trustValidator;
	}

	/**
	 * Creates a trust validator according to Belgian PKI rules for TSA
	 * certificates.
	 * 
	 * @param networkConfig
	 *            the optional network configuration to be used.
	 * @param externalTrustLinker
	 *            the optional external trust linker to be used.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createTSATrustValidator(
			NetworkConfig networkConfig, TrustLinker externalTrustLinker) {

		MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
		X509Certificate rootTsaCertificate = loadCertificate("be/fedict/trust/belgiumtsa.crt");
		memoryCertificateRepository.addTrustPoint(rootTsaCertificate);

		TrustValidator trustValidator = new TrustValidator(
				memoryCertificateRepository);

		// add trust linkers
		trustValidator.addTrustLinker(new PublicKeyTrustLinker());

		OnlineOcspRepository ocspRepository = new OnlineOcspRepository(
				networkConfig);

		OnlineCrlRepository crlRepository = new OnlineCrlRepository(
				networkConfig);
		CachedCrlRepository cachedCrlRepository = new CachedCrlRepository(
				crlRepository);

		FallbackTrustLinker fallbackTrustLinker = new FallbackTrustLinker();
		if (null != externalTrustLinker) {
			fallbackTrustLinker.addTrustLinker(externalTrustLinker);
		}
		fallbackTrustLinker.addTrustLinker(new OcspTrustLinker(ocspRepository));
		fallbackTrustLinker.addTrustLinker(new CrlTrustLinker(
				cachedCrlRepository));

		trustValidator.addTrustLinker(fallbackTrustLinker);

		// add certificate constraints
		trustValidator.addCertificateConstrain(new TSACertificateConstraint());

		return trustValidator;
	}

	/**
	 * Creates a trust validator according to Belgian PKI rules for
	 * authentication certificates.
	 * 
	 * <p>
	 * Via the external trust linker one can implement a CRL fetcher validation
	 * architecture based on Java EE.
	 * </p>
	 * 
	 * @param networkConfig
	 *            the optional network configuration to be used.
	 * @param externalTrustLinker
	 *            the optional external trust linker to be used.
	 * @param certificateRepository
	 *            containing the Belgian eID trust points.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createTrustValidator(
			NetworkConfig networkConfig, TrustLinker externalTrustLinker,
			CertificateRepository certificateRepository) {
		return createTrustValidator(CertificateType.AUTHN, networkConfig,
				externalTrustLinker, certificateRepository);
	}

	private static TrustValidator createTrustValidator(
			CertificateType certificateType, NetworkConfig networkConfig,
			TrustLinker externalTrustLinker,
			CertificateRepository certificateRepository) {

		TrustValidator trustValidator;
		if (null == certificateRepository) {
			// trust points
			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			X509Certificate rootCaCertificate = loadCertificate("be/fedict/trust/belgiumrca.crt");
			memoryCertificateRepository.addTrustPoint(rootCaCertificate);
			X509Certificate rootCa2Certificate = loadCertificate("be/fedict/trust/belgiumrca2.crt");
			memoryCertificateRepository.addTrustPoint(rootCa2Certificate);

			trustValidator = new TrustValidator(memoryCertificateRepository);
		} else {
			trustValidator = new TrustValidator(certificateRepository);
		}

		trustValidator.addTrustLinker(new PublicKeyTrustLinker());

		OnlineOcspRepository ocspRepository = new OnlineOcspRepository(
				networkConfig);

		OnlineCrlRepository crlRepository = new OnlineCrlRepository(
				networkConfig);
		CachedCrlRepository cachedCrlRepository = new CachedCrlRepository(
				crlRepository);

		FallbackTrustLinker fallbackTrustLinker = new FallbackTrustLinker();
		if (null != externalTrustLinker) {
			fallbackTrustLinker.addTrustLinker(externalTrustLinker);
		}
		fallbackTrustLinker.addTrustLinker(new OcspTrustLinker(ocspRepository));
		fallbackTrustLinker.addTrustLinker(new CrlTrustLinker(
				cachedCrlRepository));

		trustValidator.addTrustLinker(fallbackTrustLinker);

		KeyUsageCertificateConstraint keyUsageCertificateConstraint = new KeyUsageCertificateConstraint();
		switch (certificateType) {
		case AUTHN:
			keyUsageCertificateConstraint.setDigitalSignatureFilter(true);
			keyUsageCertificateConstraint.setNonRepudiationFilter(false);
			break;
		case SIGN:
			keyUsageCertificateConstraint.setDigitalSignatureFilter(false);
			keyUsageCertificateConstraint.setNonRepudiationFilter(true);
			break;
		case NATIONAL_REGISTRY:
			keyUsageCertificateConstraint.setDigitalSignatureFilter(true);
			keyUsageCertificateConstraint.setNonRepudiationFilter(true);
			break;
		}
		trustValidator.addCertificateConstrain(keyUsageCertificateConstraint);

		CertificatePoliciesCertificateConstraint certificatePoliciesCertificateConstraint = new CertificatePoliciesCertificateConstraint();
		switch (certificateType) {
		case AUTHN:
			// RootCA citizen authn
			certificatePoliciesCertificateConstraint
					.addCertificatePolicy("2.16.56.1.1.1.2.2");
			// RootCA foreigner authn
			certificatePoliciesCertificateConstraint
					.addCertificatePolicy("2.16.56.1.1.1.7.2");
			// RootCA2 citizen authn
			certificatePoliciesCertificateConstraint
					.addCertificatePolicy("2.16.56.9.1.1.2.2");
			// RootCA2 foreigner authn
			certificatePoliciesCertificateConstraint
					.addCertificatePolicy("2.16.56.9.1.1.7.2");
			break;
		case SIGN:
			// RootCA citizen sign
			certificatePoliciesCertificateConstraint
					.addCertificatePolicy("2.16.56.1.1.1.2.1");
			// RootCA foreigner sign
			certificatePoliciesCertificateConstraint
					.addCertificatePolicy("2.16.56.1.1.1.7.1");
			// RootCA2 citizen sign
			certificatePoliciesCertificateConstraint
					.addCertificatePolicy("2.16.56.9.1.1.2.1");
			// RootCA2 foreigner sign
			certificatePoliciesCertificateConstraint
					.addCertificatePolicy("2.16.56.9.1.1.7.1");
			break;
		case NATIONAL_REGISTRY:
			certificatePoliciesCertificateConstraint
					.addCertificatePolicy("2.16.56.1.1.1.4");
			certificatePoliciesCertificateConstraint
					.addCertificatePolicy("2.16.56.9.1.1.4");
			break;
		}
		trustValidator
				.addCertificateConstrain(certificatePoliciesCertificateConstraint);

		if (CertificateType.NATIONAL_REGISTRY == certificateType) {
			DistinguishedNameCertificateConstraint nameConstraint = new DistinguishedNameCertificateConstraint(
					"CN=RRN, O=RRN, C=BE");
			trustValidator.addCertificateConstrain(nameConstraint);
		}

		if (CertificateType.SIGN == certificateType) {
			QCStatementsCertificateConstraint qcStatementsCertificateConstraint = new QCStatementsCertificateConstraint(
					true);
			trustValidator
					.addCertificateConstrain(qcStatementsCertificateConstraint);
		}

		return trustValidator;
	}

	private static X509Certificate loadCertificate(String resourceName) {
		LOG.debug("loading certificate: " + resourceName);
		Thread currentThread = Thread.currentThread();
		ClassLoader classLoader = currentThread.getContextClassLoader();
		InputStream certificateInputStream = classLoader
				.getResourceAsStream(resourceName);
		if (null == certificateInputStream) {
			throw new IllegalArgumentException("resource not found: "
					+ resourceName);
		}
		try {
			CertificateFactory certificateFactory = CertificateFactory
					.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) certificateFactory
					.generateCertificate(certificateInputStream);
			return certificate;
		} catch (CertificateException e) {
			throw new RuntimeException("X509 error: " + e.getMessage(), e);
		}
	}
}
