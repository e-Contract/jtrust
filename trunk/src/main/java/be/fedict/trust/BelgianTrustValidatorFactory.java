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

/**
 * Trust Validator Factory for Belgian (eID) PKI.
 * 
 * @author Frank Cornelis
 * 
 */
public class BelgianTrustValidatorFactory {

	private static final Log LOG = LogFactory
			.getLog(BelgianTrustValidatorFactory.class);

	private BelgianTrustValidatorFactory() {
		super();
	}

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
		// trust points
		MemoryCertificateRepository certificateRepository = new MemoryCertificateRepository();
		X509Certificate rootCaCertificate = loadCertificate("be/fedict/trust/belgiumrca.crt");
		certificateRepository.addTrustPoint(rootCaCertificate);
		X509Certificate rootCa2Certificate = loadCertificate("be/fedict/trust/belgiumrca2.crt");
		certificateRepository.addTrustPoint(rootCa2Certificate);

		TrustValidator trustValidator = new TrustValidator(
				certificateRepository);

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
		keyUsageCertificateConstraint.setDigitalSignatureFilter(true);
		keyUsageCertificateConstraint.setNonRepudiationFilter(false);
		trustValidator.addCertificateConstrain(keyUsageCertificateConstraint);

		CertificatePoliciesCertificateConstraint certificatePoliciesCertificateConstraint = new CertificatePoliciesCertificateConstraint();
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
		trustValidator
				.addCertificateConstrain(certificatePoliciesCertificateConstraint);

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
