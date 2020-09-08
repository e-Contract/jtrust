/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2013-2020 e-Contract.be BV.
 * Copyright (C) 2017 Corilus NV.
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.constraints.CertificatePoliciesCertificateConstraint;
import be.fedict.trust.constraints.DistinguishedNameCertificateConstraint;
import be.fedict.trust.constraints.KeyUsageCertificateConstraint;
import be.fedict.trust.constraints.QCStatementsCertificateConstraint;
import be.fedict.trust.constraints.TSACertificateConstraint;
import be.fedict.trust.crl.CrlRepository;
import be.fedict.trust.linker.TrustLinker;
import be.fedict.trust.repository.CertificateRepository;
import be.fedict.trust.repository.MemoryCertificateRepository;

/**
 * Trust Validator Factory for Belgian (eID) PKI.
 * 
 * @author Frank Cornelis
 * @author Dennis Wagelaar
 */
public class BelgianTrustValidatorFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(BelgianTrustValidatorFactory.class);

	/**
	 * Creates a trust validator according to Belgian PKI rules for authentication
	 * certificates.
	 * 
	 * @return a trust validator instance.
	 */
	public static TrustValidator createTrustValidator() {
		return createTrustValidator(null);
	}

	/**
	 * Creates a trust validator according to Belgian PKI rules for authentication
	 * certificates.
	 * 
	 * @param networkConfig the optional network configuration to be used.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createTrustValidator(NetworkConfig networkConfig) {
		TrustValidator trustValidator = createTrustValidator(networkConfig, null);
		return trustValidator;
	}

	private enum CertificateType {
		AUTHN, SIGN, NATIONAL_REGISTRY
	};

	/**
	 * Creates a trust validator according to Belgian PKI rules for authentication
	 * certificates.
	 * 
	 * <p>
	 * Via the external trust linker one can implement a CRL fetcher validation
	 * architecture based on Java EE.
	 * </p>
	 * 
	 * @param networkConfig       the optional network configuration to be used.
	 * @param externalTrustLinker the optional external trust linker to be used.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createTrustValidator(NetworkConfig networkConfig, TrustLinker externalTrustLinker) {
		TrustValidator trustValidator = createTrustValidator(CertificateType.AUTHN, networkConfig, externalTrustLinker,
				null, null);

		return trustValidator;
	}

	/**
	 * Creates a trust validator according to Belgian PKI rules for non-repudiation
	 * certificates.
	 * 
	 * @param networkConfig       the optional network configuration to be used.
	 * @param externalTrustLinker the optional external trust linker to be used.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createNonRepudiationTrustValidator(NetworkConfig networkConfig,
			TrustLinker externalTrustLinker) {
		TrustValidator trustValidator = createTrustValidator(CertificateType.SIGN, networkConfig, externalTrustLinker,
				null, null);

		return trustValidator;
	}

	/**
	 * Creates a trust validator according to Belgian PKI rules for non-repudiation
	 * certificates.
	 * 
	 * @param networkConfig the optional network configuration to be used.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createNonRepudiationTrustValidator(NetworkConfig networkConfig) {
		TrustValidator trustValidator = createTrustValidator(CertificateType.SIGN, networkConfig, null, null, null);

		return trustValidator;
	}

	/**
	 * Creates a trust validator according to Belgian PKI rules for the national
	 * registry certificate.
	 * 
	 * @param networkConfig the optional network configuration to be used.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createNationalRegistryTrustValidator(NetworkConfig networkConfig) {
		TrustValidator trustValidator = createTrustValidator(CertificateType.NATIONAL_REGISTRY, networkConfig, null,
				null, null);

		return trustValidator;
	}

	/**
	 * Creates a trust validator according to Belgian PKI rules for TSA
	 * certificates.
	 * 
	 * @param networkConfig the optional network configuration to be used.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createTSATrustValidator(NetworkConfig networkConfig) {
		return createTSATrustValidator(networkConfig, null);
	}

	/**
	 * Creates a trust validator according to Belgian PKI rules for TSA
	 * certificates.
	 * 
	 * @param networkConfig       the optional network configuration to be used.
	 * @param externalTrustLinker the optional external trust linker to be used.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createTSATrustValidator(NetworkConfig networkConfig, TrustLinker externalTrustLinker) {

		CertificateRepository certificateRepository = createTSACertificateRepository();

		TrustValidator trustValidator = new TrustValidator(certificateRepository);

		// add trust linkers
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator(networkConfig);
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator, externalTrustLinker);

		// add certificate constraints
		trustValidator.addCertificateConstraint(new TSACertificateConstraint());

		return trustValidator;
	}

	/**
	 * Creates a trust validator according to Belgian PKI rules for authentication
	 * certificates.
	 * 
	 * <p>
	 * Via the external trust linker one can implement a CRL fetcher validation
	 * architecture based on Java EE.
	 * </p>
	 * 
	 * @param networkConfig         the optional network configuration to be used.
	 * @param externalTrustLinker   the optional external trust linker to be used.
	 * @param certificateRepository containing the Belgian eID trust points.
	 * @return a trust validator instance.
	 */
	public static TrustValidator createTrustValidator(NetworkConfig networkConfig, TrustLinker externalTrustLinker,
			CertificateRepository certificateRepository) {
		return createTrustValidator(CertificateType.AUTHN, networkConfig, externalTrustLinker, certificateRepository,
				null);
	}

	public static CertificateRepository createCertificateRepository() {
		MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();

		X509Certificate rootCaCertificate = loadCertificate("be/fedict/trust/belgiumrca.crt");
		memoryCertificateRepository.addTrustPoint(rootCaCertificate);

		X509Certificate rootCa2Certificate = loadCertificate("be/fedict/trust/belgiumrca2.crt");
		memoryCertificateRepository.addTrustPoint(rootCa2Certificate);

		X509Certificate rootCa3Certificate = loadCertificate("be/fedict/trust/belgiumrca3.crt");
		memoryCertificateRepository.addTrustPoint(rootCa3Certificate);

		X509Certificate rootCa4Certificate = loadCertificate("be/fedict/trust/belgiumrca4.crt");
		memoryCertificateRepository.addTrustPoint(rootCa4Certificate);

		X509Certificate rootCa4_2Certificate = loadCertificate("be/fedict/trust/belgiumrca4-2.crt");
		memoryCertificateRepository.addTrustPoint(rootCa4_2Certificate);

		X509Certificate rootCa6Certificate = loadCertificate("be/fedict/trust/belgiumrca6.crt");
		memoryCertificateRepository.addTrustPoint(rootCa6Certificate);

		return memoryCertificateRepository;
	}

	public static CertificateRepository createTSACertificateRepository() {
		MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();

		X509Certificate rootTsaCertificate = loadCertificate("be/fedict/trust/belgiumtsa.crt");
		memoryCertificateRepository.addTrustPoint(rootTsaCertificate);

		X509Certificate newRootTsaCertificate = loadPemCertificate(
				"be/fedict/trust/roots/Baltimore Cybertrust Root.pem");
		memoryCertificateRepository.addTrustPoint(newRootTsaCertificate);

		X509Certificate cybertrustGlobalRootTsaCertificate = loadCertificate(
				"be/fedict/trust/roots/CybertrustGlobalRoot.crt");
		memoryCertificateRepository.addTrustPoint(cybertrustGlobalRootTsaCertificate);

		return memoryCertificateRepository;
	}

	private static TrustValidator createTrustValidator(CertificateType certificateType, NetworkConfig networkConfig,
			TrustLinker externalTrustLinker, CertificateRepository certificateRepository, CrlRepository crlRepository) {

		TrustValidator trustValidator;
		if (null == certificateRepository) {
			// trust points
			CertificateRepository localCertificateRepository = createCertificateRepository();
			trustValidator = new TrustValidator(localCertificateRepository);
		} else {
			trustValidator = new TrustValidator(certificateRepository);
		}

		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator(networkConfig);
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator, externalTrustLinker, false, crlRepository);

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
		trustValidator.addCertificateConstraint(keyUsageCertificateConstraint);

		CertificatePoliciesCertificateConstraint certificatePoliciesCertificateConstraint = new CertificatePoliciesCertificateConstraint();
		switch (certificateType) {
		case AUTHN:
			// RootCA citizen authn
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.1.1.1.2.2");
			// RootCA foreigner authn
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.1.1.1.7.2");
			// RootCA2 citizen authn
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.9.1.1.2.2");
			// RootCA2 foreigner authn
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.9.1.1.7.2");
			// RootCA3 citizen authn
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.10.1.1.2.2");
			// RootCA3 foreigner authn
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.10.1.1.7.2");
			// RootCA4 citizen authn
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.12.1.1.2.2");
			// RootCA4 foreigner authn
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.12.1.1.7.2");
			break;
		case SIGN:
			// RootCA citizen sign
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.1.1.1.2.1");
			// RootCA foreigner sign
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.1.1.1.7.1");
			// RootCA2 citizen sign
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.9.1.1.2.1");
			// RootCA2 foreigner sign
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.9.1.1.7.1");
			// RootCA3 citizen sign
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.10.1.1.2.1");
			// RootCA3 foreigner sign
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.10.1.1.7.1");
			// RootCA4 citizen sign
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.12.1.1.2.1");
			// RootCA4 foreigner sign
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.12.1.1.7.1");
			break;
		case NATIONAL_REGISTRY:
			// Root CA
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.1.1.1.4");
			// Root CA 2
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.9.1.1.4");
			// Root CA 3
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.10.1.1.4");
			// Root CA 4
			certificatePoliciesCertificateConstraint.addCertificatePolicy("2.16.56.12.1.1.4");
			break;
		}
		trustValidator.addCertificateConstraint(certificatePoliciesCertificateConstraint);

		if (CertificateType.NATIONAL_REGISTRY == certificateType) {
			DistinguishedNameCertificateConstraint nameConstraint = new DistinguishedNameCertificateConstraint(
					"CN=RRN, O=RRN, C=BE");
			trustValidator.addCertificateConstraint(nameConstraint);
		}

		if (CertificateType.SIGN == certificateType) {
			QCStatementsCertificateConstraint qcStatementsCertificateConstraint = new QCStatementsCertificateConstraint(
					true);
			trustValidator.addCertificateConstraint(qcStatementsCertificateConstraint);
		}

		return trustValidator;
	}

	private static X509Certificate loadPemCertificate(String pemResourceName) {
		CertificateFactory certificateFactory;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new RuntimeException("X.509 factory error: " + e.getMessage(), e);
		}
		Thread currentThread = Thread.currentThread();
		ClassLoader classLoader = currentThread.getContextClassLoader();
		InputStream certificateInputStream = classLoader.getResourceAsStream(pemResourceName);
		if (null == certificateInputStream) {
			throw new IllegalArgumentException("resource not found: " + pemResourceName);
		}
		PemReader pemReader = new PemReader(new InputStreamReader(certificateInputStream));
		try {
			try {
				PemObject pemObject;
				pemObject = pemReader.readPemObject();
				X509Certificate certificate = (X509Certificate) certificateFactory
						.generateCertificate(new ByteArrayInputStream(pemObject.getContent()));
				return certificate;
			} finally {
				pemReader.close();
			}
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		} catch (CertificateException e) {
			throw new RuntimeException("cert error: " + e.getMessage(), e);
		}
	}

	private static X509Certificate loadCertificate(String resourceName) {
		LOGGER.debug("loading certificate: {}", resourceName);
		Thread currentThread = Thread.currentThread();
		ClassLoader classLoader = currentThread.getContextClassLoader();
		InputStream certificateInputStream = classLoader.getResourceAsStream(resourceName);
		if (null == certificateInputStream) {
			throw new IllegalArgumentException("resource not found: " + resourceName);
		}
		try {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) certificateFactory
					.generateCertificate(certificateInputStream);
			return certificate;
		} catch (CertificateException e) {
			throw new RuntimeException("X509 error: " + e.getMessage(), e);
		}
	}
}
