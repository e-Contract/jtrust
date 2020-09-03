/*
 * Java Trust Project.
 * Copyright (C) 2011 FedICT.
 * Copyright (C) 2014-2020 e-Contract.be BV.
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

package test.integ.be.fedict.trust;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.NetworkConfig;
import be.fedict.trust.TrustValidator;
import be.fedict.trust.TrustValidatorDecorator;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.policy.AllowAllAlgorithmPolicy;
import be.fedict.trust.repository.MemoryCertificateRepository;

public class CodeSigningTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(CodeSigningTest.class);

	@BeforeAll
	public static void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	@Disabled("expired certificate")
	public void testValidation2011_2014() throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		InputStream fedictCertInputStream = CodeSigningTest.class.getResourceAsStream("/fedict-2011-2014.der");
		X509Certificate fedictCert = (X509Certificate) certificateFactory.generateCertificate(fedictCertInputStream);
		LOGGER.debug("code signing not before: {}", fedictCert.getNotBefore());
		LOGGER.debug("code signing serial: {}", fedictCert.getSerialNumber());

		InputStream govCertInputStream = CodeSigningTest.class.getResourceAsStream("/gov-ca-2011.der");
		X509Certificate govCert = (X509Certificate) certificateFactory.generateCertificate(govCertInputStream);

		InputStream rootCertInputStream = CodeSigningTest.class.getResourceAsStream("/root-ca2.der");
		X509Certificate rootCert = (X509Certificate) certificateFactory.generateCertificate(rootCertInputStream);

		InputStream gsCertInputStream = CodeSigningTest.class
				.getResourceAsStream("/be/fedict/trust/roots/globalsign-be.crt");
		X509Certificate gsCert = (X509Certificate) certificateFactory.generateCertificate(gsCertInputStream);

		List<X509Certificate> certChain = new LinkedList<>();
		certChain.add(fedictCert);
		certChain.add(govCert);
		certChain.add(rootCert);
		certChain.add(gsCert);

		MemoryCertificateRepository certificateRepository = new MemoryCertificateRepository();
		certificateRepository.addTrustPoint(gsCert);
		TrustValidator trustValidator = new TrustValidator(certificateRepository);

		NetworkConfig networkConfig = new NetworkConfig("proxy.yourict.net", 8080);
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator(networkConfig);
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator, null, true);

		trustValidator.isTrusted(certChain);
	}

	@Test
	public void testValidation2010_2011() throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		InputStream fedictCertInputStream = CodeSigningTest.class.getResourceAsStream("/fedict-2010-2011.der");
		X509Certificate fedictCert = (X509Certificate) certificateFactory.generateCertificate(fedictCertInputStream);
		LOGGER.debug("code signing not before: {}", fedictCert.getNotBefore());

		InputStream govCertInputStream = CodeSigningTest.class.getResourceAsStream("/gov-ca-2010.der");
		X509Certificate govCert = (X509Certificate) certificateFactory.generateCertificate(govCertInputStream);

		InputStream rootCertInputStream = CodeSigningTest.class.getResourceAsStream("/root-ca2.der");
		X509Certificate rootCert = (X509Certificate) certificateFactory.generateCertificate(rootCertInputStream);

		InputStream gsCertInputStream = CodeSigningTest.class
				.getResourceAsStream("/be/fedict/trust/roots/globalsign-be.crt");
		X509Certificate gsCert = (X509Certificate) certificateFactory.generateCertificate(gsCertInputStream);

		List<X509Certificate> certChain = new LinkedList<>();
		certChain.add(fedictCert);
		certChain.add(govCert);
		certChain.add(rootCert);
		certChain.add(gsCert);

		MemoryCertificateRepository certificateRepository = new MemoryCertificateRepository();
		certificateRepository.addTrustPoint(gsCert);
		TrustValidator trustValidator = new TrustValidator(certificateRepository);

		NetworkConfig networkConfig = new NetworkConfig("proxy.yourict.net", 8080);
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator(networkConfig);
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator, null, true);

		try {
			trustValidator.isTrusted(certChain);
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
		}
	}

	@Test
	@Disabled("expired certificate")
	public void testEVZW() throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		InputStream fedictCertInputStream = CodeSigningTest.class.getResourceAsStream("/evzw/www.egreffe.be.crt");
		X509Certificate fedictCert = (X509Certificate) certificateFactory.generateCertificate(fedictCertInputStream);
		LOGGER.debug("code signing not before: {}", fedictCert.getNotBefore());

		InputStream govCertInputStream = CodeSigningTest.class.getResourceAsStream("/gov-ca-2011.der");
		X509Certificate govCert = (X509Certificate) certificateFactory.generateCertificate(govCertInputStream);

		InputStream rootCertInputStream = CodeSigningTest.class.getResourceAsStream("/root-ca2.der");
		X509Certificate rootCert = (X509Certificate) certificateFactory.generateCertificate(rootCertInputStream);

		InputStream gsCertInputStream = CodeSigningTest.class
				.getResourceAsStream("/be/fedict/trust/roots/globalsign-be.crt");
		X509Certificate gsCert = (X509Certificate) certificateFactory.generateCertificate(gsCertInputStream);

		List<X509Certificate> certChain = new LinkedList<>();
		certChain.add(fedictCert);
		certChain.add(govCert);
		certChain.add(rootCert);
		certChain.add(gsCert);

		MemoryCertificateRepository certificateRepository = new MemoryCertificateRepository();
		certificateRepository.addTrustPoint(gsCert);
		TrustValidator trustValidator = new TrustValidator(certificateRepository);

		NetworkConfig networkConfig = new NetworkConfig("proxy.yourict.net", 8080);
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator(networkConfig);
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator, null, false);

		trustValidator.isTrusted(certChain);
	}

	@Test
	@Disabled("expired certificate")
	public void testCertipostCodeSigning() throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		InputStream fedictCertInputStream = CodeSigningTest.class.getResourceAsStream("/FedICT-BE0367302178.cer");
		X509Certificate fedictCert = (X509Certificate) certificateFactory.generateCertificate(fedictCertInputStream);
		LOGGER.debug("code signing not before: {}", fedictCert.getNotBefore());

		InputStream govCertInputStream = CodeSigningTest.class.getResourceAsStream("/NCA_WSOS.crt");
		X509Certificate ca2Cert = (X509Certificate) certificateFactory.generateCertificate(govCertInputStream);

		InputStream rootCertInputStream = CodeSigningTest.class.getResourceAsStream("/NCA.crt");
		X509Certificate rootCert = (X509Certificate) certificateFactory.generateCertificate(rootCertInputStream);

		InputStream gsCertInputStream = CodeSigningTest.class.getResourceAsStream("/GTE_ROOT.crt");
		X509Certificate gsCert = (X509Certificate) certificateFactory.generateCertificate(gsCertInputStream);

		List<X509Certificate> certChain = new LinkedList<>();
		certChain.add(fedictCert);
		certChain.add(ca2Cert);
		certChain.add(rootCert);
		certChain.add(gsCert);

		MemoryCertificateRepository certificateRepository = new MemoryCertificateRepository();
		certificateRepository.addTrustPoint(gsCert);
		TrustValidator trustValidator = new TrustValidator(certificateRepository);

		trustValidator.setAlgorithmPolicy(new AllowAllAlgorithmPolicy());

		NetworkConfig networkConfig = new NetworkConfig("proxy.yourict.net", 8080);
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator(networkConfig);
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator, null, false);

		trustValidator.isTrusted(certChain);
	}
}
