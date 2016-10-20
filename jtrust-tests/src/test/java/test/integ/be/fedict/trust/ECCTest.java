/*
 * Java Trust Project.
 * Copyright (C) 2016 e-Contract.be BVBA.
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

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.fedict.trust.TrustValidator;
import be.fedict.trust.TrustValidatorDecorator;
import be.fedict.trust.repository.MemoryCertificateRepository;

public class ECCTest {

	private static final Log LOG = LogFactory.getLog(ECCTest.class);

	/**
	 * The CRL of the Entrust Demo ECC CA does not exist online.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testEntrustDemoECCPKI() throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate rootCertificate = (X509Certificate) certificateFactory
				.generateCertificate(ECCTest.class.getResourceAsStream("/ecc/root.cer"));
		LOG.debug("Root CA: " + rootCertificate);

		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(ECCTest.class.getResourceAsStream("/ecc/www.e-contract.be.p12"), "EntrustSSL".toCharArray());

		String alias = keyStore.aliases().nextElement();
		Certificate[] certificates = keyStore.getCertificateChain(alias);
		for (Certificate certificate : certificates) {
			LOG.debug("Certificate: " + certificate);
		}

		MemoryCertificateRepository repository = new MemoryCertificateRepository();
		repository.addTrustPoint(rootCertificate);

		TrustValidator trustValidator = new TrustValidator(repository);
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

		trustValidator.isTrusted(certificates);
	}
}
