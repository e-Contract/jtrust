/*
 * Java Trust Project.
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

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.TrustValidator;
import be.fedict.trust.TrustValidatorDecorator;
import be.fedict.trust.repository.MemoryCertificateRepository;
import be.fedict.trust.test.PKITestUtils;

public class BelgiumRootCA2v2 {

	private static final Logger LOGGER = LoggerFactory.getLogger(BelgiumRootCA2v2.class);

	@BeforeAll
	public static void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testValidation() throws Exception {
		X509Certificate rrnCert = PKITestUtils.loadCertificate("/brca2-2/CertificateRRN.crt");
		X509Certificate rootCaCert = PKITestUtils.loadCertificate("/brca2-2/CertificateBelgiumRoot.crt");
		LOGGER.debug(rootCaCert.toString());
		List<X509Certificate> certChain = new LinkedList<>();
		certChain.add(rrnCert);
		certChain.add(rootCaCert);

		MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
		X509Certificate rootCa2Certificate = PKITestUtils.loadCertificate("/be/fedict/trust/belgiumrca2.crt");
		memoryCertificateRepository.addTrustPoint(rootCa2Certificate);
		memoryCertificateRepository.addTrustPoint(rootCaCert);

		TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);
		TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
		trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

		trustValidator.isTrusted(certChain);
	}
}
