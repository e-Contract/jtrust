/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2020-2023 e-Contract.be BV.
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
package test.unit.be.fedict.trust;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import be.fedict.trust.crl.OfflineCrlRepository;
import be.fedict.trust.test.PKIBuilder;

public class OfflineCrlRepositoryTest {

	@BeforeAll
	public static void installSecurityProviders() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testCrlFound() throws Exception {
		// setup
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair).withSubjectName("CN=Test")
				.withValidityMonths(1).build();

		X509CRL crl = new PKIBuilder.CRLBuilder(keyPair.getPrivate(), certificate).build();

		OfflineCrlRepository testedInstance = new OfflineCrlRepository(Collections.singletonList(crl.getEncoded()));

		// operate
		X509CRL resultCrl = testedInstance.findCrl(new URI("http://foo.org/bar"), certificate, new Date());

		// verify
		assertNotNull(resultCrl);
		assertEquals(crl, resultCrl);
	}

	@Test
	public void testCrlNotFound() throws Exception {
		// setup
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair).withSubjectName("CN=Test")
				.withValidityMonths(1).build();

		KeyPair otherKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate otherCertificate = new PKIBuilder.CertificateBuilder(otherKeyPair)
				.withSubjectName("CN=TestOther").withValidityMonths(1).build();

		X509CRL crl = new PKIBuilder.CRLBuilder(otherKeyPair.getPrivate(), otherCertificate).build();

		OfflineCrlRepository testedInstance = new OfflineCrlRepository(Collections.singletonList(crl.getEncoded()));

		// operate
		X509CRL resultCrl = testedInstance.findCrl(new URI("http://foo.org/bar"), certificate, new Date());

		// verify
		assertNull(resultCrl);
	}
}
