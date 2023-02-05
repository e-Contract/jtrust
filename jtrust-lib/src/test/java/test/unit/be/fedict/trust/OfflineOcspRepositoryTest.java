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
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import be.fedict.trust.ocsp.OfflineOcspRepository;
import be.fedict.trust.test.PKIBuilder;

public class OfflineOcspRepositoryTest {

	private X509Certificate rootCertificate;

	private X509Certificate certificate;

	private KeyPair rootKeyPair;

	@BeforeAll
	public static void installSecurityProviders() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@BeforeEach
	public void setUp() throws Exception {
		this.rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		this.rootCertificate = new PKIBuilder.CertificateBuilder(this.rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		this.certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), this.rootKeyPair.getPrivate(),
				this.rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).build();
	}

	@Test
	public void testOcspResponseFound() throws Exception {

		// setup
		OCSPResp ocspResp = new PKIBuilder.OCSPBuilder(this.rootKeyPair.getPrivate(), this.rootCertificate, certificate,
				this.rootCertificate).build();

		OfflineOcspRepository testedInstance = new OfflineOcspRepository(
				Collections.singletonList(ocspResp.getEncoded()));

		// operate
		OCSPResp resultOcspResp = testedInstance.findOcspResponse(new URI("htpp://foo.org/bar"), this.certificate,
				this.rootCertificate, new Date());

		// verify
		assertNotNull(resultOcspResp);
		assertEquals(ocspResp, resultOcspResp);
	}

	@Test
	public void testOcspResponseNotFound() throws Exception {
		// setup
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate otherCertificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(),
				this.rootKeyPair.getPrivate(), this.rootCertificate).withSubjectName("CN=TestOther")
				.withValidityMonths(1).build();

		OCSPResp ocspResp = new PKIBuilder.OCSPBuilder(this.rootKeyPair.getPrivate(), this.rootCertificate,
				otherCertificate, this.rootCertificate).build();

		OfflineOcspRepository testedInstance = new OfflineOcspRepository(
				Collections.singletonList(ocspResp.getEncoded()));

		// operate
		OCSPResp resultOcspResp = testedInstance.findOcspResponse(new URI("htpp://foo.org/bar"), this.certificate,
				this.rootCertificate, new Date());

		// verify
		assertNull(resultOcspResp);
	}
}
