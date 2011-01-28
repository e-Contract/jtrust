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

package test.unit.be.fedict.trust;

import be.fedict.trust.ocsp.OfflineOcspRepository;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.OCSPResp;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.junit.Assert.*;

public class OfflineOcspRepositoryTest {

	private X509Certificate rootCertificate;

	private X509Certificate certificate;

	private KeyPair rootKeyPair;

	@Before
	public void setUp() throws Exception {

		this.rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		this.rootCertificate = TrustTestUtils.generateSelfSignedCertificate(
				this.rootKeyPair, "CN=TestRoot", notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		this.certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				this.rootCertificate, this.rootKeyPair.getPrivate());

		// required for org.bouncycastle.ocsp.CertificateID
		Security.addProvider(new BouncyCastleProvider());

	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testOcspResponseFound() throws Exception {

		// setup
		OCSPResp ocspResp = TrustTestUtils.createOcspResp(this.certificate,
				false, this.rootCertificate, this.rootCertificate,
				this.rootKeyPair.getPrivate());

		OfflineOcspRepository testedInstance = new OfflineOcspRepository(
				Collections.singletonList(ocspResp.getEncoded()));

		// operate
		OCSPResp resultOcspResp = testedInstance.findOcspResponse(new URI(
				"htpp://foo.org/bar"), this.certificate, this.rootCertificate);

		// verify
		assertNotNull(resultOcspResp);
		assertEquals(ocspResp, resultOcspResp);
	}

	@Test
	public void testOcspResponseNotFound() throws Exception {

		// setup
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate otherCertificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=TestOther", notBefore, notAfter,
				this.rootCertificate, this.rootKeyPair.getPrivate());

		OCSPResp ocspResp = TrustTestUtils.createOcspResp(otherCertificate,
				false, this.rootCertificate, this.rootCertificate,
				this.rootKeyPair.getPrivate());

		OfflineOcspRepository testedInstance = new OfflineOcspRepository(
				Collections.singletonList(ocspResp.getEncoded()));

		// operate
		OCSPResp resultOcspResp = testedInstance.findOcspResponse(new URI(
				"htpp://foo.org/bar"), this.certificate, this.rootCertificate);

		// verify
		assertNull(resultOcspResp);
	}
}
