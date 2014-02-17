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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import be.fedict.trust.ocsp.OfflineOcspRepository;
import be.fedict.trust.test.PKITestUtils;

public class OfflineOcspRepositoryTest {

	private X509Certificate rootCertificate;

	private X509Certificate certificate;

	private KeyPair rootKeyPair;

	@Before
	public void setUp() throws Exception {

		this.rootKeyPair = PKITestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		this.rootCertificate = PKITestUtils.generateSelfSignedCertificate(
				this.rootKeyPair, "CN=TestRoot", notBefore, notAfter);

		KeyPair keyPair = PKITestUtils.generateKeyPair();
		this.certificate = PKITestUtils.generateCertificate(
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
		OCSPResp ocspResp = PKITestUtils.createOcspResp(this.certificate,
				false, this.rootCertificate, this.rootCertificate,
				this.rootKeyPair.getPrivate());

		OfflineOcspRepository testedInstance = new OfflineOcspRepository(
				Collections.singletonList(ocspResp.getEncoded()));

		// operate
		OCSPResp resultOcspResp = testedInstance.findOcspResponse(new URI(
				"htpp://foo.org/bar"), this.certificate, this.rootCertificate,
				new Date());

		// verify
		assertNotNull(resultOcspResp);
		assertEquals(ocspResp, resultOcspResp);
	}

	@Test
	public void testOcspResponseNotFound() throws Exception {

		// setup
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyPair keyPair = PKITestUtils.generateKeyPair();
		X509Certificate otherCertificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=TestOther", notBefore, notAfter,
				this.rootCertificate, this.rootKeyPair.getPrivate());

		OCSPResp ocspResp = PKITestUtils.createOcspResp(otherCertificate,
				false, this.rootCertificate, this.rootCertificate,
				this.rootKeyPair.getPrivate());

		OfflineOcspRepository testedInstance = new OfflineOcspRepository(
				Collections.singletonList(ocspResp.getEncoded()));

		// operate
		OCSPResp resultOcspResp = testedInstance.findOcspResponse(new URI(
				"htpp://foo.org/bar"), this.certificate, this.rootCertificate,
				new Date());

		// verify
		assertNull(resultOcspResp);
	}
}
