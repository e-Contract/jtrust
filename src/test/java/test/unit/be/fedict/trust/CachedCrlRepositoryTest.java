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

import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Test;

import be.fedict.trust.CachedCrlRepository;
import be.fedict.trust.CrlRepository;

public class CachedCrlRepositoryTest {

	@Test
	public void emptyCache() throws Exception {
		// setup
		X509CRL testCrl = generateTestCrl();
		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		URI crlUri = new URI("urn:test:crl");
		Date validationDate = new Date();

		CachedCrlRepository testedInstance = new CachedCrlRepository(
				mockCrlRepository);

		// expectations
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, validationDate))
				.andReturn(testCrl);

		// prepare
		EasyMock.replay(mockCrlRepository);

		// operate
		X509CRL resultCrl = testedInstance.findCrl(crlUri, validationDate);

		// verify
		EasyMock.verify(mockCrlRepository);
		assertEquals(testCrl, resultCrl);
	}

	@Test
	public void cacheBeingUsed() throws Exception {
		// setup
		X509CRL testCrl = generateTestCrl();
		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		URI crlUri = new URI("urn:test:crl");
		Date validationDate = new Date();

		CachedCrlRepository testedInstance = new CachedCrlRepository(
				mockCrlRepository);

		// expectations
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, validationDate))
				.andReturn(testCrl);

		// prepare
		EasyMock.replay(mockCrlRepository);

		// operate
		X509CRL resultCrl = testedInstance.findCrl(crlUri, validationDate);
		X509CRL resultCrl2 = testedInstance.findCrl(crlUri, validationDate);

		// verify
		EasyMock.verify(mockCrlRepository);
		assertEquals(testCrl, resultCrl);
		assertEquals(testCrl, resultCrl2);
	}

	@Test
	public void cacheRefreshing() throws Exception {
		// setup
		X509CRL testCrl = generateTestCrl();
		X509CRL testCrl2 = generateTestCrl();
		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		URI crlUri = new URI("urn:test:crl");
		Date validationDate = new Date();
		Date validationDate2 = new DateTime(validationDate).plusHours(2)
				.toDate();

		CachedCrlRepository testedInstance = new CachedCrlRepository(
				mockCrlRepository);

		// expectations
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, validationDate))
				.andReturn(testCrl);
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, validationDate2))
				.andReturn(testCrl2);

		// prepare
		EasyMock.replay(mockCrlRepository);

		// operate
		X509CRL resultCrl = testedInstance.findCrl(crlUri, validationDate);
		X509CRL resultCrl2 = testedInstance.findCrl(crlUri, validationDate2);

		// verify
		EasyMock.verify(mockCrlRepository);
		assertEquals(testCrl, resultCrl);
		assertEquals(testCrl2, resultCrl2);
	}

	private X509CRL generateTestCrl() throws Exception {
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		PrivateKey issuerPrivateKey = keyPair.getPrivate();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate issuerCertificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter, null,
				issuerPrivateKey, true, 0, null, null);
		DateTime thisUpdate = new DateTime();
		DateTime nextUpdate = thisUpdate.plusHours(1);
		return TrustTestUtils.generateCrl(issuerPrivateKey, issuerCertificate,
				thisUpdate, nextUpdate);
	}
}
