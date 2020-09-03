/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2020 e-Contract.be BV.
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
import static org.junit.jupiter.api.Assertions.fail;

import java.security.cert.X509Certificate;
import java.util.Date;

import org.easymock.EasyMock;
import org.junit.jupiter.api.Test;

import be.fedict.trust.linker.FallbackTrustLinker;
import be.fedict.trust.linker.TrustLinker;
import be.fedict.trust.linker.TrustLinkerResult;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.policy.AlgorithmPolicy;
import be.fedict.trust.policy.DefaultAlgorithmPolicy;
import be.fedict.trust.revocation.RevocationData;

public class FallbackTrustLinkerTest {

	@Test
	public void firstTrustLinkerTrusts() throws Exception {
		// setup
		Date validationDate = new Date();
		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(mockTrustLinker.hasTrustLink(EasyMock.eq((X509Certificate) null),
				EasyMock.eq((X509Certificate) null), EasyMock.eq(validationDate), EasyMock.eq((RevocationData) null),
				EasyMock.anyObject(AlgorithmPolicy.class))).andReturn(TrustLinkerResult.TRUSTED);

		FallbackTrustLinker fallbackTrustLinker = new FallbackTrustLinker();
		fallbackTrustLinker.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockTrustLinker);

		// operate
		TrustLinkerResult result = fallbackTrustLinker.hasTrustLink(null, null, validationDate, null,
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockTrustLinker);
	}

	@Test
	public void firstTrustLinkerTrustsNot() throws Exception {
		// setup
		Date validationDate = new Date();
		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(mockTrustLinker.hasTrustLink(EasyMock.eq((X509Certificate) null),
				EasyMock.eq((X509Certificate) null), EasyMock.eq(validationDate), EasyMock.eq((RevocationData) null),
				EasyMock.anyObject(AlgorithmPolicy.class)))
				.andThrow(new TrustLinkerResultException(TrustLinkerResultReason.NO_TRUST));

		FallbackTrustLinker fallbackTrustLinker = new FallbackTrustLinker();
		fallbackTrustLinker.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockTrustLinker);

		// operate
		try {
			fallbackTrustLinker.hasTrustLink(null, null, validationDate, null, new DefaultAlgorithmPolicy());
			fail();
		} catch (TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.NO_TRUST, e.getReason());
		}

		// verify
		EasyMock.verify(mockTrustLinker);
	}

	@Test
	public void noTrustLinkers() throws Exception {
		// setup
		FallbackTrustLinker fallbackTrustLinker = new FallbackTrustLinker();

		// operate
		TrustLinkerResult result = fallbackTrustLinker.hasTrustLink(null, null, null, null,
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
	}

	@Test
	public void fallback() throws Exception {
		// setup
		Date validationDate = new Date();
		TrustLinker mockTrustLinker1 = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(mockTrustLinker1.hasTrustLink(EasyMock.eq((X509Certificate) null),
				EasyMock.eq((X509Certificate) null), EasyMock.eq(validationDate), EasyMock.eq((RevocationData) null),
				EasyMock.anyObject(AlgorithmPolicy.class))).andReturn(TrustLinkerResult.UNDECIDED);
		TrustLinker mockTrustLinker2 = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(mockTrustLinker2.hasTrustLink(EasyMock.eq((X509Certificate) null),
				EasyMock.eq((X509Certificate) null), EasyMock.eq(validationDate), EasyMock.eq((RevocationData) null),
				EasyMock.anyObject(AlgorithmPolicy.class))).andReturn(TrustLinkerResult.TRUSTED);

		FallbackTrustLinker fallbackTrustLinker = new FallbackTrustLinker();
		fallbackTrustLinker.addTrustLinker(mockTrustLinker1);
		fallbackTrustLinker.addTrustLinker(mockTrustLinker2);

		EasyMock.replay(mockTrustLinker1, mockTrustLinker2);

		// operate
		TrustLinkerResult result = fallbackTrustLinker.hasTrustLink(null, null, validationDate, null,
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockTrustLinker1, mockTrustLinker2);
	}
}
