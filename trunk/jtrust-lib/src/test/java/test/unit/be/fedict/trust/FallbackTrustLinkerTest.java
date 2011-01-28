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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Date;

import org.easymock.EasyMock;
import org.junit.Test;

import be.fedict.trust.FallbackTrustLinker;
import be.fedict.trust.TrustLinker;
import be.fedict.trust.TrustLinkerResult;

public class FallbackTrustLinkerTest {

	@Test
	public void firstTrustLinkerTrusts() throws Exception {
		// setup
		Date validationDate = new Date();
		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(null, null, validationDate, null))
				.andReturn(new TrustLinkerResult(true));

		FallbackTrustLinker fallbackTrustLinker = new FallbackTrustLinker();
		fallbackTrustLinker.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockTrustLinker);

		// operate
		TrustLinkerResult result = fallbackTrustLinker.hasTrustLink(null, null,
				validationDate, null);

		// verify
		assertNotNull(result);
		assertTrue(result.isValid());
		EasyMock.verify(mockTrustLinker);
	}

	@Test
	public void firstTrustLinkerTrustsNot() throws Exception {
		// setup
		Date validationDate = new Date();
		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(null, null, validationDate, null))
				.andReturn(new TrustLinkerResult(false));

		FallbackTrustLinker fallbackTrustLinker = new FallbackTrustLinker();
		fallbackTrustLinker.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockTrustLinker);

		// operate
		TrustLinkerResult result = fallbackTrustLinker.hasTrustLink(null, null,
				validationDate, null);

		// verify
		assertNotNull(result);
		assertFalse(result.isValid());
		EasyMock.verify(mockTrustLinker);
	}

	@Test
	public void noTrustLinkers() throws Exception {
		// setup
		FallbackTrustLinker fallbackTrustLinker = new FallbackTrustLinker();

		// operate
		TrustLinkerResult result = fallbackTrustLinker.hasTrustLink(null, null,
				null, null);

		// verify
		assertNull(result);
	}

	@Test
	public void fallback() throws Exception {
		// setup
		Date validationDate = new Date();
		TrustLinker mockTrustLinker1 = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker1.hasTrustLink(null, null, validationDate, null))
				.andReturn(null);
		TrustLinker mockTrustLinker2 = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker2.hasTrustLink(null, null, validationDate, null))
				.andReturn(new TrustLinkerResult(true));

		FallbackTrustLinker fallbackTrustLinker = new FallbackTrustLinker();
		fallbackTrustLinker.addTrustLinker(mockTrustLinker1);
		fallbackTrustLinker.addTrustLinker(mockTrustLinker2);

		EasyMock.replay(mockTrustLinker1, mockTrustLinker2);

		// operate
		TrustLinkerResult result = fallbackTrustLinker.hasTrustLink(null, null,
				validationDate, null);

		// verify
		assertNotNull(result);
		assertTrue(result.isValid());
		EasyMock.verify(mockTrustLinker1, mockTrustLinker2);
	}
}
