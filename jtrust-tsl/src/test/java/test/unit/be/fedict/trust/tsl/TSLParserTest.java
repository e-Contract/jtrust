/*
 * Java Trust Project.
 * Copyright (C) 2009-2011 FedICT.
 * Copyright (C) 2019-2020 e-Contract.be BV.
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

package test.unit.be.fedict.trust.tsl;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.InputStream;
import java.math.BigInteger;

import org.easymock.EasyMock;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import be.fedict.trust.tsl.TSLConsumer;
import be.fedict.trust.tsl.TSLParser;

public class TSLParserTest {

	@Test
	@Disabled
	public void testParseTSL_BE_2011_T1() throws Exception {
		// setup
		InputStream tslInputStream = TSLParserTest.class.getResourceAsStream("/tsl-be-2011-T1.xml");
		assertNotNull(tslInputStream);

		TSLConsumer mockTslConsumer = EasyMock.createMock(TSLConsumer.class);

		// expectations
		mockTslConsumer.setTSLSequenceNumber(BigInteger.valueOf(4));

		// prepare
		EasyMock.replay(mockTslConsumer);

		// operate
		TSLParser testedInstance = new TSLParser(tslInputStream);
		testedInstance.addTSLConsumer(mockTslConsumer);
		testedInstance.parseTrustedList();

		// verify
		EasyMock.verify(mockTslConsumer);
	}
}
