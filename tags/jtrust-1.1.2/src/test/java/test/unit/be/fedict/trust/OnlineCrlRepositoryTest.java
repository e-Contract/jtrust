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

import be.fedict.trust.crl.OnlineCrlRepository;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mortbay.jetty.testing.ServletTester;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.Assert.*;

public class OnlineCrlRepositoryTest {

	private ServletTester servletTester;

	private URI crlUri;

	private Date validationDate;

	private OnlineCrlRepository testedInstance;

	@BeforeClass
	public static void oneTimeSetUp() throws Exception {

		Security.addProvider(new BouncyCastleProvider());
	}

	@Before
	public void setUp() throws Exception {
		this.servletTester = new ServletTester();
		String pathSpec = "/test.crl";
		this.servletTester.addServlet(CrlRepositoryTestServlet.class, pathSpec);
		this.servletTester.start();

		String servletUrl = this.servletTester.createSocketConnector(true);
		this.crlUri = new URI(servletUrl + pathSpec);
		this.validationDate = new Date();

		this.testedInstance = new OnlineCrlRepository();

		CrlRepositoryTestServlet.reset();
	}

	@After
	public void tearDown() throws Exception {
		this.servletTester.stop();
	}

	@Test
	public void testCrlNotFound() throws Exception {
		// setup
		CrlRepositoryTestServlet
				.setResponseStatus(HttpServletResponse.SC_NOT_FOUND);

		// operate
		X509CRL crl = this.testedInstance.findCrl(this.crlUri, null,
				this.validationDate);

		// verify
		assertNull(crl);
	}

	@Test
	public void testInvalidCrl() throws Exception {
		// setup
		CrlRepositoryTestServlet.setCrlData("foobar".getBytes());

		// operate
		X509CRL crl = this.testedInstance.findCrl(this.crlUri, null,
				this.validationDate);

		// verify
		assertNull(crl);
	}

	@Test
	public void testDownloadCrl() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);
		X509CRL crl = TrustTestUtils.generateCrl(keyPair.getPrivate(),
				certificate, notBefore, notAfter);
		CrlRepositoryTestServlet.setCrlData(crl.getEncoded());

		// operate
		X509CRL result = this.testedInstance.findCrl(this.crlUri, certificate,
				this.validationDate);

		// verify
		assertNotNull(result);
		assertArrayEquals(crl.getEncoded(), result.getEncoded());
	}

	public static class CrlRepositoryTestServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		private static final Log LOG = LogFactory
				.getLog(CrlRepositoryTestServlet.class);

		private static int responseStatus;

		private static byte[] crlData;

		public static void reset() {
			CrlRepositoryTestServlet.responseStatus = 0;
			CrlRepositoryTestServlet.crlData = null;
		}

		public static void setResponseStatus(int responseStatus) {
			CrlRepositoryTestServlet.responseStatus = responseStatus;
		}

		public static void setCrlData(byte[] crlData) {
			CrlRepositoryTestServlet.crlData = crlData;
		}

		@Override
		protected void doGet(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			LOG.debug("doGet");
			if (null != CrlRepositoryTestServlet.crlData) {
				OutputStream outputStream = response.getOutputStream();
				IOUtils.write(CrlRepositoryTestServlet.crlData, outputStream);
			}
			if (0 != CrlRepositoryTestServlet.responseStatus) {
				response.setStatus(CrlRepositoryTestServlet.responseStatus);
			}
		}
	}
}
