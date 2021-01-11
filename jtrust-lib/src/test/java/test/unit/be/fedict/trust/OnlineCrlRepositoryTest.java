/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2020-2021 e-Contract.be BV.
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

import static be.fedict.trust.test.World.getFreePort;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.joda.time.DateTime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import be.fedict.trust.crl.OnlineCrlRepository;
import be.fedict.trust.test.PKITestUtils;

public class OnlineCrlRepositoryTest {

	private Server server;

	private URI crlUri;

	private Date validationDate;

	private OnlineCrlRepository testedInstance;

	@BeforeAll
	public static void oneTimeSetUp() throws Exception {

		Security.addProvider(new BouncyCastleProvider());
	}

	@BeforeEach
	public void setUp() throws Exception {
		int freePort = getFreePort();
		this.server = new Server(freePort);
		ServletContextHandler servletContextHandler = new ServletContextHandler();
		servletContextHandler.setContextPath("/pki");
		String pathSpec = "/test.crl";
		servletContextHandler.addServlet(CrlRepositoryTestServlet.class, pathSpec);
		this.server.setHandler(servletContextHandler);
		this.server.start();

		String servletUrl = "http://localhost:" + freePort + "/pki";
		this.crlUri = new URI(servletUrl + pathSpec);
		this.validationDate = new Date();

		this.testedInstance = new OnlineCrlRepository();

		CrlRepositoryTestServlet.reset();
	}

	@AfterEach
	public void tearDown() throws Exception {
		this.server.stop();
	}

	@Test
	public void testCrlNotFound() throws Exception {
		// setup
		CrlRepositoryTestServlet.setResponseStatus(HttpServletResponse.SC_NOT_FOUND);

		// operate
		X509CRL crl = this.testedInstance.findCrl(this.crlUri, null, this.validationDate);

		// verify
		assertNull(crl);
	}

	@Test
	public void testInvalidCrl() throws Exception {
		// setup
		CrlRepositoryTestServlet.setCrlData("foobar".getBytes());

		// operate
		X509CRL crl = this.testedInstance.findCrl(this.crlUri, null, this.validationDate);

		// verify
		assertNull(crl);
	}

	@Test
	public void testEmptyCrl() throws Exception {
		// setup
		CrlRepositoryTestServlet.setCrlData(new byte[0]);

		// operate
		X509CRL crl = this.testedInstance.findCrl(this.crlUri, null, this.validationDate);

		// verify
		assertNull(crl);
	}

	@Test
	public void testDownloadCrl() throws Exception {
		// setup
		KeyPair keyPair = PKITestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = PKITestUtils.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
				notAfter);
		X509CRL crl = PKITestUtils.generateCrl(keyPair.getPrivate(), certificate, notBefore, notAfter);
		CrlRepositoryTestServlet.setCrlData(crl.getEncoded());

		// operate
		X509CRL result = this.testedInstance.findCrl(this.crlUri, certificate, this.validationDate);

		// verify
		assertNotNull(result);
		assertArrayEquals(crl.getEncoded(), result.getEncoded());
	}

	public static class CrlRepositoryTestServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		private static final Log LOG = LogFactory.getLog(CrlRepositoryTestServlet.class);

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
		protected void doGet(HttpServletRequest request, HttpServletResponse response)
				throws ServletException, IOException {
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
