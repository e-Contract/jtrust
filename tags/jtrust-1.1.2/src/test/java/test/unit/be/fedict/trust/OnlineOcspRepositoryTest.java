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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.OCSPResp;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.testing.ServletTester;

import be.fedict.trust.ocsp.OnlineOcspRepository;

public class OnlineOcspRepositoryTest {

	private ServletTester servletTester;

	private URI ocspUri;

	private OnlineOcspRepository testedInstance;

	private X509Certificate rootCertificate;

	private X509Certificate certificate;

	private KeyPair rootKeyPair;

	@Before
	public void setUp() throws Exception {
		this.servletTester = new ServletTester();
		String pathSpec = "/test.ocsp";
		this.servletTester.addServlet(OcspResponderTestServlet.class, pathSpec);
		this.servletTester.start();

		String servletUrl = this.servletTester.createSocketConnector(true);
		this.ocspUri = new URI(servletUrl + pathSpec);

		this.testedInstance = new OnlineOcspRepository();

		OcspResponderTestServlet.reset();

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
		this.servletTester.stop();
	}

	@Test
	public void testInvalidStatusCode() throws Exception {
		// setup
		OcspResponderTestServlet
				.setResponseStatus(HttpServletResponse.SC_NOT_FOUND);

		// operate
		OCSPResp ocspResp = this.testedInstance.findOcspResponse(this.ocspUri,
				this.certificate, this.rootCertificate);

		// verify
		assertNull(ocspResp);
	}

	@Test
	public void testMissingResponseContentTypeHeader() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);

		// operate
		OCSPResp ocspResp = this.testedInstance.findOcspResponse(this.ocspUri,
				this.certificate, this.rootCertificate);

		// verify
		assertNull(ocspResp);
	}

	@Test
	public void testInvalidContentType() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);
		OcspResponderTestServlet.setContentType("foobar");

		// operate
		OCSPResp ocspResp = this.testedInstance.findOcspResponse(this.ocspUri,
				this.certificate, this.rootCertificate);

		// verify
		assertNull(ocspResp);
	}

	@Test
	public void testNoResponseReturned() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);
		OcspResponderTestServlet.setContentType("application/ocsp-response");

		// operate
		OCSPResp ocspResp = this.testedInstance.findOcspResponse(this.ocspUri,
				this.certificate, this.rootCertificate);

		// verify
		assertNull(ocspResp);
	}

	@Test
	public void testInvalidOcspResponse() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);
		OcspResponderTestServlet.setContentType("application/ocsp-response");
		OcspResponderTestServlet.setOcspData("foobar".getBytes());

		// operate
		OCSPResp ocspResp = this.testedInstance.findOcspResponse(this.ocspUri,
				this.certificate, this.rootCertificate);

		// verify
		assertNull(ocspResp);
	}

	@Test
	public void testOcspResponse() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);
		OcspResponderTestServlet.setContentType("application/ocsp-response");

		OCSPResp ocspResp = TrustTestUtils.createOcspResp(this.certificate,
				false, this.rootCertificate, this.rootCertificate,
				this.rootKeyPair.getPrivate());

		OcspResponderTestServlet.setOcspData(ocspResp.getEncoded());

		// operate
		OCSPResp resultOcspResp = this.testedInstance.findOcspResponse(
				this.ocspUri, this.certificate, this.rootCertificate);

		// verify
		assertNotNull(resultOcspResp);
	}

	public static class OcspResponderTestServlet extends HttpServlet {

		private static final Log LOG = LogFactory
				.getLog(OcspResponderTestServlet.class);

		private static final long serialVersionUID = 1L;

		private static int responseStatus;

		private static String contentType;

		private static byte[] ocspData;

		public static void setResponseStatus(int responseStatus) {
			OcspResponderTestServlet.responseStatus = responseStatus;
		}

		public static void setContentType(String contentType) {
			OcspResponderTestServlet.contentType = contentType;
		}

		public static void setOcspData(byte[] ocspData) {
			OcspResponderTestServlet.ocspData = ocspData;
		}

		public static void reset() {
			OcspResponderTestServlet.responseStatus = 0;
			OcspResponderTestServlet.contentType = null;
			OcspResponderTestServlet.ocspData = null;
		}

		@Override
		protected void doPost(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			LOG.debug("doPost");
			if (null != OcspResponderTestServlet.contentType) {
				response.addHeader("Content-Type",
						OcspResponderTestServlet.contentType);
			}
			if (null != OcspResponderTestServlet.ocspData) {
				OutputStream outputStream = response.getOutputStream();
				IOUtils.write(OcspResponderTestServlet.ocspData, outputStream);
			}
			if (0 != OcspResponderTestServlet.responseStatus) {
				response.setStatus(OcspResponderTestServlet.responseStatus);
			}
		}
	}
}
