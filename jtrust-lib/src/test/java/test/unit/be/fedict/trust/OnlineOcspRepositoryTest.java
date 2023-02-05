/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2021-2023 e-Contract.be BV.
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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.ocsp.OnlineOcspRepository;
import be.fedict.trust.test.PKIBuilder;

public class OnlineOcspRepositoryTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(OnlineOcspRepositoryTest.class);

	private Server server;

	private URI ocspUri;

	private OnlineOcspRepository testedInstance;

	private X509Certificate rootCertificate;

	private X509Certificate certificate;

	private KeyPair rootKeyPair;

	@BeforeAll
	public static void installSecurityProviders() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@BeforeEach
	public void setUp() throws Exception {
		this.server = new Server(0);
		ServletContextHandler servletContextHandler = new ServletContextHandler();
		servletContextHandler.setContextPath("/pki");
		this.server.setHandler(servletContextHandler);
		String pathSpec = "/test.ocsp";
		servletContextHandler.addServlet(OcspResponderTestServlet.class, pathSpec);
		this.server.start();

		ServerConnector serverConnector = (ServerConnector) this.server.getConnectors()[0];
		int port = serverConnector.getLocalPort();
		String servletUrl = "http://localhost:" + port + "/pki";
		this.ocspUri = new URI(servletUrl + pathSpec);

		this.testedInstance = new OnlineOcspRepository();

		OcspResponderTestServlet.reset();

		this.rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		this.rootCertificate = new PKIBuilder.CertificateBuilder(this.rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		this.certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), this.rootKeyPair.getPrivate(),
				this.rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).build();
	}

	@AfterEach
	public void tearDown() throws Exception {
		this.server.stop();
	}

	@Test
	public void testInvalidStatusCode() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_NOT_FOUND);

		// operate
		OCSPResp ocspResp = this.testedInstance.findOcspResponse(this.ocspUri, this.certificate, this.rootCertificate,
				new Date());

		// verify
		assertNull(ocspResp);
	}

	@Test
	public void testMissingResponseContentTypeHeader() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);

		// operate
		OCSPResp ocspResp = this.testedInstance.findOcspResponse(this.ocspUri, this.certificate, this.rootCertificate,
				new Date());

		// verify
		assertNull(ocspResp);
	}

	@Test
	public void testInvalidContentType() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);
		OcspResponderTestServlet.setContentType("foobar");

		// operate
		OCSPResp ocspResp = this.testedInstance.findOcspResponse(this.ocspUri, this.certificate, this.rootCertificate,
				new Date());

		// verify
		assertNull(ocspResp);
	}

	@Test
	public void testNoResponseReturned() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);
		OcspResponderTestServlet.setContentType("application/ocsp-response");

		// operate
		OCSPResp ocspResp = this.testedInstance.findOcspResponse(this.ocspUri, this.certificate, this.rootCertificate,
				new Date());

		// verify
		assertNull(ocspResp);
	}

	@Test
	public void testInvalidOcspResponse() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);
		OcspResponderTestServlet.setContentType("application/ocsp-response");
		OcspResponderTestServlet.setOcspData("foobar".getBytes());

		// operate & verify
		RuntimeException result = Assertions.assertThrows(RuntimeException.class, () -> {
			this.testedInstance.findOcspResponse(this.ocspUri, this.certificate, this.rootCertificate, new Date());
		});
		LOGGER.debug("message: {}", result.getMessage());
	}

	@Test
	public void testOcspResponse() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);
		OcspResponderTestServlet.setContentType("application/ocsp-response");

		OCSPResp ocspResp = new PKIBuilder.OCSPBuilder(this.rootKeyPair.getPrivate(), this.rootCertificate,
				this.certificate, this.rootCertificate).build();

		OcspResponderTestServlet.setOcspData(ocspResp.getEncoded());

		// operate
		OCSPResp resultOcspResp = this.testedInstance.findOcspResponse(this.ocspUri, this.certificate,
				this.rootCertificate, new Date());

		// verify
		assertNotNull(resultOcspResp);
	}

	public static class OcspResponderTestServlet extends HttpServlet {

		private static final Logger LOGGER = LoggerFactory.getLogger(OcspResponderTestServlet.class);

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
		protected void doPost(HttpServletRequest request, HttpServletResponse response)
				throws ServletException, IOException {
			LOGGER.debug("doPost");
			if (null != OcspResponderTestServlet.contentType) {
				response.addHeader("Content-Type", OcspResponderTestServlet.contentType);
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
