package ru.fintech.security.gsssample.client;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Set;

/**
 * A sample client application that uses JGSS to do mutual authentication
 * with a server using Kerberos as the underlying mechanism. It then
 * exchanges data securely with the server.
 * <p>
 * Every message sent to the server includes a 4-byte application-level
 * header that contains the big-endian integer value for the number
 * of bytes that will follow as part of the JGSS token.
 * <p>
 * The protocol is:
 * 1.  Context establishment loop:
 * a. client sends init sec context token to server
 * b. server sends accept sec context token to client
 * ....
 * 2. client sends a wrap token to the server.
 * 3. server sends a MIC token to the client for the application
 * message that was contained in the wrap token.
 */
public class SampleClient {
  private static final String LOGIN_CONFIG_PATH = "C:\\Users\\a" +
      ".pashkin\\ideaProjects\\work\\security\\gss-sample\\target\\classes\\bcsLogin.conf";
  // The name of the Kerberos principal that represents SampleServer
  private static final String SERVICE_PRINCIPAL = "postgres/epasdatabase.hopto.org@HOPTO.ORG";
  // The name of the host (machine) on which SampleServer is running
  private static final String HOSTNAME = "localhost";
  // The port number on which SampleServer listens for client connections.
  private static final int SERVER_PORT = 4444;

  private static Socket socket;
  private static DataInputStream inStream;
  private static DataOutputStream outStream;


  public static void main(String[] args) throws IOException, GSSException {
    setSystemProperties();

    establishSocketConnection();

    GSSContext gssContext = instantiateContext();

    setContextOptions(gssContext);

    establishSecurityContext(gssContext);

    /*
     * The first MessageProp argument is 0 to request
     * the default Quality-of-Protection.
     * The second argument is true to request
     * privacy (encryption of the message).
     */
    MessageProp prop = new MessageProp(0, true);

    byte[] messageBytes = "Hello There!\0".getBytes();

    /*
     * Encrypt the data and send it across. Integrity protection
     * is always applied, irrespective of confidentiality
     * (i.e., encryption).
     * You can use the same token (byte array) as that used when
     * establishing the gssContext.
     */
    // The wrap method is the primary method for message exchanges.
    // byte[] wrap (byte[] inBuf, int offset, interface len, MessageProp msgProp)
    byte[] token = gssContext.wrap(messageBytes, 0, messageBytes.length, prop);
    System.out.println("Will send wrap token of size " + token.length);
    outStream.writeInt(token.length);
    outStream.write(token);
    outStream.flush();

    /*
     * Now we will allow the server to decrypt the message,
     * calculate a MIC on the decrypted message and send it back
     * to us for verification. This is unnecessary, but done here
     * for illustration.
     */
    token = new byte[inStream.readInt()];
    System.out.println("Will read token of size " + token.length);
    inStream.readFully(token);
    gssContext.verifyMIC(token, 0, token.length,
        messageBytes, 0, messageBytes.length,
        prop);

    System.out.println("Verified received MIC for message.");

    System.out.println("Exiting...");
    gssContext.dispose();
    socket.close();
  }

  private static void setSystemProperties() {
    System.setProperty("java.security.krb5.realm", "HOPTO.ORG");
    System.setProperty("java.security.krb5.kdc", "kerbserver.hopto.org");
    System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
    System.setProperty("java.security.auth.login.config", LOGIN_CONFIG_PATH);
  }

  private static void establishSocketConnection() throws IOException {
    // Attempts a socket connection with the SampleServer
    socket = new Socket(HOSTNAME, SERVER_PORT);
    /*
     * The socket connection is accepted by SampleServer
     * SampleClient initialize a DataInputStream and a DataOutputStream
     * from the socket input and output streams, to be used for future data exchanges.
     */
    inStream = new DataInputStream(socket.getInputStream());
    outStream = new DataOutputStream(socket.getOutputStream());

    System.out.println("Connected to server " + socket.getInetAddress());
  }

  private static GSSContext instantiateContext() throws GSSException {
    /*
     * An Oid represents a Universal Object Identifier.
     * Oids are hierarchically globally-interpretable identifiers
     * used within the GSS-API framework to identify mechanisms and name types.
     *
     * The structure and encoding of Oids is defined in the
     * ISOIEC-8824 and ISOIEC-8825 standards.
     *
     * This Oid is used to represent the Kerberos version 5 GSS-API
     * mechanism to be used for the authentication
     * between the client and the server during context establishment
     * and for subsequent secure communication between them.
     * It is defined in RFC 1964.
     * We will use this Oid whenever we need to indicate to the GSS-API
     * that it must use Kerberos for some purpose.
     */
    Oid KRB5_OID = new Oid("1.2.840.113554.1.2.2");

    // factory for GSS API classes
    GSSManager manager = GSSManager.getInstance();

    /*
     * GSSName createName(String nameStr, Oid nameType);
     * The Oid passed to the createName method is specifically a name type Oid (not a mechanism Oid).
     *
     * Create a GSSName out of the server's name. The null
     * indicates that this application does not wish to make
     * any claims about the syntax of this name and that the
     * underlying mechanism should try to parse it as per whatever
     * default syntax it chooses.
     *
     * In GSS-API, string names are often mapped from a mechanism-independent format into a mechanism-specific format.
     * Usually, an Oid specifies what name format the string is in
     * so that the mechanism knows how to do this mapping.
     * Passing in a null Oid indicates that
     * the name is already in a native format that the mechanism uses.
     * This is the case for the SERVICE_PRINCIPAL String; it is in the appropriate format for a Kerberos Version 5 name.
     * Thus, SampleClient passes a null for the Oid.
     */
    GSSName servicePrincipalName = manager.createName(SERVICE_PRINCIPAL, null);

    /*
     * Create a GSSContext for mutual authentication with the
     * server.
     *    - servicePrincipalName is the GSSName that represents the server.
     *    - KRB5_OID is the Oid that represents the mechanism to use. The client chooses the mechanism to use.
     *    - null is passed in for client credentials
     *    - DEFAULT_LIFETIME lets the mechanism decide how long the
     * gssContext can remain valid (in seconds).
     *
     * Passing in null for the credentials asks GSS-API to use the
     * default credentials.
     * This means that the mechanism will look among the credentials
     * stored in the current Subject to find the right kind of credentials that it needs.
     */

    return manager.createContext(servicePrincipalName,
        KRB5_OID,
        null,
        GSSContext.DEFAULT_LIFETIME);
  }

  /**
   * Set the desired optional features on the gssContext.
   */
  private static void setContextOptions(GSSContext gssContext) throws GSSException {
    /*
     * Mutual authentication
     * The context initiator is always authenticated to the acceptor.
     * If the initiator requests mutual authentication, then the acceptor is also authenticated to the initiator.
     */
    gssContext.requestMutualAuth(true);
    /*
     *  Will use confidentiality later
     * Requesting confidentiality means that you request
     * the enabling of encryption for the context method named wrap.
     * Encryption is actually used only if the MessageProp object passed to the wrap method requests privacy.
     */
    gssContext.requestConf(true);
    /*
     *  Will use integrity later
     * This requests integrity for the wrap and getMIC methods.
     * When integrity is requested, a cryptographic tag known as a Message Integrity Code (MIC)
     * will be generated when calling those methods.
     * When getMIC is called, the generated MIC appears in the returned token.
     * When wrap is called, the MIC is packaged together with the message
     * (the original message or the result of encrypting the message,
     * depending on whether confidentiality was applied)
     * all as part of one token.
     * You can subsequently verify the MIC against the message
     * to ensure that the message has not been modified in transit.
     */
    gssContext.requestInteg(true);
  }

  private static void establishSecurityContext(GSSContext gssContext) throws GSSException, IOException {
    /*
     * The tokens returned by initSecContext are placed in a byte array.
     * Tokens should be treated by client as opaque data to be passed
     * between server and client and interpreted by Java GSS-API methods.
     */
    byte[] token = new byte[0];

    // Do the gssContext establishment loop
    while (!gssContext.isEstablished()) {
      /*
       * If this is the first call, the method is passed an empty token.
       * Otherwise, it is passed the token most recently sent to SampleClient by SampleServer
       * (a token generated by a SampleServer call to acceptSecContext).
       *
       * The first call to initSecContext always produces a token. The last call might not return a token.
       */
      if (token != null) {
        token = gssContext.initSecContext(token, 0, token.length);
      }

      // Send a token to the server if one was generated by initSecContext
      if (token != null) {
        System.out.println("Will send token of size "
            + token.length
            + " from initSecContext.");
        outStream.writeInt(token.length);
        outStream.write(token);
        outStream.flush();
      }

      /*
       * Checks to see if the context is established.
       * If not, SampleClient receives another token from SampleServer
       * and then starts the next loop iteration.
       */
      if (!gssContext.isEstablished()) {
        token = new byte[inStream.readInt()];
        System.out.println("Will read input token of size "
            + token.length
            + " for processing by initSecContext");
        inStream.readFully(token);
      }
    }

    System.out.println("Context Established! ");
    System.out.println("Client is " + gssContext.getSrcName());
    System.out.println("Server is " + gssContext.getTargName());

    /*
     * If mutual authentication did not take place, then only the
     * client was authenticated to the server. Otherwise, both
     * client and server were authenticated to each other.
     */
    if (gssContext.getMutualAuthState()) {
      System.out.println("Mutual authentication took place!");
    }
  }

}
