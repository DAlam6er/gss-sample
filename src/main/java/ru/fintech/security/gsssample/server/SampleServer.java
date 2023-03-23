package ru.fintech.security.gsssample.server;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.MessageProp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * A sample server application that uses JGSS to do mutual authentication
 * with a client using Kerberos as the underlying mechanism. It then
 * exchanges data securely with the client.
 * <p>
 * Every message exchanged with the client includes a 4-byte application-
 * level header that contains the big-endian integer value for the number
 * of bytes that will follow as part of the JGSS token.
 * <p>
 * The protocol is:
 * 1.  Context establishment loop:
 * a. client sends init sec context token to server
 * b. server sends accept sec context token to client
 * ....
 * 2. client sends a wrap token to the server.
 * 3. server sends a mic token to the client for the application
 * message that was contained in the wrap token.
 */

public class SampleServer {
  private static final String LOGIN_CONFIG_PATH = "C:\\Users\\a" +
      ".pashkin\\ideaProjects\\work\\security\\gss-sample\\target\\classes\\bcsLogin.conf";
  // port number that server should listen on for client connections
  private static final int LOCAL_PORT = 4444;

  private static Socket socket;
  private static DataInputStream inStream;
  private static DataOutputStream outStream;
  private static GSSContext gssContext;

  public static void main(String[] args) throws IOException, GSSException {

    setSystemProperties();

    // factory for GSS API classes
    GSSManager manager = GSSManager.getInstance();

    // Socket for listening for client connections
    try (ServerSocket serverSocket = new ServerSocket(LOCAL_PORT)) {
      while (true) {
        establishSocketConnection(serverSocket);

        gssContext = instantiateContext(manager);

        establishSecurityContext();

        /*
         * Create a MessageProp which unwrap will use to return
         * information such as the Quality-of-Protection that was
         * applied to the wrapped token, whether it was encrypted, etc.
         * Since the initial MessageProp values are ignored,
         * just set them to the defaults of 0 and false.
         */
        MessageProp prop = new MessageProp(0, false);

        // obtain encrypted message from client, decrypt it and check integrity
        byte[] bytes = receiveAndDecrypt(prop);

        getMICAndSend(prop, bytes);

        cleanUp();
      }
    }
  }

  private static void setSystemProperties() {
    System.setProperty("java.security.krb5.realm", "HOPTO.ORG");
    System.setProperty("java.security.krb5.kdc", "kerbserver.hopto.org");
    System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
    System.setProperty("java.security.auth.login.config", LOGIN_CONFIG_PATH);
  }

  private static void establishSocketConnection(ServerSocket serverSocket) throws IOException {
    System.out.println("Waiting for incoming connection...");
    // Listens for a connection
    socket = serverSocket.accept();
    // The socket connection is accepted by SampleServer.
    // SampleServer initialize a DataInputStream and a DataOutputStream
    // from the socket input and output streams, to be used for future data exchanges.
    inStream = new DataInputStream(socket.getInputStream());
    outStream = new DataOutputStream(socket.getOutputStream());

    System.out.println("Got connection from client " + socket.getInetAddress());
  }

  private static GSSContext instantiateContext(GSSManager manager) throws GSSException {
    /*
     * Create a GSSContext to receive the incoming request
     * from the client. Use null for the server credentials passed in.
     * This tells the underlying mechanism to use whatever credentials
     * it has available that can be used to accept this connection.
     */
    return manager.createContext((GSSCredential) null);
  }

  private static void establishSecurityContext() throws IOException, GSSException {
    /*
     * opaque byte data
     * The tokens contain messages to be securely exchanged between two peers,
     * but the method of actual token transfer is up to the peers.
     */
    byte[] token;

    // Do the gssContext establishment loop
    while (!gssContext.isEstablished()) {
      // Receives a token from SampleClient.
      // This token is the result of a SampleClient initSecContext() call.
      token = new byte[inStream.readInt()];
      System.out.println("Will read input token of size " + token.length
          + " bytes for processing by acceptSecContext");
      inStream.readFully(token);

      token = gssContext.acceptSecContext(token, 0, token.length);

      // Send a token to the client if one was generated by acceptSecContext
      if (token != null) {
        System.out.println("Will send token of size " + token.length
            + " bytes from acceptSecContext.");
        outStream.writeInt(token.length);
        outStream.write(token);
        outStream.flush();
      }
    }

    System.out.print("Context Established! ");
    System.out.println("Client is " + gssContext.getSrcName());
    System.out.println("Server is " + gssContext.getTargName());
    /*
     * If mutual authentication did not take place, then
     * only the client was authenticated to the
     * server. Otherwise, both client and server were
     * authenticated to each other.
     */
    if (gssContext.getMutualAuthState()) {
      System.out.println("Mutual authentication took place!");
    }
  }

  private static byte[] receiveAndDecrypt(MessageProp prop) throws IOException, GSSException {
    // Read the token.
    byte[] token = new byte[inStream.readInt()];
    System.out.println("Will read token of size " + token.length);
    inStream.readFully(token);

    /*
     * Server calls the unwrap method to "unwrap" the token from client
     * to get the original message and to verify its integrity.
     *
     * The unwrapping in this case includes decryption since the message was encrypted.
     *
     * Here, the integrity check is expected to succeed.
     * But note that in general if an integrity check fails,
     * it signifies that the message was changed in transit.
     * If the unwrap method encounters an integrity check failure,
     * it throws a GSSException with major error code GSSException.BAD_MIC.
     *
     */
    byte[] bytes = gssContext.unwrap(token, 0, token.length, prop);
    String str = new String(bytes);
    System.out.println("Received data \""
        + str + "\" of length " + str.length());

    System.out.println("Confidentiality applied: " + prop.getPrivacy());
    return bytes;
  }

  private static void getMICAndSend(MessageProp prop, byte[] bytes) throws GSSException, IOException {
    /*
     * Now generate a MIC and send it to the client. This is
     * just for illustration purposes. The integrity of the
     * incoming wrapped message is guaranteed irrespective of
     * the confidentiality (encryption) that was used.
     */

    /*
     * First reset the QOP of the MessageProp to 0 to ensure the default Quality-of-Protection
     * is applied.
     */
    prop.setQOP(0);

    /*
     * If you simply want to get a token containing a cryptographic Message Integrity Code (MIC)
     * for a supplied message, you call getMIC.
     * A sample reason you might want to do this is to confirm with your peer
     * that you both have the same data, by just transporting a MIC for that data
     * without incurring the cost of transporting the data itself to each other.
     */

    // byte[] getMIC (byte[] inMsg, int offset, int len, MessageProp msgProp)
    byte[] token = gssContext.getMIC(bytes, 0, bytes.length, prop);

    System.out.println("Will send MIC token of size "
        + token.length);
    outStream.writeInt(token.length);
    outStream.write(token);
    outStream.flush();
  }

  private static void cleanUp() throws GSSException, IOException {
    System.out.println("Closing connection with client " + socket.getInetAddress());
    gssContext.dispose();
    socket.close();
  }

}
