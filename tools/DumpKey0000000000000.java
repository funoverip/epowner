import java.io.*;
import java.security.*;

public class DumpKey0000000000000 { // Final Class file must be 26 chars length .. 
	static public void main(String[] a) {
	      	if (a.length<1) {
			System.out.println("Usage: java DumpKey keystore.jks outfile");
			return;
		}
		String jksFile = a[0];
		String outFile = a[1];
		try {
			char[] arrayOfChar = "OEr(&^n:1".toCharArray();
	    		KeyStore localKeyStore = KeyStore.getInstance("JCEKS");
    			localKeyStore.load(new FileInputStream(jksFile), arrayOfChar);
	    		Key key = localKeyStore.getKey("symKey", arrayOfChar);

			FileOutputStream out = new FileOutputStream(outFile);
	         	out.write(key.getEncoded());
	         	out.close();
		} catch (Exception e) {
			e.printStackTrace();
	         	return;
		}
	}
}
