package cryptography;
		
public class CryptoUtils
{
	//Static auxiliary representations variables
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	
	protected static String bytesToHex(byte[] bytes)
	{
		char[] hexChars = new char[bytes.length * 2];
		for ( int i = 0; i < bytes.length; i++ )
		{
			int v = bytes[i] & 0xFF;
			hexChars[i * 2] = hexArray[v >>> 4];
			hexChars[i * 2 + 1] = hexArray[v & 0x0F];
		}
	return new String(hexChars);
}
	/*
	public static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
    }
    return data;
	}
	*/
}
