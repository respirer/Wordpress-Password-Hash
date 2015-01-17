package com.nnf.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Wordpress password hasher
 * 
 * @author Ho-jin Lee
 */
public class WordpressPasswordHasher {

	private static final String strItoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	private static String cryptPrivate(String password, String setting)
			throws NoSuchAlgorithmException {
		String output = "*0";
		if (setting.startsWith(output))
			output = "*1";

		String id = setting.substring(0, 3);

		if (!id.equals("$P$") && !id.equals("$H$"))
			return output;

		int count_log2 = strItoa64.indexOf(setting.substring(3, 4));
		if (count_log2 < 7 || count_log2 > 30)
			return output;

		int count = 1 << count_log2;

		String salt = setting.substring(4, 12);
		if (salt.length() != 8)
			return output;

		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update((salt + password).getBytes());
		byte hash[] = md.digest();
		do {
			byte newHash[] = new byte[hash.length + password.getBytes().length];
			System.arraycopy(hash, 0, newHash, 0, hash.length);
			System.arraycopy(password.getBytes(), 0, newHash, hash.length,
					password.getBytes().length);
			md.update(newHash);
			hash = md.digest();
		} while ((--count) > 0);

		output = setting.substring(0, 12);
		output += encode64(hash, 16);
		return output;
	}
	
	private static String encode64(byte input[], int count) {
		String output = "";
		int i = 0;
		do {
			int value = input[i++] & 0xFF;
			output += strItoa64.charAt(value & 0x3f);
			if (i < count)
				value |= ((input[i] & 0xFF) << 8);
			output += strItoa64.charAt((value >> 6) & 0x3f);
			if (i++ >= count)
				break;
			if (i < count)
				value |= ((input[i] & 0xFF) << 16);
			output += strItoa64.charAt((value >> 12) & 0x3f);
			if (i++ >= count)
				break;
			output += strItoa64.charAt((value >> 18) & 0x3f);
		} while (i < count);
		return output;
	}

	/**
	 * Check password
	 * 
	 * @param password Plain password
	 * @param storedPassword Stored password
	 * @return If the password is correct, then returns true. Else it returns false.
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	public static boolean checkPassword(String password, String storedHash)
			throws NoSuchAlgorithmException {
		String hash = cryptPrivate(password, storedHash);

		return hash.equals(storedHash);
	}
}