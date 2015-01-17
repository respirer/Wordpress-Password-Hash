package com.nnf.test;

import java.security.NoSuchAlgorithmException;

import com.nnf.utils.WordpressPasswordHasher;

public class test {

	public static void main(String[] args) {
		try {
			System.out.println(WordpressPasswordHasher.checkPassword("11112222","$P$Bd8tjhJBS.YyskXUUGOwpaUxpIkqaH0"));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

}
