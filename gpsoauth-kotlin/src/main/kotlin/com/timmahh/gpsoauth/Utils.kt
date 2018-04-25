package com.timmahh.gpsoauth

import java.io.ByteArrayOutputStream
import java.lang.String.format
import java.math.BigInteger
import java.security.*
import java.security.spec.InvalidKeySpecException
import java.security.spec.RSAPublicKeySpec
import java.util.regex.Pattern
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

fun <R> (() -> R).catch(vararg exceptions: Throwable, catchBlock: (Throwable) -> R): R =
		try {
			this()
		} catch (e: Throwable) {
			if (e in exceptions) catchBlock(e) else throw IllegalStateException(e)
		}

fun createSignature(username: String, password: String, modulus: BigInteger, exponent: BigInteger): ByteArray =
		ByteArrayOutputStream().use {
			it.write(0)
			it.write(sha1(createKeyStruct(modulus, exponent)).copyOfRange(0, 4))
			it.write(pkcs1AoepEncode(format("%s\u0000%s", username, password).toByteArray(), createKey(modulus, exponent)))
			it.toByteArray()
		}

fun pkcs1AoepEncode(bytes: ByteArray, publicKey: PublicKey): ByteArray =
		{
			Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding").apply {
				init(Cipher.ENCRYPT_MODE, publicKey)
			}.doFinal(bytes)
		}.catch(InvalidKeyException(),
				BadPaddingException(),
				NoSuchAlgorithmException(),
				NoSuchPaddingException(),
				IllegalBlockSizeException()) {
			throw IllegalStateException(it)
		}

fun createKey(modulus: BigInteger, exponent: BigInteger): PublicKey =
		{
			KeyFactory.getInstance("RSA")
					.generatePublic(RSAPublicKeySpec(modulus, exponent))
		}.catch(InvalidKeySpecException(),
				NoSuchAlgorithmException()) {
			throw IllegalStateException(it)
		}

fun sha1(bytes: ByteArray): ByteArray =
		try {
			MessageDigest.getInstance("SHA1").digest(bytes)
		} catch (e: NoSuchAlgorithmException) {
			throw IllegalStateException(e)
		}

fun createKeyStruct(modulus: BigInteger, exponent: BigInteger): ByteArray =
		ByteArrayOutputStream().use {
			it.write(byteArrayOf(0x00, 0x00, 0x00, 0x80.toByte()))
			it.write(bigIntegerToBytesWithoutSign(modulus))
			it.write(byteArrayOf(0x00, 0x00, 0x00, 0x03))
			it.write(bigIntegerToBytesWithoutSign(exponent))
			it.toByteArray()
		}

fun bigIntegerToBytesWithoutSign(bigInteger: BigInteger): ByteArray =
		bigInteger.toByteArray().run {
			if (get(0).toInt() == 0) copyOfRange(0, size)
			else this
		}

fun extractValue(responseBody: String, key: String): Try<String> =
		Pattern.compile(format("(\n|^)%s=(.*)?(\n|$)", key))
				.matcher(responseBody).let {
					if (it.find()) Try.of(it.group(2))
					else Try.failure()
				}