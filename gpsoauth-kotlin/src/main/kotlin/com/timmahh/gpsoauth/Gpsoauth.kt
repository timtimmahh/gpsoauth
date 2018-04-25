package com.timmahh.gpsoauth

import android.util.Base64
import okhttp3.*
import java.io.IOException
import java.math.BigInteger

data class GpsoauthConfig(val modulus: BigInteger = BigInteger("141956196257934770187925561804359820971448272350983018436093173897855484510782207920697285059648243152878542520514658971720228524276304322321325896163977435852395272134149378260200371457183474602754725451457370420041505749329659663863538423736961928495802209949126722610439862310060378247113201580053877385209"),
                          val exponent: BigInteger = BigInteger("65537"),
                          val userAgent: String = "gpsoauth")

interface GpsoauthConfigFactory {
	fun load(): GpsoauthConfig
}

data class AuthToken(val token: String, val expiry: Long) {
	
	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (other !is AuthToken) return false
		
		if (expiry != other.expiry) return false
		return token == other.token
	}
	
	override fun hashCode(): Int =
			31 * token.hashCode() + (expiry xor (expiry ushr 32)).toInt()
	
	override fun toString(): String =
			"""AuthToken{
				|   token='$token',
				|   expiry=$expiry
				|}""".trimMargin()
}

class Gpsoauth(private val httpClient: OkHttpClient = OkHttpClient(),
               private val config: GpsoauthConfig = GpsoauthConfig()) {
	
	companion object {
		private const val url = "https://android.clients.google.com/auth"
	}
	
	fun login(username: String,
	          password: String,
	          androidId: String,
	          service: String,
	          app: String,
	          clientSig: String): AuthToken =
			performOAuthForToken(
					username = username,
					masterToken = performMasterLoginForToken(username, password, androidId),
					androidId = androidId,
					service = service,
					app = app,
					clientSig = clientSig)
	
	private fun makeMasterLoginCall(username: String,
	                                password: String,
	                                androidId: String,
	                                service: String = "ac2dm",
	                                deviceCountry: String = "us",
	                                operatorCountry: String = "us",
	                                lang: String = "en",
	                                sdkVersion: String = "17"): Call =
			httpClient.newCall(Request.Builder()
					.url(url)
					.post(FormBody.Builder()
							.add("accountType", "HOSTED_OR_GOOGLE")
							.add("Email", username)
							.add("has_permission", "1")
							.add("add_account", "1")
							.add("EncryptedPasswd", Base64.encodeToString(createSignature(
									username = username,
									password = password,
									modulus = config.modulus,
									exponent = config.exponent), Base64.URL_SAFE))
							.add("service", service)
							.add("source", "android")
							.add("androidId", androidId)
							.add("device_country", deviceCountry)
							.add("operatorCountry", operatorCountry)
							.add("lang", lang)
							.add("sdk_version", sdkVersion)
							.build())
					.header("User-Agent", config.userAgent)
					.build())
	
	fun performMasterLogin(username: String,
	                       password: String,
	                       androidId: String,
	                       service: String = "ac2dm",
	                       deviceCountry: String = "us",
	                       operatorCountry: String = "us",
	                       lang: String = "en",
	                       sdkVersion: String = "17"): Response =
			makeMasterLoginCall(
					username = username,
					password = password,
					androidId = androidId,
					service = service,
					deviceCountry = deviceCountry,
					operatorCountry = operatorCountry,
					lang = lang,
					sdkVersion = sdkVersion).execute()
	
	fun performMasterLoginAsync(username: String,
	                            password: String,
	                            androidId: String,
	                            service: String = "ac2dm",
	                            deviceCountry: String = "us",
	                            operatorCountry: String = "us",
	                            lang: String = "en",
	                            sdkVersion: String = "17",
	                            callback: Callback) =
			makeMasterLoginCall(
					username = username,
					password = password,
					androidId = androidId,
					service = service,
					deviceCountry = deviceCountry,
					operatorCountry = operatorCountry,
					lang = lang,
					sdkVersion = sdkVersion).enqueue(callback)
	
	fun performMasterLoginForToken(username: String,
	                               password: String,
	                               androidId: String,
	                               service: String = "ac2dm",
	                               deviceCountry: String = "us",
	                               operatorCountry: String = "us",
	                               lang: String = "en",
	                               sdkVersion: String = "17"): String =
			performMasterLogin(
					username = username,
					password = password,
					androidId = androidId,
					service = service,
					deviceCountry = deviceCountry,
					operatorCountry = operatorCountry,
					lang = lang,
					sdkVersion = sdkVersion).use {
				if (it.code() != 200) throw TokenRequestFailed
				extractValue(
						responseBody = it.body()?.string() ?: throw TokenRequestFailed,
						key = "Token").run {
					if (isFailure()) throw TokenRequestFailed
					else get()
				}
			}
	
	fun performMasterLoginForTokenAsync(username: String,
	                                    password: String,
	                                    androidId: String,
	                                    service: String = "ac2dm",
	                                    deviceCountry: String = "us",
	                                    operatorCountry: String = "us",
	                                    lang: String = "en",
	                                    sdkVersion: String = "17",
	                                    callback: MasterLoginCallback) =
			performMasterLoginAsync(
					username = username,
					password = password,
					androidId = androidId,
					service = service,
					deviceCountry = deviceCountry,
					operatorCountry = operatorCountry,
					lang = lang,
					sdkVersion = sdkVersion,
					callback = callback)
	
	fun makeOAuthCall(username: String,
	                  masterToken: String,
	                  androidId: String,
	                  service: String,
	                  app: String,
	                  clientSig: String,
	                  deviceCountry: String = "us",
	                  operatorCountry: String = "us",
	                  lang: String = "en",
	                  sdkVersion: String = "17") =
			httpClient.newCall(Request.Builder()
					.url(url)
					.post(FormBody.Builder()
							.add("accountType", "HOSTED_OR_GOOGLE")
							.add("Email", username)
							.add("has_permission", "1")
							.add("EncryptedPasswd", masterToken)
							.add("service", service)
							.add("source", "android")
							.add("androidId", androidId)
							.add("app", app)
							.add("client_sig", clientSig)
							.add("device_country", deviceCountry)
							.add("operatorCountry", operatorCountry)
							.add("lang", lang)
							.add("sdk_version", sdkVersion)
							.build())
					.header("User-Agent", config.userAgent)
					.build())
	
	fun performOAuth(username: String,
	                 masterToken: String,
	                 androidId: String,
	                 service: String,
	                 app: String,
	                 clientSig: String,
	                 deviceCountry: String = "us",
	                 operatorCountry: String = "us",
	                 lang: String = "en",
	                 sdkVersion: String = "17"): Response =
			makeOAuthCall(
					username = username,
					masterToken = masterToken,
					androidId = androidId,
					service = service,
					app = app,
					clientSig = clientSig,
					deviceCountry = deviceCountry,
					operatorCountry = operatorCountry,
					lang = lang,
					sdkVersion = sdkVersion).execute()
	
	fun performOAuthAsync(username: String,
	                      masterToken: String,
	                      androidId: String,
	                      service: String,
	                      app: String,
	                      clientSig: String,
	                      deviceCountry: String = "us",
	                      operatorCountry: String = "us",
	                      lang: String = "en",
	                      sdkVersion: String = "17",
	                      callback: Callback) =
			makeOAuthCall(
					username = username,
					masterToken = masterToken,
					androidId = androidId,
					service = service,
					app = app,
					clientSig = clientSig,
					deviceCountry = deviceCountry,
					operatorCountry = operatorCountry,
					lang = lang,
					sdkVersion = sdkVersion).enqueue(callback)
	
	
	fun performOAuthForToken(username: String,
	                         masterToken: String,
	                         androidId: String,
	                         service: String,
	                         app: String,
	                         clientSig: String,
	                         deviceCountry: String = "us",
	                         operatorCountry: String = "us",
	                         lang: String = "en",
	                         sdkVersion: String = "17"): AuthToken =
			performOAuth(
					username = username,
					masterToken = masterToken,
					androidId = androidId,
					service = service,
					app = app,
					clientSig = clientSig,
					deviceCountry = deviceCountry,
					operatorCountry = operatorCountry,
					lang = lang,
					sdkVersion = sdkVersion).use {
				if (it.code() != 200) throw TokenRequestFailed
				val responseBody = it.body()?.string() ?: throw TokenRequestFailed
				AuthToken(
						token = extractValue(
								responseBody = responseBody,
								key = "Auth").takeUnless { it.isFailure() }?.get()
								?: throw TokenRequestFailed,
						expiry = extractValue(
								responseBody = responseBody,
								key = "Expiry").takeUnless { it.isFailure() }?.get()?.toLongOrNull()
								?: throw TokenRequestFailed)
			}
	
	fun performOAuthForTokenAsync(username: String,
	                              masterToken: String,
	                              androidId: String,
	                              service: String,
	                              app: String,
	                              clientSig: String,
	                              deviceCountry: String = "us",
	                              operatorCountry: String = "us",
	                              lang: String = "en",
	                              sdkVersion: String = "17",
	                              callback: AuthTokenCallback) =
			performOAuthAsync(username = username,
					masterToken = masterToken,
					androidId = androidId,
					service = service,
					app = app,
					clientSig = clientSig,
					deviceCountry = deviceCountry,
					operatorCountry = operatorCountry,
					lang = lang,
					sdkVersion = sdkVersion,
					callback = callback)
}

abstract class MasterLoginCallback : Callback {
	
	abstract fun onFailure(call: Call, tokenError: TokenRequestFailed)
	
	abstract fun onResponse(call: Call, masterToken: String)
	
	override fun onFailure(call: Call, e: IOException) {
		onFailure(call, TokenRequestFailed)
	}
	
	override fun onResponse(call: Call, response: Response) {
		if (response.code() != 200) return onFailure(call, TokenRequestFailed)
		onResponse(call, extractValue(
				responseBody = response.body()?.string()
						?: return onFailure(call, TokenRequestFailed),
				key = "Token").run {
			if (isFailure()) return onFailure(call, TokenRequestFailed)
			else get()
		})
	}
}

abstract class AuthTokenCallback : Callback {
	
	abstract fun onFailure(call: Call, tokenError: TokenRequestFailed)
	
	abstract fun onResponse(call: Call, authToken: AuthToken)
	
	override fun onResponse(call: Call, response: Response) {
		if (response.code() != 200) return onFailure(call, TokenRequestFailed)
		val responseBody = response.body()?.string()
				?: return onFailure(call, TokenRequestFailed)
		onResponse(call, AuthToken(
				token = extractValue(
						responseBody = responseBody,
						key = "Auth").takeUnless { it.isFailure() }?.get()
						?: return onFailure(call, TokenRequestFailed),
				expiry = extractValue(
						responseBody = responseBody,
						key = "Expiry").takeUnless { it.isFailure() }?.get()?.toLongOrNull()
						?: return onFailure(call, TokenRequestFailed)))
	}
	
	override fun onFailure(call: Call, e: IOException) {
		onFailure(call, TokenRequestFailed)
	}
}

object TokenRequestFailed : Exception()