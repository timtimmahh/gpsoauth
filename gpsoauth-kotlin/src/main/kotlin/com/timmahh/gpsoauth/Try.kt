package com.timmahh.gpsoauth

class Try<T> private constructor(private val value: T? = null) {
	
	companion object {
		@JvmStatic
		private val FAILURE: Try<Any> = Try()
		
		@JvmStatic
		fun <T> of(value: T): Try<T> = Try(value)
		
		@Suppress("UNCHECKED_CAST")
		@JvmStatic
		fun <T> failure() = FAILURE as Try<T>
	}
	
	fun isFailure() = this == FAILURE
	
	fun get(): T =
			if (isFailure()) throw IllegalArgumentException("Cannot get value from a failure.")
			else value !!
	
	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (other !is Try<*>) return false
		
		if (value != other.value) return false
		
		return true
	}
	
	override fun hashCode(): Int {
		return value?.hashCode() ?: 0
	}
	
	
}


