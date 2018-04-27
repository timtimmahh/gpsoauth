Kotlin Android client library for Google Play Services OAuth
--------------------------------------------------

Based on [gpsoauth-java](https://github.com/svarzee/gpsoauth-java) by [swarzee](https://github.com/svarzee) which is based on [gpsoauth](https://github.com/simon-weber/gpsoauth) by [Simon Weber](https://github.com/simon-weber).

With this library you can log in using username and password.

Simplest usage:
```
val token: AuthToken = Gpsoauth().login("username", "password", "androidId", "service", "app", "clientSig")
