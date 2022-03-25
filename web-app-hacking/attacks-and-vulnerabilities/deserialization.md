# Deserialization

## **Serialization basics**

* We serialize data to generate a storable representation of a value/data without losing its type of structure.
* Serialization converts objects into a stream of bytes to transfer over network or storage.
* Usually conversion methods involve XML, JSON, or a serialization method specific to the language.
* Insecure deserialization is when user-controllable data is deserialized by a website. This potentially enables an attacker to manipulate serialized objects in order to pass harmful data into the application code.
* Can often result in remote code execution

## **Identifying serialization**

* Burp Scanner will scan for serialized objects
* PHP
  * Example: `O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}`
  * Look for unserialize() in source code
* Java
  * Any class that implements the interface `java.io.Serializable` can be serialized and deserialized. If you have source code access, take note of any code that uses the `readObject()` method, which is used to read and deserialize data from an `InputStream`.

## **Manipulating serialized objects**

* Modifying object attributes
* Modifying data types
  * PHP-based logic is particularly vulnerable to this kind of manipulation due to the behavior of its loose comparison operator (`==`) when comparing different data types. For example, if you perform a loose comparison between an integer and a string, PHP will attempt to convert the string to an integer, meaning that `5 == "5"` evaluates to `true`.
  * Unusually, this also works for any alphanumeric string that starts with a number. In this case, PHP will effectively convert the entire string to an integer value based on the initial number. The rest of the string is ignored completely. Therefore, `5 == "5 of something"` is in practice treated as `5 == 5`.
  * Let's say an attacker modified the password attribute so that it contained the integer `0` instead of the expected string. As long as the stored password does not start with a number, the condition would always return `true`, enabling an [authentication](https://portswigger.net/web-security/authentication) bypass. Note that this is only possible because deserialization preserves the data type.
* Using Application Functionality
  * As well as simply checking attribute values, a website's functionality might also perform dangerous operations on data from a deserialized object. In this case, you can use insecure deserialization to pass in unexpected data and leverage the related functionality to do damage.
* Magic Methods
  * Magic methods are a special subset of methods that you do not have to explicitly invoke. Instead, they are invoked automatically whenever a particular event or scenario occurs. Magic methods are a common feature of object-oriented programming in various languages. They are sometimes indicated by prefixing or surrounding the method name with double-underscores.
* Injecting Arbitrary objects
  * In object-oriented programming, the methods available to an object are determined by its class. Therefore, if an attacker can manipulate which class of object is being passed in as serialized data, they can influence what code is executed after, and even during, deserialization.\
    &#x20;Deserialization methods do not typically check what they are deserializing. This means that you can pass in objects of any serializable class that is available to the website, and the object will be deserialized. This effectively allows an attacker to create instances of arbitrary classes. The fact that this object is not of the expected class does not matter. The unexpected object type might cause an exception in the application logic, but the malicious object will already be instantiated by then.\
    &#x20;If an attacker has access to the source code, they can study all of the available classes in detail. To construct a simple exploit, they would look for classes containing deserialization magic methods, then check whether any of them perform dangerous operations on controllable data. The attacker can then pass in a serialized object of this class to use its magic method for an exploit.
* Gadget Chains
  * A "gadget" is a snippet of code that exists in the application that can help an attacker to achieve a particular goal. An individual gadget may not directly do anything harmful with user input. However, the attacker's goal might simply be to invoke a method that will pass their input into another gadget. By chaining multiple gadgets together in this way, an attacker can potentially pass their input into a dangerous "sink gadget", where it can cause maximum damage.
  * It is important to understand that, unlike some other types of exploit, a gadget chain is not a payload of chained methods constructed by the attacker. All of the code already exists on the website. The only thing the attacker controls is the data that is passed into the gadget chain. This is typically done using a magic method that is invoked during deserialization, sometimes known as a "kick-off gadget".
  * In the wild, many insecure deserialization vulnerabilities will only be exploitable through the use of gadget chains. This can sometimes be a simple one or two-step chain, but constructing high-severity attacks will likely require a more elaborate sequence of object instantiations and method invocations. Therefore, being able to construct gadget chains is one of the key aspects of successfully exploiting insecure deserialization.
  * When off-the-shelf gadget chains and documented exploits are unsuccessful, you will need to create your own exploit. To successfully build your own gadget chain, you will almost certainly need source code access. The first step is to study this source code to identify a class that contains a magic method that is invoked during deserialization. Assess the code that this magic method executes to see if it directly does anything dangerous with user-controllable attributes. This is always worth checking just in case.\
    &#x20;If the magic method is not exploitable on its own, it can serve as your "kick-off gadget" for a gadget chain. Study any methods that the kick-off gadget invokes. Do any of these do something dangerous with data that you control? If not, take a closer look at each of the methods that they subsequently invoke, and so on.\
    &#x20;Repeat this process, keeping track of which values you have access to, until you either reach a dead end or identify a dangerous sink gadget into which your controllable data is passed.

## **PHP deserialization**

* PHP provides several URL-style wrappers that you can use for handling different protocols when accessing file paths. One of these is the `phar://` wrapper, which provides a stream interface for accessing PHP Archive (`.phar`) files.
* &#x20;The PHP documentation reveals that `PHAR` manifest files contain serialized metadata. Crucially, if you perform any filesystem operations on a `phar://` stream, this metadata is implicitly deserialized. This means that a `phar://` stream can potentially be a vector for exploiting insecure deserialization, provided that you can pass this stream into a filesystem method.\
  &#x20;In the case of obviously dangerous filesystem methods, such as `include()` or `fopen()`, websites are likely to have implemented counter-measures to reduce the potential for them to be used maliciously. However, methods such as `file_exists()`, which are not so overtly dangerous, may not be as well protected.
* &#x20;This technique also requires you to upload the `PHAR` to the server somehow. One approach is to use an image upload functionality, for example. If you are able to create a polyglot file, with a `PHAR` masquerading as a simple `JPG`, you can sometimes bypass the website's validation checks. If you can then force the website to load this polyglot "`JPG`" from a `phar://` stream, any harmful data you inject via the `PHAR` metadata will be deserialized. As the file extension is not checked when PHP reads a stream, it does not matter that the file uses an image extension.
* &#x20;As long as the class of the object is supported by the website, both the `__wakeup()` and `__destruct()` magic methods can be invoked in this way, allowing you to potentially kick off a gadget chain using this technique

## **Tools**

* [YSoSerial.net](https://github.com/pwntester/ysoserial.net) - A proof-of-concept tool for generating payloads that exploit unsafe .NET object deserialization.
* [PHPGGC](https://github.com/ambionics/phpggc) - PHPGGC is a library of PHP unserialize() payloads along with a tool to generate them, from command line or programmatically.

## **Resources**

* [Java Deserialization CheatSheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
* [https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/)
* [https://blog.websecurity.com/2017/2/hacking-node-serialize.html](https://blog.websecurity.com/2017/2/hacking-node-serialize.html)
* [https://xapax.github.io/security/#attacking\_web\_applications/deserialization\_attacks/](https://xapax.github.io/security/#attacking\_web\_applications/deserialization\_attacks/)
* [https://cheatsheetseries.owasp.org/cheatsheets/Deserialization\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization\_Cheat\_Sheet.html)
