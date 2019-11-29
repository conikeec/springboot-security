import java.nio.charset.StandardCharsets._
import java.nio.file.{Files, Paths}
import io.shiftleft.passes.{CpgPass, DiffGraph}
import io.shiftleft.codepropertygraph.Cpg
import scala.collection.mutable.ListBuffer

case class Coordinates(name : String, fileName : String, linenumber : String)
implicit val coordinatesRW = upickle.default.macroRW[Coordinates]

case class Results(verifyingFunction : String, 
                    configured : Boolean, 
                    coordinates : Option[List[Coordinates]])
implicit val resultsRW = upickle.default.macroRW[Results]

case class Goal(results : List[Results], message : String)
implicit val goalRW = upickle.default.macroRW[Goal]


val passwordEncodeRecommendMap : Map[String, String] = Map(
    "Md5PasswordEncoder" -> "This is deprecated and marked for deletion. Replace with an implementation of MessageDigestPasswordEncoder with an algorithm of 'MD5'",
    "Md4PasswordEncoder" -> "Digest based password encoding is not considered secure. Instead use an adaptive one way function like BCryptPasswordEncoder, Pbkdf2PasswordEncoder, or SCryptPasswordEncoder. Even better use DelegatingPasswordEncoder which supports password upgrades",
    "LdapShaPasswordEncoder" -> "Digest based password encoding is not considered secure. Instead use an adaptive one way function like BCryptPasswordEncoder, Pbkdf2PasswordEncoder, or SCryptPasswordEncoder. Even better use DelegatingPasswordEncoder which supports password upgrades",
    "PlaintextPasswordEncoder" -> "This class will be removed in Spring Security 5",
    "MessageDigestPasswordEncoder" -> "Digest based password encoding is not considered secure. Instead use an adaptive one way function like BCryptPasswordEncoder, Pbkdf2PasswordEncoder, or SCryptPasswordEncoder. Even better use DelegatingPasswordEncoder which supports password upgrades",
    "BCryptPasswordEncoder" -> "Implementation of PasswordEncoder that uses the BCrypt strong hashing function. Clients can optionally supply a 'version' ($2a, $2b, $2y) and a 'strength' (a.k.a. log rounds in BCrypt) and a SecureRandom instance. The larger the strength parameter the more work will have to be done (exponentially) to hash the passwords. The default value is 10",
    "Pbkdf2PasswordEncoder" -> "A PasswordEncoder implementation that uses PBKDF2 with a configurable number of iterations and a random 8-byte random salt value",
    "SCryptPasswordEncoder" -> "Implementation of PasswordEncoder that uses the SCrypt hashing function. Clients can optionally supply a cpu cost parameter, a memory cost parameter and a parallelization parameter",
    "DelegatingPasswordEncoder" -> "A password encoder that delegates to another PasswordEncoder based upon a prefixed identifier"
)

// Verify Implementation type for interface PasswordEncoder and add EDGE to CPG (via DYNAMIC DISPATCH)
def addPasswordEncodersImpl2CPG(cpg: io.shiftleft.codepropertygraph.Cpg) = {
    
    val encodingInterface = ".*org\\.springframework\\.security\\.crypto\\.password\\.PasswordEncoder.*"

    val bCryptImpl = cpg.method.fullName(".*org\\.springframework\\.security\\.crypto\\.bcrypt\\.BCryptPasswordEncoder.*").l.headOption
    if(bCryptImpl.isDefined) {
        cpg.method.fullName(encodingInterface).callIn.l.foreach { c =>
            c.addEdge(EdgeTypes.CALL, bCryptImpl.get)
        }
        println("AUTH Manager is configured with BCryptPasswordEncoder")

    } else {
        println("AUTH Manager not configured with BCryptPasswordEncoder")
    }

    val delegatingPasswordImpl = cpg.method.fullName(".*org\\.springframework\\.security\\.crypto\\.password\\.DelegatingPasswordEncoder.*").l.headOption
    if(delegatingPasswordImpl.isDefined) {
        cpg.method.fullName(encodingInterface).callIn.l.foreach { c =>
            c.addEdge(EdgeTypes.CALL, delegatingPasswordImpl.get)
        }
        println("AUTH Manager is configured with DelegatingPasswordEncoder")
    } else {
        println("AUTH Manager not configured with DelegatingPasswordEncoder")
    }
    
    val ldapShaImpl = cpg.method.fullName(".*org\\.springframework\\.security\\.crypto\\.password\\.LdapShaPasswordEncoder.*").l.headOption
    if(ldapShaImpl.isDefined) {
        cpg.method.fullName(encodingInterface).callIn.l.foreach { c =>
            c.addEdge(EdgeTypes.CALL, ldapShaImpl.get)
        }
        println("AUTH Manager is configured with LdapShaPasswordEncoder")
    } else {
        println("AUTH Manager not configured with LdapShaPasswordEncoder")
    }
    
    val md4PasswordImpl = cpg.method.fullName(".*org\\.springframework\\.security\\.crypto\\.password\\.Md4PasswordEncoder.*").l.headOption
    if(md4PasswordImpl.isDefined) {
        cpg.method.fullName(encodingInterface).callIn.l.foreach { c =>
            c.addEdge(EdgeTypes.CALL, md4PasswordImpl.get)
        }
        println("AUTH Manager is configured with Md4PasswordEncoder")
    } else {
        println("AUTH Manager not configured with Md4PasswordEncoder")
    }

    val messageDigestImpl = cpg.method.fullName(".*org\\.springframework\\.security\\.crypto\\.password\\.MessageDigestPasswordEncoder.*").l.headOption
    if(messageDigestImpl.isDefined) {
        cpg.method.fullName(encodingInterface).callIn.l.foreach { c =>
            c.addEdge(EdgeTypes.CALL, messageDigestImpl.get)
        }
        println("AUTH Manager is configured with messageDigestImpl")
    } else {
        println("AUTH Manager not configured with messageDigestImpl")
    }
    
    val pbkdf2PasswordImpl = cpg.method.fullName(".*org\\.springframework\\.security\\.crypto\\.password\\.Pbkdf2PasswordEncoder.*").l.headOption
    if(pbkdf2PasswordImpl.isDefined) {
        cpg.method.fullName(encodingInterface).callIn.l.foreach { c =>
            c.addEdge(EdgeTypes.CALL, pbkdf2PasswordImpl.get)
        }
        println("AUTH Manager is configured with pbkdf2PasswordImpl")
    } else {
        println("AUTH Manager not configured with pbkdf2PasswordImpl")
    }
    
    val sCryptPasswordImpl = cpg.method.fullName(".*org\\.springframework\\.security\\.crypto\\.scrypt\\.SCryptPasswordEncoder.*").l.headOption
    if(sCryptPasswordImpl.isDefined) {
        cpg.method.fullName(encodingInterface).callIn.l.foreach { c =>
            c.addEdge(EdgeTypes.CALL, sCryptPasswordImpl.get)
        }
        println("AUTH Manager is configured with sCryptPasswordImpl")
    } else {
        println("AUTH Manager not configured with sCryptPasswordImpl")
    }

}

// Verify Password Encoding Algorithm
def isUserDetailsPasswordEncodingEnabled(cpg: io.shiftleft.codepropertygraph.Cpg) = {
    
    val AUTH_ADAPTOR_CLASS = ".*org\\.springframework\\.security\\.core\\.userdetails\\.UserDetailsService.*"
    val CONF_METHOD_PARAM = ".*org\\.springframework\\.security\\.config\\.annotation\\.authentication\\.builders\\.AuthenticationManagerBuilder.*"
    val PASSWORD_ENCODING_INTERFACE = ".*org\\.springframework\\.security\\.config\\.annotation\\.authentication\\.configurers\\.userdetails\\.DaoAuthenticationConfigurer\\.passwordEncoder\\:org\\.springframework\\.security\\.config\\.annotation\\.authentication\\.configurers\\.userdetails\\.AbstractDaoAuthenticationConfigurer\\(org\\.springframework\\.security\\.crypto\\.password\\.PasswordEncoder\\).*"
    val PASSWORD_ENCODING_IMPL = ".*(BCryptPasswordEncoder|DelegatingPasswordEncoder|LdapShaPasswordEncoder|Md4PasswordEncoder|MessageDigestPasswordEncoder|Pbkdf2PasswordEncoder|SCryptPasswordEncoder|StandardPasswordEncoder).*"
    
    val checkAuthImpl = cpg.typeDecl.
                        filter(_.baseTypeDecl.fullName(AUTH_ADAPTOR_CLASS)).
                        method.fullName.l


    if(checkAuthImpl.size > 0) {

        // Adding PasswordEncoder Implementations to CPG edges
        addPasswordEncodersImpl2CPG(cpg)

        val isEncodingImplUsed = cpg.typeDecl.fullName(PASSWORD_ENCODING_IMPL).
                                        method.callIn.l.filter(m => 
                                            m.methodFullName.matches(PASSWORD_ENCODING_INTERFACE) && 
                                                            m.dispatchType.equals("DYNAMIC_DISPATCH"))
        if(isEncodingImplUsed.size > 0) {
            println("A password encoding implementation of type (BCryptPasswordEncoder|DelegatingPasswordEncoder|LdapShaPasswordEncoder|Md4PasswordEncoder|MessageDigestPasswordEncoder|Pbkdf2PasswordEncoder|SCryptPasswordEncoder|StandardPasswordEncoder) is used")
        }

        val coordinates = cpg.method.fullName(PASSWORD_ENCODING_INTERFACE).
                            repeat(m =>m.caller).
                            until(m => m.name(".*config.*").parameter.evalType(CONF_METHOD_PARAM)).
                            emit().l.map(i => Coordinates(i.fullName,
                                i.start.file.name.l.headOption.getOrElse("UNDEFINED"),
                                i.lineNumber.getOrElse("SYSTEM").toString))

        if(coordinates.size > 0)
            Results("UserDetailsPasswordEncodingEnabled",true,Some(coordinates)) 
        else 
            Results("UserDetailsPasswordEncodingEnabled",false,None)
    } else {
        Results("UserDetailsPasswordEncodingEnabled",false,None)
    }
}

// Verify if WebSecurityConfigurerAdapter is implemented (primary check for security enablement)
def isWebSecurityConfigurerAdapterEnabled(cpg: io.shiftleft.codepropertygraph.Cpg) = {
    val SECURITY_ADAPTOR_CLASS = "WebSecurityConfigurerAdapter"
    val ADAPTOR_CONFIG_METHOD=".*configure\\:void\\(org\\.springframework\\.security\\.config\\.annotation\\.authentication\\.builders\\.AuthenticationManagerBuilder\\).*"
     
    val coordinates = cpg.typeDecl.filter(_.baseTypeDecl.name(SECURITY_ADAPTOR_CLASS)).
                        method.fullName(ADAPTOR_CONFIG_METHOD).l.map { item =>
                            Coordinates(item.fullName, 
                            item.start.file.name.l.headOption.getOrElse("UNDEFINED"),
                            item.lineNumber.getOrElse("SYSTEM").toString) 
    }
    if(coordinates.size>0)
        Results("WebSecurityConfigurerAdapterEnabled", true, Some(coordinates)) 
    else 
        Results("WebSecurityConfigurerAdapterEnabled", false, None)
}

// Verify if HTTPS is enabled 
def isHTTPSSet(cpg: io.shiftleft.codepropertygraph.Cpg) = {
    
    val SECURE_METHOD_EXPR="org.springframework.security.config.annotation.web.configurers.ChannelSecurityConfigurer$RequiresChannelUrl.requiresSecure:org.springframework.security.config.annotation.web.configurers.ChannelSecurityConfigurer$ChannelRequestMatcherRegistry()"
    val ADAPTOR_CONFIG_METHOD = ".*configure\\:void\\(org\\.springframework\\.security\\.config\\.annotation\\.authentication\\.builders\\.AuthenticationManagerBuilder\\).*"

    val coordinates = cpg.method.fullNameExact(SECURE_METHOD_EXPR).
                        repeat(m =>m.caller).
                        until(m => m.name(ADAPTOR_CONFIG_METHOD)).
                        emit().l.map(i => Coordinates(i.fullName,
                                i.start.file.name.l.headOption.getOrElse("UNDEFINED"),
                                i.lineNumber.getOrElse("SYSTEM").toString))

    if(coordinates.size>0)
        Results("HTTPSSet",true,Some(coordinates)) 
    else 
        Results("HTTPSSet",false,None)
}

// some parts of our services require the user to be authenticated again even if the user is already logged in. 
// For example, user wants to change settings or payment information; 
// it's of course good practice to ask for manual authentication in the more sensitive areas of the system.
def isFullyAuthenticated(cpg: io.shiftleft.codepropertygraph.Cpg) = {

    val FULL_AUTH_EXPR = ".*org\\.springframework\\.security\\.config\\.annotation\\.web\\.configurers.*fullyAuthenticated.*"
    val CONF_METHOD_IMPL = ".*configure\\:void\\(org\\.springframework\\.security\\.config\\.annotation\\.web\\.builders\\.HttpSecurity\\).*"

    val coordinates = cpg.method.fullName(".*fullyAuthenticated.*").repeat(m =>m.caller).
                        until(m => m.name(CONF_METHOD_IMPL)).
                        emit().l.map(i => Coordinates(i.fullName,
                                        i.start.file.name.l.headOption.getOrElse("UNDEFINED"),
                                        i.lineNumber.getOrElse("SYSTEM").toString))
                                        
     if(coordinates.size>0)
        Results("FullyAuthenticated",true,Some(coordinates)) 
    else 
        Results("FullyAuthenticated",false,None)
}

// Content Security Policy (CSP) is an added layer of security that helps mitigate XSS (cross-site scripting) and data injection attacks. 
def isContentSecurityPolicySet(cpg: io.shiftleft.codepropertygraph.Cpg) = {
    
    val CSP_CONFIG="\"script-src \\'self\\' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/\""
    val CSP_METHOD_EXPR="org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.contentSecurityPolicy:org.springframework.security.config.annotation.web.configurers.HeadersConfigurer$ContentSecurityPolicyConfig(java.lang.String)"
    val ADAPTOR_CONFIG_METHOD = ".*configure\\:void\\(org\\.springframework\\.security\\.config\\.annotation\\.authentication\\.builders\\.AuthenticationManagerBuilder\\).*"

    val cspConfigCheck = cpg.method.fullNameExact(CSP_METHOD_EXPR).
                             parameter.
                             argument.
                             literal.l.filter(_.code.contains(CSP_CONFIG))

    if(cspConfigCheck.size > 0) {

        val coordinates = cpg.method.fullNameExact(CSP_METHOD_EXPR).
                                    repeat(m =>m.caller).
                                    until(m => m.name(ADAPTOR_CONFIG_METHOD)).
                                    emit().l.map(i => Coordinates(i.fullName,
                                                i.start.file.name.l.headOption.getOrElse("UNDEFINED"),
                                                i.lineNumber.getOrElse("SYSTEM").toString))
        if(coordinates.size>0)
            Results("ContentSecurityPolicySet",true,Some(coordinates)) 
        else 
            Results("ContentSecurityPolicySet",false,None)
    } else {
        Results("ContentSecurityPolicySet",false,None)
    }
}


// Spring Security automatically sends X-Frame-Options DENY with all responses. 
// If you need to change this default, you need to configure it manually. 
// Adding ContentSecurityPolicy headers to prevent ClickJacking

def isClickJackingPolicySet(cpg: io.shiftleft.codepropertygraph.Cpg) = {
    
    val CLKJ_CONFIG="\"frame-ancestors \\'self\\'\""
    val CSP_METHOD_EXPR="org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.contentSecurityPolicy:org.springframework.security.config.annotation.web.configurers.HeadersConfigurer$ContentSecurityPolicyConfig(java.lang.String)"
    val ADAPTOR_CONFIG_METHOD = ".*configure\\:void\\(org\\.springframework\\.security\\.config\\.annotation\\.authentication\\.builders\\.AuthenticationManagerBuilder\\).*"

    val clkjConfigCheck = cpg.method.fullNameExact(CSP_METHOD_EXPR).
                             parameter.
                             argument.
                             literal.l.filter(_.code.contains(CLKJ_CONFIG))

    if(clkjConfigCheck.size > 0) {

        val coordinates = cpg.method.fullNameExact(CSP_METHOD_EXPR).
                                    repeat(m =>m.caller).
                                    until(m => m.name(ADAPTOR_CONFIG_METHOD)).
                                    emit().l.map(i => Coordinates(i.fullName,
                                                i.start.file.name.l.headOption.getOrElse("UNDEFINED"),
                                                i.lineNumber.getOrElse("SYSTEM").toString))
        if(coordinates.size>0)
            Results("ClickJackingPolicySet",true,Some(coordinates)) 
        else 
            Results("ClickJackingPolicySet",false,None)
    } else {
        Results("ClickJackingPolicySet",false,None)
    }
}

def creatingCpg(payload: String, payloadType : String) : Boolean = {
    println("[+] Verify if CPG exists") 
    if(!workspace.baseCpgExists(payload)) {

        payloadType match {

            case "JAR" | "WAR" | "EAR" =>

                printf("[+] Creating CPG and SP for %s\n", payload) 
                createCpgAndSp(payload)

                println("[+] Verify if CPG was created successfully") 
                if(!workspace.baseCpgExists(payload)) {
                    printf("[+] Failed to create CPG for %s\n", payload)
                    return false
                }
            case "CPG" => 

                println("[+] Creating CPG for " + payload)
                loadCpg(payload)
                addOverlay("tagging")
                addOverlay("securityprofile")

                println("[+] Verify if CPG was created successfully") 
                if(!workspace.baseCpgExists(payload)) {
                    printf("[+] Failed to create CPG for %s\n", payload)
                    return false
                }

            case _ => 
                println("[+] Unrecognized payload type specified")
        }

    } else {
        println("[+] CPG already exists. Proceed to loadCpg")
    }
    return true
}

def loadingCpg(payload: String, payloadType : String) : Boolean = {
    println("[+] Load if CPG exists")
    if(workspace.baseCpgExists(payload)) {

        printf("[+] Loading pre-existing CPG for %s\n", payload)
        loadCpg(payload)

        if(workspace.recordExists(payload)) {
            printf("[+] CPG successfully loaded for %s\n", payload) 
        } else {
            printf("[+] Failed to load CPG for %s\n", payload)
            return false
        }
    } else {
        printf("[+] Attempting to load non-existent CPG for %s\n", payload)
        return false
    } 
    return true
}

//main function executed in scripting mode 
@main def exec(payload: String, 
        payloadType: String,  
        outFile: String) : Boolean = { 

    val cpgName = Paths.get(payload).getFileName().toString()

    if(workspace.baseCpgExists(cpgName)) {
            println("[+] Cpg exists so delete prior to executing runbook") 
            deleteCpg(cpgName)
            println("[+] Load blacklist ")
            config.frontend.java.cmdLineParams = Seq("-default-blacklist packageblacklist")
    }

    if(creatingCpg(payload,payloadType) && loadingCpg(payload,payloadType)) {
        
        var results = new ListBuffer[Results]()
        val primaryCheck = isWebSecurityConfigurerAdapterEnabled(cpg)
        results += primaryCheck
        if(primaryCheck.configured.equals(true)) {
            results += isUserDetailsPasswordEncodingEnabled(cpg)
            results += isHTTPSSet(cpg)
            results += isFullyAuthenticated(cpg)
            results += isContentSecurityPolicySet(cpg)
            results += isClickJackingPolicySet(cpg)
        } 
        val resultsList = results.toList
        val goal = Goal(
            resultsList,
            "%d out of %d goals have been accomplished".format(resultsList.filter(_.configured.equals(true)).size, resultsList.size)
        )

        println("Writing to OutFile : " + outFile)
        val writer = new java.io.PrintWriter(new java.io.File(outFile))
        writer.write(upickle.default.write(goal, indent=2))
        writer.close()
        printf("[+] Saving results to %s\n", outFile)

        return true
    } else {
        printf("[+] Failed to execute Spring Boot Security goal for CPG of Payload %s\n", payload)
        return false
    }
}



