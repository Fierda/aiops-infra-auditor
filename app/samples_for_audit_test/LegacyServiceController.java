// STATIC AUDIT TEST FIXTURE — Demonstrates java4shell / JNDI / Deserialization / SpEL anti-patterns
import javax.naming.InitialContext;
import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class LegacyServiceController {
    public Object lookupDirectory(String userProvidedName) throws Exception {
        // JNDI Injection sink (CWE-917 / CWE-74)
        InitialContext ctx = new InitialContext();
        return ctx.lookup(userProvidedName);
    }

    public Object restoreObject(byte[] payload) throws Exception {
        // Untrusted Java Deserialization (CWE-502)
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
        return ois.readObject();
    }

    public Object evaluateRule(String userRule) {
        // SpEL Expression Injection (CWE-917)
        SpelExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression(userRule).getValue();
    }
}

