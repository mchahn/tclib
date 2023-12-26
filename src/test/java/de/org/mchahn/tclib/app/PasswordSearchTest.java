package de.org.mchahn.tclib.app;

import static org.junit.Assert.assertEquals;
import java.util.Iterator;

import org.junit.Before;
import org.junit.Test;

import de.org.mchahn.tclib.crypto.Registry;
import de.org.mchahn.tclib.app.PasswordSearch.GeneratorSource;

public class PasswordSearchTest {

    @Before
    public void setUp() throws Exception {
        Registry.setup(false);
    }

    @Test
    public void testGeneratorSource() {
        Iterator<String> i = new GeneratorSource(3, GeneratorSource.Set.NUMBERS);
        int c = 0;
        while (i.hasNext()) {
            assertEquals(String.format("%03d",  c++), i.next());
        }
        assertEquals(1000, c);
    }

    static final String TEST_FILE_PATH =
            "./src/test/java/de/org/mchahn/tclib/container/resources/";

    @Test
    public void testMainGenerator() {
        for (String etc : new String[] { "_", "" }) {
            String[] args = new String[] {
                    TEST_FILE_PATH + "firstsector.dat",
                "generator",
                "3",
                "user_defined",
                "abcd1234" + etc
            };
            PasswordSearch.ExitCode ec = PasswordSearch._main(args);
            if (0 == etc.length()) assertEquals(PasswordSearch.ExitCode.NOT_FOUND, ec);
            else                   assertEquals(PasswordSearch.ExitCode.SUCCESS  , ec);
        }
    }

    @Test
    public void testMainFile() {
        String[] args = new String[] {
            TEST_FILE_PATH + "firstsector.dat",
            "file",
            TEST_FILE_PATH + "passwords.txt"
        };
        PasswordSearch.ExitCode ec = PasswordSearch._main(args);
        assertEquals(PasswordSearch.ExitCode.SUCCESS, ec);
    }
}
