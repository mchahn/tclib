package de.org.mchahn.tclib.crypto;

import de.org.mchahn.tclib.util.Erasable;
import de.org.mchahn.tclib.util.Testable;

public interface Algorithm extends Erasable, Testable {
    public String name();
}
