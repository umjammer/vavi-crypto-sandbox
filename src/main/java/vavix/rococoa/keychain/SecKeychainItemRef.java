package vavix.rococoa.keychain;

import com.sun.jna.Pointer;
import com.sun.jna.platform.mac.CoreFoundation;

public class SecKeychainItemRef extends CoreFoundation.CFTypeRef {

    public SecKeychainItemRef() {
    }

    public SecKeychainItemRef(Pointer p) {
        super(p);
    }
}