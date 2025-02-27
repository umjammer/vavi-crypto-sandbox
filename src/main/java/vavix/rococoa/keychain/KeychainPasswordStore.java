/*
 *  Copyright (c) 2005 David Kocher. All rights reserved.
 *  http://cyberduck.ch/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  Bug fixes, suggestions and comments should be sent to:
 *  dkocher@cyberduck.ch
 */

package vavix.rococoa.keychain;

import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import org.rococoa.cocoa.corefoundation.CoreFoundation;

import static vavix.rococoa.keychain.SecurityFunctions.errSecDuplicateItem;
import static vavix.rococoa.keychain.SecurityFunctions.errSecItemNotFound;
import static vavix.rococoa.keychain.SecurityFunctions.kSecAuthenticationTypeDefault;
import static vavix.rococoa.keychain.SecurityFunctions.kSecProtocolTypeAny;
import static vavix.rococoa.keychain.SecurityFunctions.kSecProtocolTypeFTP;
import static vavix.rococoa.keychain.SecurityFunctions.kSecProtocolTypeFTPS;
import static vavix.rococoa.keychain.SecurityFunctions.kSecProtocolTypeHTTP;
import static vavix.rococoa.keychain.SecurityFunctions.kSecProtocolTypeHTTPS;
import static vavix.rococoa.keychain.SecurityFunctions.kSecProtocolTypeSSH;
import static vavix.rococoa.keychain.SecurityFunctions.library;


public final class KeychainPasswordStore {
    private static final Logger log = Logger.getLogger(KeychainPasswordStore.class.getName());

    private static final Object lock = new Object();

    public String getPassword(String scheme, int port, String serviceName, String accountName) {
        synchronized(lock) {
            IntByReference passwordLength = new IntByReference();
            PointerByReference passwordRef = new PointerByReference();
            int err = SecurityFunctions.library.SecKeychainFindInternetPassword(null,
                serviceName.getBytes(StandardCharsets.UTF_8).length, serviceName.getBytes(StandardCharsets.UTF_8),
                0, null,
                accountName.getBytes(StandardCharsets.UTF_8).length, accountName.getBytes(StandardCharsets.UTF_8),
                0, null,
                port, toSecProtocolType(scheme), SecurityFunctions.kSecAuthenticationTypeDefault,
                passwordLength, passwordRef, null);
            if(0 == err) {
                return new String(passwordRef.getValue().getByteArray(0, passwordLength.getValue()), StandardCharsets.UTF_8);
            }
            if(errSecItemNotFound == err) {
                return null;
            }
            throw new IllegalStateException(String.format("Failure reading credentials for %s from Keychain", serviceName));
        }
    }

    public void addPassword(String scheme, int port, String serviceName, String accountName, String password) {
        synchronized(lock) {
            int err = library.SecKeychainAddInternetPassword(null,
                serviceName.getBytes(StandardCharsets.UTF_8).length, serviceName.getBytes(StandardCharsets.UTF_8),
                0, null,
                accountName.getBytes(StandardCharsets.UTF_8).length, accountName.getBytes(StandardCharsets.UTF_8),
                0, null,
                port, toSecProtocolType(scheme), kSecAuthenticationTypeDefault,
                password.getBytes(StandardCharsets.UTF_8).length,
                password.getBytes(StandardCharsets.UTF_8), null);
            if(errSecDuplicateItem == err) {
                // Found existing item
                PointerByReference itemRef = new PointerByReference();
                err = SecurityFunctions.library.SecKeychainFindInternetPassword(null,
                    serviceName.getBytes(StandardCharsets.UTF_8).length, serviceName.getBytes(StandardCharsets.UTF_8),
                    0, null,
                    accountName.getBytes(StandardCharsets.UTF_8).length, accountName.getBytes(StandardCharsets.UTF_8),
                    0, null,
                    port, toSecProtocolType(scheme), SecurityFunctions.kSecAuthenticationTypeDefault,
                    null, null, itemRef);
                if(0 != err) {
                    throw new IllegalStateException(String.format("Failure saving credentials for %s in Keychain", serviceName));
                }
                err = library.SecKeychainItemModifyContent(new SecKeychainItemRef(itemRef.getValue()), null,
                    password.getBytes(StandardCharsets.UTF_8).length,
                    password.getBytes(StandardCharsets.UTF_8));
                if(0 != err) {
                    throw new IllegalStateException(String.format("Failure saving credentials for %s in Keychain", serviceName));
                }
                CoreFoundation.library.CFRelease(new SecKeychainItemRef(itemRef.getValue()));
            }
            if(0 != err) {
                throw new IllegalStateException(String.format("Failure saving credentials for %s in Keychain", serviceName));
            }
        }
    }

    public void deletePassword(String scheme, int port, String serviceName, String accountName) {
        synchronized(lock) {
            PointerByReference itemRef = new PointerByReference();
            int err = SecurityFunctions.library.SecKeychainFindInternetPassword(null,
                serviceName.getBytes(StandardCharsets.UTF_8).length, serviceName.getBytes(StandardCharsets.UTF_8),
                0, null,
                accountName.getBytes(StandardCharsets.UTF_8).length, accountName.getBytes(StandardCharsets.UTF_8),
                0, null,
                port,
                toSecProtocolType(scheme), SecurityFunctions.kSecAuthenticationTypeDefault,
                null, null, itemRef);
            if(0 == err) {
                if(0 != SecurityFunctions.library.SecKeychainItemDelete(itemRef.getValue())) {
                    throw new IllegalStateException(String.format("Failure deleting credentials for %s in Keychain", serviceName));
                }
                return;
            }
            if(errSecItemNotFound == err) {
                return;
            }
            throw new IllegalStateException(String.format("Failure deleting credentials for %s in Keychain", serviceName));
        }
    }

    public String getPassword(String serviceName, String accountName) {
        synchronized(lock) {
            IntByReference passwordLength = new IntByReference();
            PointerByReference passwordRef = new PointerByReference();
            int err = SecurityFunctions.library.SecKeychainFindGenericPassword(null,
                serviceName.getBytes(StandardCharsets.UTF_8).length, serviceName.getBytes(StandardCharsets.UTF_8),
                accountName.getBytes(StandardCharsets.UTF_8).length, accountName.getBytes(StandardCharsets.UTF_8),
                passwordLength, passwordRef, null);
            if(0 == err) {
                return new String(passwordRef.getValue().getByteArray(0, passwordLength.getValue()), StandardCharsets.UTF_8);
            }
            if(errSecItemNotFound == err) {
                return null;
            }
            throw new IllegalStateException(String.format("Failure reading credentials for %s from Keychain", serviceName));
        }
    }

    public void addPassword(String serviceName, String accountName, String password) {
        synchronized(lock) {
            int err = library.SecKeychainAddGenericPassword(null,
                serviceName.getBytes(StandardCharsets.UTF_8).length, serviceName.getBytes(StandardCharsets.UTF_8),
                accountName.getBytes(StandardCharsets.UTF_8).length, accountName.getBytes(StandardCharsets.UTF_8),
                password.getBytes(StandardCharsets.UTF_8).length,
                password.getBytes(StandardCharsets.UTF_8), null);
            if(errSecDuplicateItem == err) {
                // Found existing item
                PointerByReference itemRef = new PointerByReference();
                err = SecurityFunctions.library.SecKeychainFindGenericPassword(null,
                    serviceName.getBytes(StandardCharsets.UTF_8).length, serviceName.getBytes(StandardCharsets.UTF_8),
                    accountName.getBytes(StandardCharsets.UTF_8).length, accountName.getBytes(StandardCharsets.UTF_8),
                    null, null, itemRef);
                if(0 != err) {
                    throw new IllegalStateException(String.format("Failure saving credentials for %s in Keychain", serviceName));
                }
                err = library.SecKeychainItemModifyContent(new SecKeychainItemRef(itemRef.getValue()), null,
                    password.getBytes(StandardCharsets.UTF_8).length,
                    password.getBytes(StandardCharsets.UTF_8));
                if(0 != err) {
                    throw new IllegalStateException(String.format("Failure saving credentials for %s in Keychain", serviceName));
                }
                CoreFoundation.library.CFRelease(new SecKeychainItemRef(itemRef.getValue()));
            }
            if(0 != err) {
                throw new IllegalStateException(String.format("Failure saving credentials for %s in Keychain", serviceName));
            }
        }
    }

    public void deletePassword(String serviceName, String accountName) {
        synchronized(lock) {
            PointerByReference itemRef = new PointerByReference();
            int err = SecurityFunctions.library.SecKeychainFindGenericPassword(null,
                serviceName.getBytes(StandardCharsets.UTF_8).length, serviceName.getBytes(StandardCharsets.UTF_8),
                accountName.getBytes(StandardCharsets.UTF_8).length, accountName.getBytes(StandardCharsets.UTF_8),
                null, null, itemRef);
            if(0 == err) {
                if(0 != SecurityFunctions.library.SecKeychainItemDelete(itemRef.getValue())) {
                    throw new IllegalStateException(String.format("Failure deleting credentials for %s in Keychain", serviceName));
                }
                return;
            }
            if(errSecItemNotFound == err) {
                return;
            }
            throw new IllegalStateException(String.format("Failure deleting credentials for %s in Keychain", serviceName));
        }
    }

    private static int toSecProtocolType(String scheme) {
        return switch (scheme) {
            case "ftp" -> kSecProtocolTypeFTP;
            case "ftps" -> kSecProtocolTypeFTPS;
            case "sftp" -> kSecProtocolTypeSSH;
            case "http" -> kSecProtocolTypeHTTP;
            case "https" -> kSecProtocolTypeHTTPS;
            default -> kSecProtocolTypeAny;
        };
    }
}
