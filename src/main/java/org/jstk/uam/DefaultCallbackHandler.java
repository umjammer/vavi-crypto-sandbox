/*
 * @(#) $Id: DefaultCallbackHandler.java,v 1.1.1.1 2003/10/05 18:39:26 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk.uam;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;


public class DefaultCallbackHandler implements CallbackHandler {

    @Override
    public void handle(Callback[] cb) {
        try {
            for (Callback callback : cb) {
                if (callback instanceof NameCallback nc) {
                    System.out.print(nc.getPrompt() + " ");
                    System.out.flush();
                    String name = new BufferedReader(new InputStreamReader(System.in)).readLine();
                    nc.setName(name);
                } else if (callback instanceof PasswordCallback pc) {
                    System.out.print(pc.getPrompt() + " ");
                    System.out.flush();
                    String pw = new BufferedReader(new InputStreamReader(System.in)).readLine();
                    pc.setPassword(pw.toCharArray());
                }
            }
        } catch (IOException ioe) {
            System.out.println("ioe = " + ioe);
        }
    }
}
