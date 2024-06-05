/*
 * @(#) $Id: JSTKShell.java,v 1.1.1.1 2003/10/05 18:39:19 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk.jstksh;

import java.rmi.Remote;

import javax.security.auth.Subject;


public interface JSTKShell extends Remote {
    String execCommand(String[] cmdargs) throws Exception;

    String createSession() throws Exception;

    void destroySession(String sessId) throws Exception;

    void setSubject(Subject sub) throws Exception;
}
