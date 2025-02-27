/*
 * @(#) $Id: UAMPersistenceManagerIntf.java,v 1.1.1.1 2003/10/05 18:39:27 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk.uam;

public interface UAMPersistenceManagerIntf {
    UserAccountManager load() throws Exception;

    void addUser(String loginName, String userName, String passWord);

    void changePassWord(String loginName, String passWord);

    void remUser(String loginName);

    void addRole(String roleName, String desc);

    void remRole(String roleName);

    void addRoleToUser(String roleName, String loginName);

    void remRoleFromUser(String roleName, String loginName);
}
